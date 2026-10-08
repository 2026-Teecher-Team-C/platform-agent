"""에이전트 자격 증명(agent_id, agent_token)과 그 보관소.

설계 원칙 "에이전트에 영속 저장소를 두지 않는다"의 유일한 예외다(2026-09-29 결정). 1회용 등록 토큰으로
받은 agent_token은 재시작 뒤에도 남아야 하므로 OS 키체인(macOS Keychain, Windows 자격 증명 관리자)에
둔다. 평문 파일로는 쓰지 않는다 — OS 보안 저장소가 아닌 keyring 백엔드에는 쓰지도 읽지도 않는다.
로그에 토큰 값을 남기지 않는다.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

import keyring
from keyring.errors import PasswordDeleteError

logger = logging.getLogger(__name__)

SERVICE = "teecher-agent"
USERNAME = "credentials"

# OS 보안 저장소 백엔드만 쓴다. keyrings.alt 같은 평문 파일 백엔드가 골라져도 토큰을 쓰지 않는다(CWE-312).
# 클래스의 정확한 이름(모듈.이름)으로 비교한다 — 하위 클래스나 설정으로 바꿔 끼운 백엔드에 속지 않고,
# 백엔드 모듈을 import할 때의 부수 효과에 기대지 않는다
SECURE_BACKENDS = frozenset(
    {
        "keyring.backends.macOS.Keyring",
        "keyring.backends.Windows.WinVaultKeyring",
        "keyring.backends.SecretService.Keyring",
    }
)
_CHAINER = "keyring.backends.chainer.ChainerBackend"


class CredentialStoreError(Exception):
    """자격 증명을 저장하지 못했다. 호출자는 이번 실행 동안 메모리의 값을 쓴다."""


@dataclass(frozen=True)
class Credentials:
    agent_id: str
    agent_token: str = field(repr=False)
    issued_at: datetime  # 에이전트가 토큰을 받은 시각(UTC). 서버는 발급 시각을 주지 않는다
    expires_at: datetime

    def refresh_due(self, now: datetime) -> bool:
        return now >= self.issued_at + (self.expires_at - self.issued_at) / 2

    def to_json(self) -> str:
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "agent_token": self.agent_token,
                "issued_at": self.issued_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
            }
        )

    @staticmethod
    def from_json(raw: str) -> "Credentials":
        data = json.loads(raw)
        issued_at = datetime.fromisoformat(data["issued_at"])
        expires_at = datetime.fromisoformat(data["expires_at"])
        if issued_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("시간대 없는 시각")
        return Credentials(
            agent_id=data["agent_id"],
            agent_token=data["agent_token"],
            issued_at=issued_at,
            expires_at=expires_at,
        )


class CredentialStore(Protocol):
    def load(self) -> Credentials | None: ...

    def save(self, creds: Credentials) -> None: ...

    def clear(self) -> None: ...


class MemoryStore:
    """테스트·개발(Docker처럼 키체인이 없는 환경)용. 재시작하면 사라진다."""

    def __init__(self) -> None:
        self._creds: Credentials | None = None

    def load(self) -> Credentials | None:
        return self._creds

    def save(self, creds: Credentials) -> None:
        self._creds = creds

    def clear(self) -> None:
        self._creds = None


def _backend_name(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


def _secure_backend(backend: Any) -> Any | None:
    """읽고 쓸 OS 보안 저장소 백엔드. 없으면 None.

    체이너는 그 자체로 쓰지 않는다 — 묶인 백엔드 중 처음 성공하는 곳(평문 파일일 수 있다)에 쓰기 때문이다.
    keyrings.alt처럼 백엔드가 둘 이상이면 keyring은 체이너를 고르므로, 묶인 것 중 허용된 첫 백엔드를 직접 쓴다.
    """
    if _backend_name(backend) == _CHAINER:
        return next((b for b in getattr(backend, "backends", ()) if _backend_name(b) in SECURE_BACKENDS), None)
    return backend if _backend_name(backend) in SECURE_BACKENDS else None


class KeyringStore:
    def load(self) -> Credentials | None:
        try:
            active = keyring.get_keyring()
            backend = _secure_backend(active)
            if backend is None:
                logger.error("OS 보안 저장소가 아닌 keyring 백엔드(%s) — 읽지 않는다", _backend_name(active))
                return None
            raw = backend.get_password(SERVICE, USERNAME)
        except Exception:
            logger.exception("키체인에서 자격 증명을 읽지 못했다 — 없는 것으로 본다")
            return None
        if raw is None:
            return None
        try:
            return Credentials.from_json(raw)
        except Exception:
            logger.error("키체인의 자격 증명 항목이 깨졌다 — 없는 것으로 본다")
            return None

    def _backend_for_write(self) -> Any:
        try:
            active = keyring.get_keyring()
        except Exception as exc:
            raise CredentialStoreError(f"키체인 백엔드 확인 실패: {type(exc).__name__}") from exc
        backend = _secure_backend(active)
        if backend is None:
            raise CredentialStoreError(f"OS 보안 저장소가 아닌 keyring 백엔드: {_backend_name(active)}")
        return backend

    def save(self, creds: Credentials) -> None:
        backend = self._backend_for_write()
        try:
            backend.set_password(SERVICE, USERNAME, creds.to_json())
        except Exception as exc:
            raise CredentialStoreError(f"키체인 저장 실패: {type(exc).__name__}") from exc

    def clear(self) -> None:
        backend = self._backend_for_write()
        try:
            backend.delete_password(SERVICE, USERNAME)
        except PasswordDeleteError:
            return  # 이미 없다
        except Exception as exc:
            raise CredentialStoreError(f"키체인 삭제 실패: {type(exc).__name__}") from exc


def secure_backend_available() -> bool:
    """설치본 자체 점검용. PyInstaller가 keyring 백엔드 메타데이터를 빠뜨리면 False가 된다."""
    try:
        return _secure_backend(keyring.get_keyring()) is not None
    except Exception:
        return False


def make_store(kind: str) -> CredentialStore:
    return MemoryStore() if kind == "memory" else KeyringStore()
