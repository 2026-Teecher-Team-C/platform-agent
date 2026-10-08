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
from typing import Protocol

import keyring

logger = logging.getLogger(__name__)

SERVICE = "teecher-agent"
USERNAME = "credentials"

# OS 보안 저장소 백엔드만 쓴다. keyrings.alt 같은 평문 파일 백엔드가 골라져도 토큰을 쓰지 않는다(CWE-312).
# 다른 OS의 백엔드 모듈을 import하지 않도록 클래스 이름으로 비교한다
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


class MemoryStore:
    """테스트·개발(Docker처럼 키체인이 없는 환경)용. 재시작하면 사라진다."""

    def __init__(self) -> None:
        self._creds: Credentials | None = None

    def load(self) -> Credentials | None:
        return self._creds

    def save(self, creds: Credentials) -> None:
        self._creds = creds


def _backend_name(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


def _is_secure(backend: object) -> bool:
    # 체이너는 묶인 백엔드 중 처음 성공하는 곳에 쓰고 읽으므로, 묶인 백엔드가 전부 허용될 때만 쓴다
    if _backend_name(backend) == _CHAINER:
        chained = list(getattr(backend, "backends", ()))
        return bool(chained) and all(_backend_name(b) in SECURE_BACKENDS for b in chained)
    return _backend_name(backend) in SECURE_BACKENDS


class KeyringStore:
    def load(self) -> Credentials | None:
        try:
            backend = keyring.get_keyring()
            if not _is_secure(backend):
                logger.error("OS 보안 저장소가 아닌 keyring 백엔드(%s) — 읽지 않는다", _backend_name(backend))
                return None
            raw = keyring.get_password(SERVICE, USERNAME)
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

    def save(self, creds: Credentials) -> None:
        try:
            backend = keyring.get_keyring()
        except Exception as exc:
            raise CredentialStoreError(f"키체인 백엔드 확인 실패: {type(exc).__name__}") from exc
        if not _is_secure(backend):
            raise CredentialStoreError(f"OS 보안 저장소가 아닌 keyring 백엔드: {_backend_name(backend)}")
        try:
            keyring.set_password(SERVICE, USERNAME, creds.to_json())
        except Exception as exc:
            raise CredentialStoreError(f"키체인 저장 실패: {type(exc).__name__}") from exc


def make_store(kind: str) -> CredentialStore:
    return MemoryStore() if kind == "memory" else KeyringStore()
