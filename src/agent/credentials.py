"""에이전트 자격 증명(agent_id, agent_token)과 그 보관소.

설계 원칙 "에이전트에 영속 저장소를 두지 않는다"의 유일한 예외다(2026-09-29 결정). 1회용 등록 토큰으로
받은 agent_token은 재시작 뒤에도 남아야 하므로 OS 키체인(macOS Keychain, Windows 자격 증명 관리자)에
둔다. 평문 파일로는 쓰지 않는다. 로그에 토큰 값을 남기지 않는다.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import keyring

logger = logging.getLogger(__name__)

SERVICE = "teecher-agent"
USERNAME = "credentials"


class CredentialStoreError(Exception):
    """자격 증명을 저장하지 못했다. 호출자는 이번 실행 동안 메모리의 값을 쓴다."""


@dataclass(frozen=True)
class Credentials:
    agent_id: str
    agent_token: str
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
        return Credentials(
            agent_id=data["agent_id"],
            agent_token=data["agent_token"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
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


class KeyringStore:
    def load(self) -> Credentials | None:
        try:
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
            keyring.set_password(SERVICE, USERNAME, creds.to_json())
        except Exception as exc:
            raise CredentialStoreError(f"키체인 저장 실패: {type(exc).__name__}") from exc


def make_store(kind: str) -> CredentialStore:
    return MemoryStore() if kind == "memory" else KeyringStore()
