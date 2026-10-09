"""설치 폴더의 agent.conf. 비밀이 아닌 설정만 KEY=VALUE로 둔다(설계 레포 2026-10-08 스펙 2.2).

우선순위는 환경변수 > agent.conf > 코드 기본값이다. Config.from_env()가 그대로 읽도록 환경변수에 채운다.
"""

import os
import sys
from collections.abc import MutableMapping
from pathlib import Path

CONF_NAME = "agent.conf"
ALLOWED_KEYS = frozenset(
    {
        "VERDICT_SERVER_ADDRESS",
        "VERDICT_SERVER_TLS",
        "HOLD_TIMEOUT_SECONDS",
        "RPC_TIMEOUT_SECONDS",
        "BODY_SIZE_LIMIT",
        "HEARTBEAT_INTERVAL_SECONDS",
        "POLICY_REFRESH_SECONDS",
        "CREDENTIAL_STORE",
    }
)
# 토큰은 평문 파일에 두지 않는다 — 영속 저장소의 유일한 예외는 OS 키체인이다
SECRET_KEYS = frozenset({"ENROLLMENT_TOKEN", "AGENT_TOKEN"})


class ConfError(ValueError):
    pass


def parse_conf(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep:
            raise ConfError(f"{CONF_NAME} {lineno}번째 줄에 '='이 없다")
        if key in SECRET_KEYS:
            raise ConfError(f"{key}는 {CONF_NAME}에 둘 수 없다 — 토큰은 평문 파일에 쓰지 않는다")
        if key not in ALLOWED_KEYS:
            raise ConfError(f"{CONF_NAME} {lineno}번째 줄: 알 수 없는 키 {key!r}")
        values[key] = value.strip()
    return values


def apply_conf(path: Path, environ: MutableMapping[str, str] = os.environ) -> None:
    """파일이 없으면 아무것도 하지 않는다(개발 환경). 이미 있는 환경변수는 덮어쓰지 않는다."""
    if not path.is_file():
        return
    for key, value in parse_conf(path.read_text(encoding="utf-8-sig")).items():
        environ.setdefault(key, value)


def default_conf_path() -> Path | None:
    """설치본(PyInstaller)에서만 실행 파일 옆의 agent.conf를 쓴다."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / CONF_NAME
    return None
