"""에이전트 실행 설정. 환경변수에서 읽어온다."""

import math
import os
from dataclasses import dataclass

from mitmproxy.utils.human import parse_size

_TRUE_VALUES = {"true", "1", "yes", "on"}
_FALSE_VALUES = {"false", "0", "no", "off", ""}


def _parse_bool_env(raw: str, var_name: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    # 오타를 조용히 넘기면 토큰을 평문(TLS 없이)으로 보내는 사고로 이어질 수 있다 — 바로 죽는다.
    raise ValueError(f"{var_name} 값을 해석할 수 없다: {raw!r}")


def _parse_positive_seconds(raw: str, var_name: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{var_name} 값을 해석할 수 없다: {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{var_name}는 유한한 양수여야 한다: {raw!r}")
    return value


def _validate_body_size_limit(raw: str, var_name: str) -> str:
    # 실제 상한 계산(mitmproxy 옵션에 넘길 때)은 raw 문자열 그대로 쓴다 — 여기서는 오타로 상한이
    # 없어지는 사고(예: 파싱 실패 시 무제한 취급)를 막기 위해 미리 검증만 한다.
    # mitmproxy 버퍼링은 본문의 약 2.3배 메모리를 쓴다 (설계 레포 2026-09-26-header-timing.md 실측).
    try:
        size = parse_size(raw)
    except ValueError as exc:
        raise ValueError(f"{var_name} 값을 해석할 수 없다: {raw!r}") from exc
    if size <= 0:
        raise ValueError(f"{var_name}는 0보다 커야 한다: {raw!r}")
    return raw


@dataclass(frozen=True)
class Config:
    verdict_server_address: str = "localhost:9090"
    verdict_server_tls: bool = False
    # S2에서 에이전트 등록 흐름이 이 수동 주입을 대체한다.
    agent_token: str = ""
    hold_timeout_seconds: float = 120
    rpc_timeout_seconds: float = 10
    # mitmproxy human.parse_size가 읽는 크기 문자열 (예: "500m"). 검사 대상 본문 상한.
    body_size_limit: str = "500m"

    @staticmethod
    def from_env() -> "Config":
        return Config(
            verdict_server_address=os.environ.get("VERDICT_SERVER_ADDRESS", "localhost:9090"),
            verdict_server_tls=_parse_bool_env(os.environ.get("VERDICT_SERVER_TLS", "false"), "VERDICT_SERVER_TLS"),
            agent_token=os.environ.get("AGENT_TOKEN", ""),
            hold_timeout_seconds=_parse_positive_seconds(
                os.environ.get("HOLD_TIMEOUT_SECONDS", "120"), "HOLD_TIMEOUT_SECONDS"
            ),
            rpc_timeout_seconds=_parse_positive_seconds(
                os.environ.get("RPC_TIMEOUT_SECONDS", "10"), "RPC_TIMEOUT_SECONDS"
            ),
            body_size_limit=_validate_body_size_limit(os.environ.get("BODY_SIZE_LIMIT", "500m"), "BODY_SIZE_LIMIT"),
        )
