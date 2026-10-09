"""설치·제거 순서. OS를 모른다 — OS 작업은 OsIntegration(src/agent/platform/)이 한다.

OS 설치 파일이 권한에 맞게 단계(phase)를 하나씩 부른다(설계 레포 2026-10-08 스펙 2.1, 3장).
  prepare  (사용자)  포트 확인 → CA 생성 → 등록 → 자동 실행 등록·시작(포트가 열리는지 확인)
  trust    (관리자)  CA 신뢰
  activate (macOS 관리자, Windows 사용자)  시스템 프록시 켜기
프록시는 맨 마지막이다. 먼저 켜면 에이전트가 뜨기 전까지 모든 웹이 끊긴다.

한 단계 안에서 실패하면 실패한 단계 자신(일부만 됐을 수 있다)과 앞서 끝낸 단계를 역순으로 되돌리고
InstallError를 낸다. 포트 충돌(PortBusyError)은 첫 단계라 CA·등록(1회용 토큰 소비) 전에 나므로
실패한 단계는 되돌리지 않는다. 앞 단계까지 되돌리는 일은 OS 설치 파일이 uninstall을 불러서 한다.
제거는 activate → trust → prepare 순서이고, 하나가 실패해도 멈추지 않고 남은 항목을 모은다.
CA 파일은 신뢰를 푼 다음(prepare 되돌리기)에 지운다 — 신뢰 해제에 쓰는 핑거프린트를 그 파일에서
계산하기 때문이다. 그래서 CA가 아직 신뢰돼 있으면 CA 파일을, 우리 프록시가 아직 켜져 있으면 자동 실행을
지우지 않고 남은 항목으로 알린다. 프록시만 켜지고 에이전트가 없으면 모든 웹이 끊긴다.
"""

import logging
import shutil
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from agent.ca import CaFiles, ensure_ca, load_ca
from agent.credentials import CredentialStore
from agent.platform import PROXY_HOST, PROXY_PORT, AppDirs

logger = logging.getLogger(__name__)

STEP_PORT = "포트 확인"
STEP_CA = "CA 생성"
STEP_ENROLL = "등록"
STEP_AUTOSTART = "자동 실행"
STEP_TRUST = "CA 신뢰"
STEP_PROXY = "시스템 프록시"


class Phase(StrEnum):
    PREPARE = "prepare"
    TRUST = "trust"
    ACTIVATE = "activate"


INSTALL_ORDER = (Phase.PREPARE, Phase.TRUST, Phase.ACTIVATE)
UNINSTALL_ORDER = (Phase.ACTIVATE, Phase.TRUST, Phase.PREPARE)


class OsIntegration(Protocol):
    def ca_trusted(self, ca: CaFiles) -> bool: ...

    def trust_ca(self, ca: CaFiles) -> None: ...

    def untrust_ca(self, ca: CaFiles) -> None: ...

    def proxy_is_ours(self) -> bool: ...

    def enable_proxy(self) -> None: ...

    def disable_proxy_if_ours(self) -> None: ...

    def autostart_installed(self) -> bool: ...

    def install_autostart(self, command: list[str]) -> None: ...

    def remove_autostart(self) -> None: ...


@dataclass
class InstallContext:
    dirs: AppDirs
    integration: OsIntegration
    store: CredentialStore
    enroll: Callable[[], None]  # 등록 토큰으로 등록하고 키체인에 저장한다. 토큰이 없으면 예외
    run_command: list[str]  # 자동 실행할 명령
    port_open: Callable[[], bool]
    wait_port: Callable[[], bool]  # 에이전트가 포트를 열 때까지 기다린다


@dataclass(frozen=True)
class Step:
    name: str
    phase: Phase
    done: Callable[[], bool]
    do: Callable[[], None]
    undo: Callable[[], None]


class PortBusyError(RuntimeError):
    pass


class InstallError(Exception):
    def __init__(self, step: str, cause: BaseException, leftovers: list[str]) -> None:
        self.step = step
        self.cause = cause
        self.leftovers = leftovers
        message = f"{step} 단계 실패: {cause}"
        if leftovers:
            message += f" / 되돌리지 못한 항목: {', '.join(leftovers)}"
        super().__init__(message)


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host: str, port: int, timeout: float = 15.0, interval: float = 0.25) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(host, port, timeout=interval):
            return True
        time.sleep(interval)
    return False


def build_steps(ctx: InstallContext) -> list[Step]:
    integration = ctx.integration

    def check_port() -> None:
        if ctx.port_open():
            raise PortBusyError(
                f"{PROXY_HOST}:{PROXY_PORT} 포트를 다른 프로그램이 쓰고 있다 — 그 프로그램을 끄고 다시 설치한다"
            )

    def create_ca() -> None:
        ensure_ca(ctx.dirs.ca)

    def remove_files() -> None:
        ca = load_ca(ctx.dirs.ca)
        if ca is not None and integration.ca_trusted(ca):
            raise RuntimeError("CA 신뢰를 아직 풀지 못해 CA 파일을 지우지 않는다 — trust를 먼저 되돌린다")
        shutil.rmtree(ctx.dirs.data, ignore_errors=True)
        shutil.rmtree(ctx.dirs.logs, ignore_errors=True)
        if ctx.dirs.data.exists():
            # CA 개인 키가 남으면 안 된다 — 남은 항목으로 보고한다
            raise RuntimeError(f"데이터 폴더를 지우지 못했다: {ctx.dirs.data}")

    def start_agent() -> None:
        integration.install_autostart(ctx.run_command)
        if not ctx.wait_port():
            raise RuntimeError(f"에이전트가 {PROXY_HOST}:{PROXY_PORT} 포트를 열지 않았다")

    def stop_agent() -> None:
        if integration.proxy_is_ours():
            raise RuntimeError("시스템 프록시가 아직 켜져 있어 자동 실행을 지우지 않는다 — activate를 먼저 되돌린다")
        integration.remove_autostart()

    def trusted() -> bool:
        ca = load_ca(ctx.dirs.ca)
        return ca is not None and integration.ca_trusted(ca)

    def trust() -> None:
        ca = load_ca(ctx.dirs.ca)
        if ca is None:
            raise RuntimeError(f"CA가 없다 — prepare 단계를 먼저 실행한다: {ctx.dirs.ca}")
        integration.trust_ca(ca)

    def untrust() -> None:
        ca = load_ca(ctx.dirs.ca)
        if ca is None:
            # CA 파일은 신뢰 해제 뒤에만 지우므로, 없으면 우리가 신뢰 등록한 적도 없다
            return
        integration.untrust_ca(ca)

    return [
        # 우리 에이전트가 이미 자동 실행 중이면(재설치) 포트를 쓰는 게 정상이다
        Step(STEP_PORT, Phase.PREPARE, integration.autostart_installed, check_port, lambda: None),
        Step(STEP_CA, Phase.PREPARE, lambda: load_ca(ctx.dirs.ca) is not None, create_ca, remove_files),
        Step(STEP_ENROLL, Phase.PREPARE, lambda: ctx.store.load() is not None, ctx.enroll, ctx.store.clear),
        Step(
            STEP_AUTOSTART,
            Phase.PREPARE,
            lambda: integration.autostart_installed() and ctx.port_open(),
            start_agent,
            stop_agent,
        ),
        Step(STEP_TRUST, Phase.TRUST, trusted, trust, untrust),
        Step(
            STEP_PROXY,
            Phase.ACTIVATE,
            integration.proxy_is_ours,
            integration.enable_proxy,
            integration.disable_proxy_if_ours,
        ),
    ]


def install_phase(steps: list[Step], phase: Phase) -> list[str]:
    performed: list[Step] = []
    for step in steps:
        if step.phase != phase or step.done():
            continue
        logger.info("설치: %s", step.name)
        try:
            step.do()
        except Exception as exc:
            logger.error("설치 실패: %s: %s", step.name, exc)
            to_undo = list(reversed(performed))
            if not isinstance(exc, PortBusyError):
                to_undo.insert(0, step)  # 일부만 적용됐을 수 있다 — undo는 멱등이다
            raise InstallError(step.name, exc, _undo(to_undo)) from exc
        performed.append(step)
    return [step.name for step in performed]


def uninstall_phase(steps: list[Step], phase: Phase) -> list[str]:
    """되돌리지 못한 항목 이름을 돌려준다. 하나가 실패해도 나머지를 계속한다."""
    return _undo(reversed([step for step in steps if step.phase == phase]))


def _undo(steps: Iterable[Step]) -> list[str]:
    leftovers: list[str] = []
    for step in steps:
        logger.info("되돌리기: %s", step.name)
        try:
            step.undo()
        except Exception:
            logger.exception("되돌리기 실패: %s", step.name)
            leftovers.append(step.name)
    return leftovers
