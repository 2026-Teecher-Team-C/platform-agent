import socket
from datetime import UTC, datetime, timedelta

import pytest

from agent.ca import load_ca
from agent.credentials import Credentials, MemoryStore
from agent.installer import (
    INSTALL_ORDER,
    STEP_AUTOSTART,
    STEP_ENROLL,
    STEP_PROXY,
    STEP_TRUST,
    UNINSTALL_ORDER,
    InstallContext,
    InstallError,
    Phase,
    build_steps,
    install_phase,
    port_open,
    uninstall_phase,
    wait_port,
)
from agent.platform import AppDirs

CREDS = Credentials("agent-1", "tok-1", datetime.now(UTC), datetime.now(UTC) + timedelta(hours=24))


class FakeIntegration:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.trusted: set[str] = set()
        self.proxy = False
        self.autostart = False
        self.fail_on: str | None = None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise RuntimeError(f"{name} 실패")

    def ca_trusted(self, ca) -> bool:
        return ca.sha1 in self.trusted

    def trust_ca(self, ca) -> None:
        self._call("trust_ca")
        self.trusted.add(ca.sha1)

    def untrust_ca(self, ca) -> None:
        self._call("untrust_ca")
        self.trusted.discard(ca.sha1)

    def proxy_is_ours(self) -> bool:
        return self.proxy

    def enable_proxy(self) -> None:
        self._call("enable_proxy")
        self.proxy = True

    def disable_proxy_if_ours(self) -> None:
        self._call("disable_proxy_if_ours")
        self.proxy = False

    def autostart_installed(self) -> bool:
        return self.autostart

    def install_autostart(self, command: list[str]) -> None:
        self._call("install_autostart")
        self.autostart = True

    def remove_autostart(self) -> None:
        self._call("remove_autostart")
        self.autostart = False


@pytest.fixture
def ctx(tmp_path):
    integration = FakeIntegration()
    store = MemoryStore()
    state = {"listening": False, "enrolls": 0}

    def enroll() -> None:
        state["enrolls"] += 1
        store.save(CREDS)

    def wait() -> bool:
        state["listening"] = integration.autostart
        return state["listening"]

    context = InstallContext(
        dirs=AppDirs(data=tmp_path / "data", logs=tmp_path / "logs"),
        integration=integration,
        store=store,
        enroll=enroll,
        run_command=["teecher-agent", "run"],
        port_open=lambda: state["listening"],
        wait_port=wait,
    )
    return context, integration, store, state


def install_all(context) -> None:
    steps = build_steps(context)
    for phase in INSTALL_ORDER:
        install_phase(steps, phase)


def uninstall_all(context) -> list[str]:
    steps = build_steps(context)
    return [name for phase in UNINSTALL_ORDER for name in uninstall_phase(steps, phase)]


def test_세_단계를_순서대로_설치한다(ctx):
    context, integration, store, _ = ctx

    install_all(context)

    assert integration.calls == ["install_autostart", "trust_ca", "enable_proxy"]
    assert load_ca(context.dirs.ca) is not None
    assert store.load() == CREDS


def test_자동_실행이_실패하면_등록과_CA를_되돌린다(ctx):
    context, integration, store, _ = ctx
    integration.fail_on = "install_autostart"

    with pytest.raises(InstallError) as info:
        install_phase(build_steps(context), Phase.PREPARE)

    assert info.value.step == STEP_AUTOSTART
    assert info.value.leftovers == []
    assert store.load() is None
    assert not context.dirs.data.exists()


def test_되돌리기_실패는_남은_항목으로_알린다(ctx):
    context, integration, store, _ = ctx
    install_phase(build_steps(context), Phase.PREPARE)
    integration.fail_on = "remove_autostart"

    leftovers = uninstall_phase(build_steps(context), Phase.PREPARE)

    assert leftovers == [STEP_AUTOSTART]
    # 하나가 실패해도 나머지는 계속 지운다
    assert store.load() is None
    assert not context.dirs.data.exists()


def test_재설치에서는_된_단계를_건너뛰고_다시_등록하지_않는다(ctx):
    # Review Focus 2 — 업그레이드에서 토큰을 비워 둬도 성공해야 한다
    context, integration, _, state = ctx
    install_all(context)
    integration.calls.clear()

    def no_token() -> None:
        raise ValueError("등록 토큰이 없다")

    context.enroll = no_token
    install_all(context)

    assert integration.calls == []
    assert state["enrolls"] == 1


def test_포트를_다른_프로그램이_쓰고_있으면_실패하고_되돌린다(ctx):
    # Review Focus 1 — 개발용 mitmdump가 18080에 떠 있으면 "에이전트가 떴다"고 착각하면 안 된다
    context, integration, store, state = ctx
    state["listening"] = True

    with pytest.raises(InstallError) as info:
        install_phase(build_steps(context), Phase.PREPARE)

    assert info.value.step == STEP_AUTOSTART
    assert "18080" in str(info.value)
    assert integration.calls == []
    assert store.load() is None


def test_설치한_적_없는_PC에서_제거해도_남은_항목이_없다(ctx):
    # Review Focus 3
    context, integration, _, _ = ctx

    assert uninstall_all(context) == []
    assert "untrust_ca" not in integration.calls


def test_설치_후_제거하면_모두_되돌린다(ctx):
    context, integration, store, _ = ctx
    install_all(context)
    integration.calls.clear()

    assert uninstall_all(context) == []
    assert integration.calls == ["disable_proxy_if_ours", "untrust_ca", "remove_autostart"]
    assert integration.trusted == set()
    assert store.load() is None
    assert not context.dirs.data.exists()


def test_CA_없이_신뢰_단계를_부르면_실패한다(ctx):
    context, _, _, _ = ctx

    with pytest.raises(InstallError) as info:
        install_phase(build_steps(context), Phase.TRUST)

    assert info.value.step == STEP_TRUST


def test_등록_실패_메시지에_단계_이름이_들어간다(ctx):
    context, _, _, _ = ctx

    def bad() -> None:
        raise RuntimeError("UNAUTHENTICATED")

    context.enroll = bad
    with pytest.raises(InstallError, match=STEP_ENROLL):
        install_phase(build_steps(context), Phase.PREPARE)


def test_프록시_단계_이름(ctx):
    context, integration, _, _ = ctx
    install_all(context)
    integration.fail_on = "enable_proxy"
    integration.proxy = False

    with pytest.raises(InstallError) as info:
        install_phase(build_steps(context), Phase.ACTIVATE)

    assert info.value.step == STEP_PROXY


def test_port_open과_wait_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        assert port_open("127.0.0.1", port)
        assert wait_port("127.0.0.1", port, timeout=1)
    assert not port_open("127.0.0.1", port)
    assert not wait_port("127.0.0.1", port, timeout=0.3, interval=0.1)
