import io

import pytest
from test_installer import CREDS, FakeIntegration

from agent import cli
from agent.conf_file import ConfError
from agent.credentials import MemoryStore


@pytest.fixture
def env(monkeypatch, tmp_path):
    integration = FakeIntegration()
    store = MemoryStore()
    monkeypatch.setattr(cli, "make_store", lambda kind: store)
    listening = {"on": False}
    monkeypatch.setattr(cli, "port_open", lambda host, port, timeout=0.5: listening["on"])

    def fake_wait(host, port, timeout=15.0, interval=0.25):
        listening["on"] = integration.autostart
        return listening["on"]

    monkeypatch.setattr(cli, "wait_port", fake_wait)
    enrolled = []

    async def fake_enroll(config, token, s):
        if token != "enroll-ok":
            # 서버 오류 문구에 토큰이 섞여 와도 가려야 한다
            raise RuntimeError(f"invalid enrollment token {token!r}")
        enrolled.append(token)
        s.save(CREDS)
        return CREDS

    monkeypatch.setattr(cli, "enroll", fake_enroll)
    monkeypatch.delenv("ENROLLMENT_TOKEN", raising=False)

    def run(*argv: str) -> int:
        return cli.main(["--home", str(tmp_path), *argv], integration_factory=lambda dirs, home: integration)

    return run, integration, store, enrolled


def test_세_단계를_설치하고_status가_모두_OK다(env, capsys):
    run, integration, store, enrolled = env

    assert run("install", "--phase", "prepare", "--enrollment-token", "enroll-ok") == 0
    assert run("install", "--phase", "trust") == 0
    assert run("install", "--phase", "activate") == 0
    assert run("status") == 0

    assert enrolled == ["enroll-ok"]
    out = capsys.readouterr().out
    assert "enroll-ok" not in out  # 토큰 값을 출력하지 않는다
    assert out.count("OK ") >= 5


def test_토큰_없이_처음_설치하면_실패하고_되돌린다(env, capsys, tmp_path):
    run, integration, store, _ = env

    assert run("install", "--phase", "prepare") == 1

    assert "등록" in capsys.readouterr().err
    assert store.load() is None
    assert integration.calls == []


def test_잘못된_토큰_오류에_토큰_값이_없다(env, capsys, tmp_path):
    run, _, _, _ = env
    log = tmp_path / "install.log"

    assert run("--log-file", str(log), "install", "--phase", "prepare", "--enrollment-token", "wrong-token-123") == 1

    err = capsys.readouterr().err
    assert "invalid enrollment token" in err
    assert "wrong-token-123" not in err
    text = log.read_text(encoding="utf-8")
    assert "invalid enrollment token" in text
    assert "wrong-token-123" not in text


def test_등록_토큰을_표준_입력으로_받는다(env, monkeypatch):
    # sudo가 명령 인자를 시스템 로그에 남기므로 macOS는 토큰을 인자로 넘기지 않는다
    run, _, store, enrolled = env
    monkeypatch.setattr("sys.stdin", io.StringIO("  enroll-ok  \n다음 줄\n"))

    assert run("install", "--phase", "prepare", "--enrollment-token-stdin") == 0

    assert enrolled == ["enroll-ok"]
    assert store.load() == CREDS


def test_표준_입력이_비어_있으면_토큰이_없는_것이다(env, monkeypatch, capsys):
    run, integration, store, enrolled = env
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))

    assert run("install", "--phase", "prepare", "--enrollment-token-stdin") == 1

    assert "등록 토큰이 없다" in capsys.readouterr().err
    assert enrolled == []
    assert store.load() is None


def test_토큰_인자와_표준_입력은_함께_쓸_수_없다(env):
    run, _, _, _ = env

    with pytest.raises(SystemExit) as info:
        run("install", "--phase", "prepare", "--enrollment-token", "x", "--enrollment-token-stdin")
    assert info.value.code == 2


def test_제거하고_status는_실패를_알린다(env):
    run, integration, store, _ = env
    for phase in ("prepare", "trust", "activate"):
        run("install", "--phase", phase, "--enrollment-token", "enroll-ok")

    for phase in ("activate", "trust", "prepare"):
        assert run("uninstall", "--phase", phase) == 0

    assert run("status") == 1
    assert store.load() is None


def test_로그_파일에_단계를_남긴다(env, tmp_path):
    run, _, _, _ = env
    log = tmp_path / "install.log"

    run("--log-file", str(log), "install", "--phase", "prepare", "--enrollment-token", "enroll-ok")

    text = log.read_text(encoding="utf-8")
    assert "설치: 등록" in text
    assert "enroll-ok" not in text


def test_agent_conf_오류도_설치_기록에_남긴다(env, monkeypatch, tmp_path):
    # Windows 설치 파일은 stderr를 보여 주지 않는다 — 원인은 설치 기록에서만 찾을 수 있다
    run, _, _, _ = env
    conf = tmp_path / "agent.conf"
    conf.write_text("NOT_A_KEY=1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "default_conf_path", lambda: conf)
    log = tmp_path / "install.log"

    with pytest.raises(ConfError):
        run("--log-file", str(log), "install", "--phase", "prepare", "--enrollment-token", "enroll-ok")

    text = log.read_text(encoding="utf-8")
    assert "NOT_A_KEY" in text
    assert "enroll-ok" not in text


def test_예상하지_못한_예외도_설치_기록에_남기고_다시_던진다(env, monkeypatch, tmp_path):
    run, _, _, _ = env

    def broken_store(kind):
        raise RuntimeError("키체인 백엔드 없음")

    monkeypatch.setattr(cli, "make_store", broken_store)
    log = tmp_path / "install.log"

    with pytest.raises(RuntimeError, match="키체인"):
        run("--log-file", str(log), "install", "--phase", "prepare", "--enrollment-token", "enroll-ok")

    text = log.read_text(encoding="utf-8")
    assert "키체인 백엔드 없음" in text
    assert "enroll-ok" not in text


def test_로그_파일_핸들러를_끝나면_떼어낸다(env, tmp_path):
    import logging

    run, _, _, _ = env
    before = list(logging.getLogger().handlers)

    run("--log-file", str(tmp_path / "install.log"), "status")

    assert logging.getLogger().handlers == before


def test_없는_단계는_인자_오류다(env):
    run, _, _, _ = env

    with pytest.raises(SystemExit) as info:
        run("install", "--phase", "everything")
    assert info.value.code == 2


def test_지원하지_않는_OS는_2로_끝난다(monkeypatch, tmp_path, capsys):
    from agent.platform import UnsupportedPlatformError

    def unsupported(dirs, home):
        raise UnsupportedPlatformError("리눅스 설치는 지원하지 않는다")

    assert cli.main(["--home", str(tmp_path), "status"], integration_factory=unsupported) == 2
    assert "리눅스" in capsys.readouterr().err


def test_agent_conf를_환경변수보다_낮은_우선순위로_적용한다(monkeypatch, tmp_path):
    conf = tmp_path / "agent.conf"
    conf.write_text("VERDICT_SERVER_ADDRESS=from-file:443\n", encoding="utf-8")
    monkeypatch.setattr(cli, "default_conf_path", lambda: conf)
    monkeypatch.delenv("VERDICT_SERVER_ADDRESS", raising=False)
    environ: dict[str, str] = {}
    monkeypatch.setattr(cli.os, "environ", environ)

    cli.load_conf()

    assert environ["VERDICT_SERVER_ADDRESS"] == "from-file:443"
