import sys

import pytest

from agent import conf_file
from agent.conf_file import ConfError, apply_conf, default_conf_path, parse_conf


def test_주석과_빈_줄은_건너뛰고_KEY_VALUE를_읽는다():
    text = "# 서버\n\nVERDICT_SERVER_ADDRESS = teamc-platform.duckdns.org:443\nVERDICT_SERVER_TLS=true\n"

    assert parse_conf(text) == {
        "VERDICT_SERVER_ADDRESS": "teamc-platform.duckdns.org:443",
        "VERDICT_SERVER_TLS": "true",
    }


def test_값에_있는_등호는_값으로_남긴다():
    assert parse_conf("BODY_SIZE_LIMIT=a=b") == {"BODY_SIZE_LIMIT": "a=b"}


def test_등호가_없는_줄은_오류다():
    with pytest.raises(ConfError, match="2번째 줄"):
        parse_conf("VERDICT_SERVER_TLS=true\nVERDICT_SERVER_ADDRESS\n")


def test_알_수_없는_키는_오류다():
    # 오타를 조용히 넘기면 TLS 없이 붙는 사고로 이어질 수 있다
    with pytest.raises(ConfError, match="VERDICT_SERVER_TSL"):
        parse_conf("VERDICT_SERVER_TSL=true")


@pytest.mark.parametrize("key", ["ENROLLMENT_TOKEN", "AGENT_TOKEN"])
def test_비밀_키는_파일에_둘_수_없다(key):
    with pytest.raises(ConfError, match="평문 파일"):
        parse_conf(f"{key}=secret-value")


def test_비밀_키_오류에는_값이_들어가지_않는다():
    with pytest.raises(ConfError) as info:
        parse_conf("AGENT_TOKEN=secret-value")

    assert "secret-value" not in str(info.value)


def test_환경변수가_파일보다_우선한다(tmp_path):
    path = tmp_path / "agent.conf"
    path.write_text("VERDICT_SERVER_ADDRESS=from-file:443\nVERDICT_SERVER_TLS=true\n", encoding="utf-8")
    environ = {"VERDICT_SERVER_ADDRESS": "from-env:9090"}

    apply_conf(path, environ)

    assert environ == {"VERDICT_SERVER_ADDRESS": "from-env:9090", "VERDICT_SERVER_TLS": "true"}


def test_파일이_없으면_아무것도_하지_않는다(tmp_path):
    environ: dict[str, str] = {}

    apply_conf(tmp_path / "agent.conf", environ)

    assert environ == {}


def test_개발_실행에서는_기본_경로가_없다(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert default_conf_path() is None


def test_설치본에서는_실행_파일_옆의_agent_conf다(monkeypatch, tmp_path):
    exe = tmp_path / "teecher-agent"
    exe.touch()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))

    assert default_conf_path() == exe.resolve().parent / conf_file.CONF_NAME
