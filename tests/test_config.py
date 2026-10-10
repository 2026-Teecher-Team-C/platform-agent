import pytest

from agent.config import Config


def test_새_설정의_기본값(monkeypatch):
    for name in ("ENROLLMENT_TOKEN", "HEARTBEAT_INTERVAL_SECONDS", "POLICY_REFRESH_SECONDS", "CREDENTIAL_STORE"):
        monkeypatch.delenv(name, raising=False)

    config = Config.from_env()

    assert config.enrollment_token == ""
    assert config.heartbeat_interval_seconds == 60
    assert config.policy_refresh_seconds == 300
    assert config.credential_store == "keyring"


def test_새_설정을_환경변수에서_읽는다(monkeypatch):
    monkeypatch.setenv("ENROLLMENT_TOKEN", "enroll-ok")
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "30")
    monkeypatch.setenv("POLICY_REFRESH_SECONDS", "120")
    monkeypatch.setenv("CREDENTIAL_STORE", "Memory")

    config = Config.from_env()

    assert (config.enrollment_token, config.heartbeat_interval_seconds, config.policy_refresh_seconds) == (
        "enroll-ok",
        30,
        120,
    )
    assert config.credential_store == "memory"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CREDENTIAL_STORE", "file"),
        ("HEARTBEAT_INTERVAL_SECONDS", "0"),
        ("POLICY_REFRESH_SECONDS", "nan"),
    ],
)
def test_잘못된_값은_시작_시_거부한다(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        Config.from_env()
