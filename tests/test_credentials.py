import json
from datetime import UTC, datetime, timedelta

import pytest

from agent import credentials
from agent.credentials import Credentials, CredentialStoreError, KeyringStore, MemoryStore, make_store

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def creds(lifetime: timedelta = timedelta(hours=24)) -> Credentials:
    return Credentials("agent-1", "tok-1", issued_at=T0, expires_at=T0 + lifetime)


def test_수명의_절반이_지나면_갱신_대상이다():
    c = creds()

    assert not c.refresh_due(T0 + timedelta(hours=11, minutes=59))
    assert c.refresh_due(T0 + timedelta(hours=12))


def test_JSON으로_왕복한다():
    c = creds()

    assert Credentials.from_json(c.to_json()) == c


def test_MemoryStore는_저장한_것을_돌려준다():
    store = MemoryStore()
    assert store.load() is None

    store.save(creds())

    assert store.load() == creds()


class FakeKeyring:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.fail = False

    def get_password(self, service: str, username: str) -> str | None:
        if self.fail:
            raise RuntimeError("keychain locked")
        return self.data.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        if self.fail:
            raise RuntimeError("keychain locked")
        self.data[(service, username)] = value


@pytest.fixture
def fake_keyring(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(credentials, "keyring", fake)
    return fake


def test_KeyringStore는_teecher_agent_항목에_저장한다(fake_keyring):
    KeyringStore().save(creds())

    assert KeyringStore().load() == creds()
    assert ("teecher-agent", "credentials") in fake_keyring.data


def test_KeyringStore_깨진_항목은_없는_것으로_본다(fake_keyring):
    fake_keyring.data[("teecher-agent", "credentials")] = "{not json"

    assert KeyringStore().load() is None


def test_KeyringStore_키체인_오류는_로드에서_None(fake_keyring):
    fake_keyring.fail = True

    assert KeyringStore().load() is None


def test_KeyringStore_저장_실패는_CredentialStoreError(fake_keyring):
    fake_keyring.fail = True

    with pytest.raises(CredentialStoreError):
        KeyringStore().save(creds())


def test_make_store():
    assert isinstance(make_store("memory"), MemoryStore)
    assert isinstance(make_store("keyring"), KeyringStore)


def test_repr에_토큰이_없다():
    assert "tok-1" not in repr(creds())


def test_시간대_없는_시각은_깨진_항목으로_본다(fake_keyring):
    raw = json.dumps(
        {
            "agent_id": "a",
            "agent_token": "t",
            "issued_at": "2026-09-29T00:00:00",
            "expires_at": "2026-09-30T00:00:00",
        }
    )
    with pytest.raises(ValueError):
        Credentials.from_json(raw)
    fake_keyring.data[("teecher-agent", "credentials")] = raw

    assert KeyringStore().load() is None
