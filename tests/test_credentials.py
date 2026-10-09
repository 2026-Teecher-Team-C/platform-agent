import json
from datetime import UTC, datetime, timedelta

import pytest
from keyring.errors import PasswordDeleteError

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


class FakeBackend:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.fail = False
        self.calls: list[str] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.calls.append("get_password")
        if self.fail:
            raise RuntimeError("keychain locked")
        return self.data.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        self.calls.append("set_password")
        if self.fail:
            raise RuntimeError("keychain locked")
        self.data[(service, username)] = value

    def delete_password(self, service: str, username: str) -> None:
        self.calls.append("delete_password")
        if self.fail:
            raise RuntimeError("keychain locked")
        if (service, username) not in self.data:
            raise PasswordDeleteError("not found")
        del self.data[(service, username)]


def fake_backend(qualified_name: str, chained: list | None = None) -> FakeBackend:
    """keyring.get_keyring()이 돌려줄 백엔드 흉내. 클래스 이름(모듈.이름)만 실제 백엔드와 맞춘다."""
    module, _, name = qualified_name.rpartition(".")
    cls = type(name, (FakeBackend,), {"__module__": module, "__qualname__": name})
    backend = cls()
    if chained is not None:
        backend.backends = chained
    return backend


MACOS = "keyring.backends.macOS.Keyring"
WINDOWS = "keyring.backends.Windows.WinVaultKeyring"
SECRET_SERVICE = "keyring.backends.SecretService.Keyring"
PLAINTEXT = "keyrings.alt.file.PlaintextKeyring"
NULL = "keyring.backends.null.Keyring"
CHAINER = "keyring.backends.chainer.ChainerBackend"


class FakeKeyring:
    """keyring 모듈 대역. get_keyring()만 둔다 — 저장소는 고른 백엔드 인스턴스로만 읽고 쓴다."""

    def __init__(self) -> None:
        self.backend: FakeBackend = fake_backend(MACOS)

    def get_keyring(self) -> FakeBackend:
        return self.backend

    @property
    def data(self) -> dict[tuple[str, str], str]:
        return self.backend.data

    @property
    def fail(self) -> bool:
        return self.backend.fail

    @fail.setter
    def fail(self, value: bool) -> None:
        self.backend.fail = value


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


@pytest.mark.parametrize("name", [MACOS, WINDOWS, SECRET_SERVICE])
def test_KeyringStore는_OS_보안_저장소_백엔드에는_저장하고_읽는다(fake_keyring, name):
    fake_keyring.backend = fake_backend(name)

    KeyringStore().save(creds())

    assert KeyringStore().load() == creds()


@pytest.mark.parametrize(
    "chained",
    [[NULL, PLAINTEXT], []],
    ids=["chainer-without-secure", "chainer-empty"],
)
def test_KeyringStore는_허용된_백엔드가_없는_체이너에_쓰지도_읽지도_않는다(fake_keyring, chained, caplog):
    members = [fake_backend(name) for name in chained]
    fake_keyring.backend = fake_backend(CHAINER, chained=members)

    with pytest.raises(CredentialStoreError):
        KeyringStore().save(creds())
    assert KeyringStore().load() is None

    assert fake_keyring.backend.calls == []
    assert all(member.calls == [] for member in members)
    assert "tok-1" not in caplog.text


@pytest.mark.parametrize("name", [PLAINTEXT, NULL])
def test_KeyringStore는_허용하지_않은_백엔드에_쓰지도_읽지도_않는다(fake_keyring, name, caplog):
    fake_keyring.backend = fake_backend(name)
    fake_keyring.data[("teecher-agent", "credentials")] = creds().to_json()

    with pytest.raises(CredentialStoreError):
        KeyringStore().save(creds())
    assert KeyringStore().load() is None

    assert fake_keyring.backend.calls == []
    assert "tok-1" not in caplog.text


@pytest.mark.parametrize("plaintext_first", [True, False], ids=["plaintext-first", "secure-first"])
def test_KeyringStore는_체이너에서_허용된_백엔드에만_쓰고_읽는다(fake_keyring, plaintext_first):
    secure, plaintext = fake_backend(SECRET_SERVICE), fake_backend(PLAINTEXT)
    members = [plaintext, secure] if plaintext_first else [secure, plaintext]
    fake_keyring.backend = fake_backend(CHAINER, chained=members)

    KeyringStore().save(creds())

    assert KeyringStore().load() == creds()
    assert ("teecher-agent", "credentials") in secure.data
    assert plaintext.calls == []
    assert fake_keyring.backend.calls == []  # 체이너 자체로는 쓰지 않는다


@pytest.mark.parametrize("name", sorted(credentials.SECURE_BACKENDS))
def test_허용_목록의_이름은_실제_keyring_백엔드_클래스다(name):
    module_name, _, class_name = name.rpartition(".")
    module = pytest.importorskip(module_name)

    cls = getattr(module, class_name)

    assert f"{cls.__module__}.{cls.__qualname__}" == name


def test_MemoryStore를_비운다():
    store = MemoryStore()
    store.save(creds())

    store.clear()

    assert store.load() is None


def test_KeyringStore를_비운다(fake_keyring):
    KeyringStore().save(creds())

    KeyringStore().clear()

    assert KeyringStore().load() is None


def test_KeyringStore는_없는_항목을_비워도_오류가_아니다(fake_keyring):
    KeyringStore().clear()


def test_KeyringStore_삭제_실패는_CredentialStoreError다(fake_keyring):
    KeyringStore().save(creds())
    fake_keyring.fail = True

    with pytest.raises(CredentialStoreError):
        KeyringStore().clear()


def test_평문_백엔드에서는_비우지_않는다(fake_keyring):
    fake_keyring.backend = fake_backend(PLAINTEXT)

    with pytest.raises(CredentialStoreError):
        KeyringStore().clear()
    assert fake_keyring.backend.calls == []


def test_보안_저장소_백엔드가_있는지_알려준다(fake_keyring):
    assert credentials.secure_backend_available()
    fake_keyring.backend = fake_backend(PLAINTEXT)
    assert not credentials.secure_backend_available()


def test_보안_저장소_백엔드_이름을_알려준다(fake_keyring):
    assert credentials.secure_backend_name() in credentials.SECURE_BACKENDS
    fake_keyring.backend = fake_backend(PLAINTEXT)
    assert credentials.secure_backend_name() is None
