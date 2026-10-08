import pytest
from fakes.verdict_server import create_server

from agent.agent_client import AgentServiceError
from agent.config import Config
from agent.credentials import CredentialStoreError, MemoryStore
from agent.enroll import enroll


@pytest.fixture
async def server():
    fake, port, servicer = await create_server()
    yield port, servicer.agent
    await fake.stop(None)


async def test_등록_토큰으로_등록하고_자격_증명을_저장한다(server):
    port, agent = server
    store = MemoryStore()

    creds = await enroll(Config(verdict_server_address=f"127.0.0.1:{port}"), "enroll-ok", store)

    assert store.load() == creds
    assert creds.agent_token in agent.valid_tokens


async def test_잘못된_등록_토큰이면_저장하지_않는다(server):
    port, _ = server
    store = MemoryStore()

    with pytest.raises(AgentServiceError):
        await enroll(Config(verdict_server_address=f"127.0.0.1:{port}"), "wrong", store)
    assert store.load() is None


class BrokenStore(MemoryStore):
    def save(self, creds) -> None:
        raise CredentialStoreError("키체인 저장 실패: RuntimeError")


async def test_저장에_실패하면_등록도_실패로_본다(server):
    # 설치 중 등록은 토큰을 남기지 않으므로, 저장 못 한 자격 증명은 다음 실행에 쓸 수 없다
    port, _ = server

    with pytest.raises(CredentialStoreError):
        await enroll(Config(verdict_server_address=f"127.0.0.1:{port}"), "enroll-ok", BrokenStore())
