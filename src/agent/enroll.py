"""설치 중 1회 등록. 받은 자격 증명을 키체인에 넣고, 등록 토큰은 어디에도 남기지 않는다."""

from agent.agent_client import AgentClient
from agent.config import Config
from agent.credentials import Credentials, CredentialStore
from agent.identity import current_identity
from agent.verdict_client import open_channel


async def enroll(config: Config, enrollment_token: str, store: CredentialStore) -> Credentials:
    channel = open_channel(config)
    try:
        creds = await AgentClient(channel, config.rpc_timeout_seconds).register(
            enrollment_token=enrollment_token, identity=current_identity()
        )
    finally:
        await channel.close()
    # 저장 실패(CredentialStoreError)는 그대로 올린다 — 설치는 토큰을 남기지 않으므로 여기서 실패해야 한다
    store.save(creds)
    return creds
