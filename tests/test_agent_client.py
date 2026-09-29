import socket
from datetime import timedelta

import grpc
import pytest
from fakes.verdict_server import create_server
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient, AgentServiceError, AgentUnauthenticated
from agent.identity import AgentIdentity
from teecher.agent.v1 import agent_pb2

IDENTITY = AgentIdentity("pc-1", agent_pb2.OS_PLATFORM_MACOS, "0.1.0", "HW-1")


def unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def env():
    server, port, verdict = await create_server()
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")
    yield AgentClient(channel, rpc_timeout_seconds=5), verdict.agent
    await channel.close()
    await server.stop(None)


async def test_등록하면_자격_증명을_받고_등록_토큰은_1회용이다(env):
    client, fake = env

    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    assert creds.agent_id
    assert creds.agent_token in fake.valid_tokens
    assert creds.expires_at > creds.issued_at
    [request] = fake.registrations
    assert (request.hostname, request.os_platform, request.agent_version, request.hardware_uuid) == (
        "pc-1",
        agent_pb2.OS_PLATFORM_MACOS,
        "0.1.0",
        "HW-1",
    )
    with pytest.raises(AgentUnauthenticated):
        await client.register(enrollment_token="enroll-ok", identity=IDENTITY)


async def test_하트비트는_토큰과_버전을_보낸다(env):
    client, fake = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    await client.heartbeat(creds.agent_token, "0.1.0")

    assert fake.heartbeats == [(creds.agent_token, "0.1.0")]


async def test_토큰_갱신은_새_토큰을_주고_이전_토큰은_무효가_된다(env):
    client, _ = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    renewed = await client.refresh_token(creds)

    assert renewed.agent_id == creds.agent_id
    assert renewed.agent_token != creds.agent_token
    with pytest.raises(AgentUnauthenticated):
        await client.heartbeat(creds.agent_token, "0.1.0")


async def test_정책을_받는다(env):
    client, fake = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)
    fake.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE)]
    )

    policy = await client.get_policy(creds.agent_token)

    assert policy.bypass_category("dl.google.com") == agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


async def test_서버_오류는_AgentServiceError이고_인증_실패와_구분된다(env):
    client, fake = env
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    with pytest.raises(AgentServiceError) as exc_info:
        await client.get_policy("anything")

    assert not isinstance(exc_info.value, AgentUnauthenticated)


async def test_쓸_수_없는_자격_증명은_거부한다(env):
    client, fake = env
    fake.token_lifetime = timedelta(seconds=-1)  # 이미 지난 만료 시각

    with pytest.raises(AgentServiceError):
        await client.register(enrollment_token="enroll-ok", identity=IDENTITY)


async def test_오류_메시지에_토큰이_없다(env):
    client, _ = env

    with pytest.raises(AgentUnauthenticated) as exc_info:
        await client.heartbeat("secret-token-value", "0.1.0")

    assert "secret-token-value" not in str(exc_info.value)


async def test_서버가_없으면_AgentServiceError():
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{unused_port()}")
    client = AgentClient(channel, rpc_timeout_seconds=1)

    with pytest.raises(AgentServiceError):
        await client.heartbeat("t", "0.1.0")
    await channel.close()
