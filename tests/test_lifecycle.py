import asyncio
from datetime import UTC, datetime, timedelta

import grpc
import pytest
from fakes.verdict_server import create_server
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient
from agent.config import Config
from agent.credentials import CredentialStoreError, MemoryStore
from agent.identity import AgentIdentity
from agent.lifecycle import AgentLifecycle
from agent.policy import EMPTY_POLICY
from teecher.agent.v1 import agent_pb2

IDENTITY = AgentIdentity("pc-1", agent_pb2.OS_PLATFORM_MACOS, "0.1.0", "HW-1")
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


@pytest.fixture
async def env():
    server, port, verdict = await create_server()
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")
    lifecycles: list[AgentLifecycle] = []

    def make(store=None, clock=None, **config_kwargs) -> AgentLifecycle:
        config = Config(verdict_server_address=f"127.0.0.1:{port}", **config_kwargs)
        lifecycle = AgentLifecycle(config, AgentClient(channel, 5), store or MemoryStore(), IDENTITY, clock=clock)
        lifecycles.append(lifecycle)
        return lifecycle

    yield make, verdict.agent

    for lifecycle in lifecycles:
        await lifecycle.stop()
    await channel.close()
    await server.stop(None)


class FailingSaveStore(MemoryStore):
    def save(self, creds):
        raise CredentialStoreError("keychain locked")


async def test_자격_증명이_없으면_등록하고_저장한다(env):
    make, fake = env
    store = MemoryStore()
    lifecycle = make(store=store, enrollment_token="enroll-ok")

    await lifecycle.start()

    assert lifecycle.token() in fake.valid_tokens
    assert store.load() is not None and store.load().agent_token == lifecycle.token()
    assert len(fake.heartbeats) == 1
    assert fake.policy_calls == 1


async def test_저장된_자격_증명이_있으면_등록하지_않는다(env):
    make, fake = env
    first = make(enrollment_token="enroll-ok")
    await first.start()
    store = MemoryStore()
    store.save(first._creds)
    fake.enrollment_tokens.add("enroll-2")

    second = make(store=store, enrollment_token="enroll-2")
    await second.start()

    assert len(fake.registrations) == 1
    assert second.token() == first.token()


async def test_자격_증명도_등록_토큰도_없으면_빈_토큰으로_시작한다(env):
    make, fake = env
    lifecycle = make()

    await lifecycle.start()

    assert lifecycle.token() == ""
    assert lifecycle.policy is EMPTY_POLICY
    assert fake.heartbeats == []


async def test_등록에_실패하면_다음_주기에_다시_시도한다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-late")

    await lifecycle.start()
    assert lifecycle.token() == ""

    fake.enrollment_tokens.add("enroll-late")
    await lifecycle.tick()

    assert lifecycle.token() in fake.valid_tokens
    assert fake.policy_calls == 1  # 등록 직후 정책도 받는다


async def test_수명의_절반이_지나면_토큰을_갱신하고_저장한다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    store = MemoryStore()
    lifecycle = make(store=store, clock=lambda: now[0], enrollment_token="enroll-ok")
    await lifecycle.start()
    old = lifecycle.token()

    await lifecycle.refresh_token_if_due()
    assert lifecycle.token() == old  # 아직 절반 전

    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()

    assert lifecycle.token() != old
    assert old not in fake.valid_tokens
    assert store.load().agent_token == lifecycle.token()


async def test_토큰_갱신_실패는_기존_토큰을_유지한다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    lifecycle = make(clock=lambda: now[0], enrollment_token="enroll-ok")
    await lifecycle.start()
    old = lifecycle.token()
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()

    assert lifecycle.token() == old


async def test_정책_수신_실패는_마지막_정책을_유지한다(env):
    make, fake = env
    fake.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE)]
    )
    lifecycle = make(enrollment_token="enroll-ok")
    await lifecycle.start()
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    await lifecycle.refresh_policy_once()

    assert lifecycle.policy.bypass_category("dl.google.com") == SECURITY_UPDATE


async def test_키체인_저장이_실패해도_메모리의_토큰으로_동작한다(env):
    make, fake = env
    lifecycle = make(store=FailingSaveStore(), enrollment_token="enroll-ok")

    await lifecycle.start()

    assert lifecycle.token() in fake.valid_tokens


async def test_AGENT_TOKEN을_주면_등록하지_않고_그_토큰을_쓴다(env):
    make, fake = env
    fake.valid_tokens.add("manual")
    lifecycle = make(agent_token="manual", enrollment_token="enroll-ok")

    await lifecycle.start()

    assert fake.registrations == []
    assert lifecycle.token() == "manual"
    assert fake.heartbeats == [("manual", "0.1.0")]


async def test_주기_작업은_예외에도_계속_돈다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-ok", heartbeat_interval_seconds=0.05, policy_refresh_seconds=0.05)
    await lifecycle.start()

    fake.fail_code = grpc.StatusCode.UNAVAILABLE
    await asyncio.sleep(0.2)
    fake.fail_code = None
    before = len(fake.heartbeats)
    await asyncio.sleep(0.2)

    assert len(fake.heartbeats) > before


async def test_stop하면_주기_작업이_멈춘다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-ok", heartbeat_interval_seconds=0.05)
    await lifecycle.start()
    await asyncio.sleep(0.15)

    await lifecycle.stop()
    count = len(fake.heartbeats)
    await asyncio.sleep(0.15)

    assert len(fake.heartbeats) == count
