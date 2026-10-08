import asyncio
from datetime import UTC, datetime, timedelta

import grpc
import pytest
from fakes.verdict_server import create_server
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient
from agent.config import Config
from agent.credentials import Credentials, CredentialStoreError, MemoryStore
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


class RaisingSaveStore(MemoryStore):
    def save(self, creds):
        raise RuntimeError("boom")


async def test_start는_예상하지_못한_예외에도_던지지_않고_주기_작업을_만든다(env):
    make, fake = env
    lifecycle = make(store=RaisingSaveStore(), enrollment_token="enroll-ok", heartbeat_interval_seconds=0.05)

    await lifecycle.start()

    assert lifecycle._tasks and not any(task.done() for task in lifecycle._tasks)


async def test_서버가_거부한_저장_토큰은_다음_주기에_재등록으로_복구한다(env):
    make, fake = env
    now = datetime.now(UTC)
    store = MemoryStore()
    store.save(Credentials("agent-x", "dead", now, now + timedelta(hours=24)))
    lifecycle = make(store=store, enrollment_token="enroll-ok")

    await lifecycle.start()
    assert lifecycle.token() == ""

    await lifecycle.tick()

    assert lifecycle.token() in fake.valid_tokens
    assert store.load().agent_token == lifecycle.token()


async def test_이미_만료된_저장_자격_증명은_쓰지_않고_등록한다(env):
    make, fake = env
    now = datetime.now(UTC)
    store = MemoryStore()
    store.save(Credentials("agent-x", "old", now - timedelta(hours=48), now - timedelta(hours=24)))
    lifecycle = make(store=store, enrollment_token="enroll-ok")

    await lifecycle.start()

    assert len(fake.registrations) == 1
    assert lifecycle.token() in fake.valid_tokens


async def test_수동_AGENT_TOKEN은_인증_거부에도_지워지지_않는다(env):
    make, fake = env
    lifecycle = make(agent_token="manual", enrollment_token="enroll-ok")

    await lifecycle.start()
    await lifecycle.heartbeat_once()

    assert lifecycle.token() == "manual"


async def _바이패스_정책을_받은_lifecycle(make, fake, **kwargs):
    fake.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE)]
    )
    lifecycle = make(**kwargs)
    await lifecycle.start()
    assert lifecycle.policy.bypass_category("dl.google.com") == SECURITY_UPDATE
    return lifecycle


async def test_하트비트에서_토큰이_거부되면_바이패스_정책을_지운다(env):
    make, fake = env
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, enrollment_token="enroll-ok")
    fake.valid_tokens.clear()

    await lifecycle.heartbeat_once()

    assert lifecycle.policy is EMPTY_POLICY


async def test_토큰_갱신에서_토큰이_거부되면_바이패스_정책을_지운다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, clock=lambda: now[0], enrollment_token="enroll-ok")
    fake.valid_tokens.clear()

    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()

    assert lifecycle.token() == ""
    assert lifecycle.policy is EMPTY_POLICY


async def test_정책_수신에서_토큰이_거부되면_바이패스_정책을_지우고_재등록한다(env):
    make, fake = env
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, enrollment_token="enroll-ok")
    fake.valid_tokens.clear()

    await lifecycle.refresh_policy_once()

    assert lifecycle.token() == ""
    assert lifecycle.policy is EMPTY_POLICY


async def test_수동_AGENT_TOKEN이_거부되면_바이패스_정책을_지운다(env):
    make, fake = env
    fake.valid_tokens.add("manual")
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, agent_token="manual")
    fake.valid_tokens.discard("manual")

    await lifecycle.heartbeat_once()

    assert lifecycle.token() == "manual"
    assert lifecycle.policy is EMPTY_POLICY


async def test_일시적_오류에는_바이패스_정책을_유지한다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, clock=lambda: now[0], enrollment_token="enroll-ok")
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    now[0] += timedelta(hours=13)
    await lifecycle.tick()
    await lifecycle.refresh_policy_once()

    assert lifecycle.policy.bypass_category("dl.google.com") == SECURITY_UPDATE


async def test_거부_뒤에_늦게_도착한_정책은_적용하지_않는다(env):
    make, fake = env
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, enrollment_token="enroll-ok")
    original = lifecycle._client.get_policy
    release = asyncio.Event()

    async def slow_get_policy(token):
        policy = await original(token)  # 서버는 아직 토큰을 받아 바이패스 정책을 돌려준다
        await release.wait()
        return policy

    lifecycle._client.get_policy = slow_get_policy
    in_flight = asyncio.create_task(lifecycle.refresh_policy_once())
    await asyncio.sleep(0.05)
    fake.valid_tokens.clear()
    await lifecycle.heartbeat_once()
    assert lifecycle.policy is EMPTY_POLICY

    release.set()
    await in_flight

    assert lifecycle.policy is EMPTY_POLICY


async def test_갱신으로_바뀐_예전_토큰의_거부는_새_자격_증명을_지우지_않는다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    lifecycle = await _바이패스_정책을_받은_lifecycle(make, fake, clock=lambda: now[0], enrollment_token="enroll-ok")
    old = lifecycle.token()
    original = lifecycle._client.get_policy
    release = asyncio.Event()

    async def late_get_policy(token):
        await release.wait()
        return await original(token)  # 그 사이 갱신으로 예전 토큰은 무효 → UNAUTHENTICATED

    lifecycle._client.get_policy = late_get_policy
    in_flight = asyncio.create_task(lifecycle.refresh_policy_once())
    await asyncio.sleep(0.05)
    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()
    new = lifecycle.token()
    assert new != old and new in fake.valid_tokens

    release.set()
    await in_flight

    assert lifecycle.token() == new
    assert lifecycle.policy.bypass_category("dl.google.com") == SECURITY_UPDATE
