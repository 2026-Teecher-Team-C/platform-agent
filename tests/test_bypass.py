from types import SimpleNamespace

import pytest
from fakes.verdict_server import create_server
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.test import taddons
from test_addon import CLEAN_BODY, make_flow

from agent.addon import HOLD_KEY, HoldPipeline
from teecher.agent.v1 import agent_pb2
from teecher.verdict.v1 import verdict_pb2

PINNED = agent_pb2.BYPASS_CATEGORY_PINNED
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


@pytest.fixture
async def pipeline(monkeypatch):
    """dl.google.com=SECURITY_UPDATE, pinned.example=PINNED 정책을 받은 파이프라인."""
    server, port, servicer = await create_server()
    servicer.agent.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[
            agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE),
            agent_pb2.BypassHost(host="pinned.example", category=PINNED),
        ]
    )
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
    monkeypatch.delenv("AGENT_TOKEN", raising=False)
    monkeypatch.setenv("ENROLLMENT_TOKEN", "enroll-ok")
    p = HoldPipeline()
    taddons.context(Proxyserver(), p)
    p.running()
    await p.wait_started()

    async def no_rpc(*args, **kwargs):
        raise AssertionError("바이패스된 flow가 판정 RPC를 호출했다")

    monkeypatch.setattr(p.client, "check_hash", no_rpc)
    monkeypatch.setattr(p.client, "submit_file", no_rpc)
    yield p, servicer
    await p.done()
    await server.stop(None)


def at_host(flow, host: str, connect_host: str | None = None):
    flow.request.host = host
    flow.request.scheme = "https"
    flow.server_conn.address = (connect_host or host, 443)
    flow.server_conn.tls = True
    flow.server_conn.sni = connect_host or host
    return flow


async def test_SECURITY_UPDATE_호스트의_다운로드는_보류_없이_흘려보내고_BYPASSED로_보고한다(pipeline):
    p, servicer = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")

    p.responseheaders(flow)
    await p.response(flow)
    await p.drain_reports()

    assert flow.response.stream is True
    assert HOLD_KEY not in flow.metadata
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_BYPASSED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_POLICY
    assert event.sha256 == ""
    assert event.file_size == len(CLEAN_BODY)
    assert event.request_host == "dl.google.com"


async def test_바이패스_호스트의_비다운로드는_보고하지_않는다(pipeline):
    p, servicer = pipeline
    flow = at_host(make_flow(b"{}", content_type="application/json", attachment=False), "dl.google.com")

    p.responseheaders(flow)
    await p.drain_reports()

    assert flow.response.stream is True
    assert servicer.report_events == []


async def test_하위_도메인은_바이패스하지_않는다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "x.dl.google.com")

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


async def test_Host_헤더와_연결_대상이_다르면_바이패스하지_않는다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com", connect_host="evil.example")

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


async def test_정책을_받기_전에는_바이패스하지_않는다(monkeypatch):
    server, port, servicer = await create_server()
    servicer.agent.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE)]
    )
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
    monkeypatch.delenv("AGENT_TOKEN", raising=False)
    monkeypatch.delenv("ENROLLMENT_TOKEN", raising=False)  # 등록 못 함 → 정책 못 받음
    p = HoldPipeline()
    taddons.context(Proxyserver(), p)
    p.running()
    await p.wait_started()
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata
    await p.done()
    await server.stop(None)


async def test_평문_HTTP는_바이패스_호스트여도_보류한다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")
    flow.request.scheme = "http"
    flow.server_conn.tls = False

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


async def test_SNI가_연결_대상과_다르면_보류한다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")
    flow.server_conn.sni = "evil.example"

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


def clienthello(connect_host: str | None, sni: str | None):
    return SimpleNamespace(
        context=SimpleNamespace(server=SimpleNamespace(address=(connect_host, 443) if connect_host else None)),
        client_hello=SimpleNamespace(sni=sni),
        ignore_connection=False,
    )


async def test_PINNED_호스트는_TLS를_풀지_않는다(pipeline):
    p, _ = pipeline
    data = clienthello("pinned.example", "pinned.example")

    p.tls_clienthello(data)

    assert data.ignore_connection is True


@pytest.mark.parametrize(
    ("connect_host", "sni"),
    [("dl.google.com", "dl.google.com"), ("other.example", "other.example"), ("x.pinned.example", "x.pinned.example")],
)
async def test_PINNED가_아니면_가로챈다(pipeline, connect_host, sni):
    p, _ = pipeline
    data = clienthello(connect_host, sni)

    p.tls_clienthello(data)

    assert data.ignore_connection is False


async def test_SNI만_PINNED_호스트면_가로챈다(pipeline):
    p, _ = pipeline
    data = clienthello("evil.example", "pinned.example")

    p.tls_clienthello(data)

    assert data.ignore_connection is False
