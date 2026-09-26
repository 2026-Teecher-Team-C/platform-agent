import asyncio
import gzip
import hashlib
import socket

import mitmproxy.net.encoding
import pytest
from fakes.verdict_server import EICAR_BODY, EICAR_SHA256, create_server
from mitmproxy import exceptions, http
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.flow import Error
from mitmproxy.test import taddons, tflow, tutils

from agent import addon as addon_module
from agent.addon import ENCODED_DOWNLOAD_REASON, HOLD_KEY, PASSTHROUGH_KEY, HoldPipeline
from agent.verdict_client import ReportFailed
from teecher.verdict.v1 import verdict_pb2

CLEAN_BODY = b"clean installer bytes " * 100


def unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_flow(
    body: bytes,
    content_type: str = "application/octet-stream",
    attachment: bool = True,
    content_encoding: str | None = None,
    method: str = "GET",
    **req_headers,
):
    headers = {"content-type": content_type, "content-length": str(len(body))}
    if content_encoding is not None:
        headers["content-encoding"] = content_encoding
    if attachment:
        headers["content-disposition"] = 'attachment; filename="<img src=x onerror=alert(1)>.exe"'
    response = tutils.tresp(headers=http.Headers([(k.encode(), v.encode()) for k, v in headers.items()]))
    # 선로의 바이트 그대로 넣는다 — content=로 넣으면 content-encoding에 맞춰 다시 인코딩된다
    response.raw_content = body
    return tflow.tflow(
        req=tutils.treq(headers=http.Headers(**req_headers), host="dl.example.com", port=80, method=method.encode()),
        resp=response,
    )


@pytest.fixture
async def fake_server():
    server, port, servicer = await create_server()
    yield port, servicer
    await server.stop(None)


@pytest.fixture
async def pipeline_factory(monkeypatch):
    """env로 Config를 주입하고 running()까지 부른 addon을 돌려준다. 끝나면 done()으로 정리한다."""
    started: list[HoldPipeline] = []

    def _make(port: int, hold_timeout: float = 5) -> HoldPipeline:
        monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
        monkeypatch.setenv("HOLD_TIMEOUT_SECONDS", str(hold_timeout))
        pipeline = HoldPipeline()
        # ctx.options를 세운다. body_size_limit 등 옵션은 Proxyserver가 등록한다
        taddons.context(Proxyserver(), pipeline)
        pipeline.running()
        started.append(pipeline)
        return pipeline

    yield _make

    for pipeline in started:
        await pipeline.done()


async def run_flow(pipeline: HoldPipeline, flow: http.HTTPFlow) -> None:
    pipeline.responseheaders(flow)
    await pipeline.response(flow)


async def test_비다운로드는_스트리밍으로_통과시키고_보류하지_않는다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(b"<html></html>", content_type="text/html", attachment=False, sec_fetch_mode="navigate")

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.stream is True
    assert HOLD_KEY not in flow.metadata
    assert flow.response.status_code == 200
    assert flow.response.content == b"<html></html>"
    assert servicer.report_events == []


async def test_깨끗한_다운로드는_원본_그대로_통과하고_RELEASED를_보고한다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.stream is False
    assert flow.response.status_code == 200
    assert flow.response.content == CLEAN_BODY
    assert servicer.last_submit_body == CLEAN_BODY
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_RELEASED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_ENGINE
    assert event.cache_hit is False
    assert event.bytes_uploaded == len(CLEAN_BODY)
    assert event.file_size == len(CLEAN_BODY)
    assert event.sha256 == hashlib.sha256(CLEAN_BODY).hexdigest()
    assert event.event_id == flow.metadata[HOLD_KEY].event_id
    assert event.url == "http://dl.example.com/path"
    assert event.request_host == "dl.example.com"
    assert event.filename == "<img src=x onerror=alert(1)>.exe"
    assert event.content_disposition == 'attachment; filename="<img src=x onerror=alert(1)>.exe"'
    assert event.held_at.ToNanoseconds() <= event.decided_at.ToNanoseconds()
    assert event.hold_duration_ms >= 0


async def test_EICAR를_담은_본문은_엔진이_BLOCK하고_403으로_바뀐다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    body = b"prefix " + EICAR_BODY
    flow = make_flow(body)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    assert flow.response.headers["content-type"] == "text/plain; charset=utf-8"
    text = flow.response.get_text()
    assert "EICAR" in text  # 서버가 준 사유(matched_rules)
    assert "<img" not in text  # 공격자가 정한 파일명은 403 페이지에 넣지 않는다
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_BLOCKED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_ENGINE
    assert event.cache_hit is False
    assert event.bytes_uploaded == len(body)


async def test_EICAR_해시는_업로드_없이_BLACKLIST로_차단한다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(EICAR_BODY)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    assert "EICAR test file" in flow.response.get_text()
    assert servicer.last_submit_body == b""
    [event] = servicer.report_events
    assert event.sha256 == EICAR_SHA256
    assert event.decision == verdict_pb2.FINAL_DECISION_BLOCKED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_BLACKLIST
    assert event.cache_hit is True
    assert event.bytes_uploaded == 0


async def test_서버에_닿지_못하면_403이다(pipeline_factory):
    pipeline = pipeline_factory(unused_port())
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    assert "fail-close" in flow.response.get_text()


async def test_보류_시간을_넘기면_403이고_FAIL_CLOSE를_보고한다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port, hold_timeout=0.3)
    servicer.delay_seconds = 2
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)
    servicer.delay_seconds = 0
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_FAIL_CLOSE
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_UNSPECIFIED
    assert event.sha256 == hashlib.sha256(CLEAN_BODY).hexdigest()


async def test_판정_중_예상치_못한_예외도_403이다(fake_server, pipeline_factory, monkeypatch):
    # VerdictUnavailable이 아닌 예외가 새면 mitmproxy가 원본을 통과시킨다 — 그 fail-open이 없음을 확인한다.
    port, servicer = fake_server
    pipeline = pipeline_factory(port)

    async def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline.client, "check_hash", boom)
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_FAIL_CLOSE


async def test_판별이_예외를_던지면_스트리밍하지_않고_보류해서_판정한다(fake_server, pipeline_factory, monkeypatch):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(addon_module, "is_download", boom)
    flow = make_flow(CLEAN_BODY)

    pipeline.responseheaders(flow)
    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata

    await pipeline.response(flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 200
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_RELEASED


async def test_스냅샷을_끝내_못_만들면_통과시키지_않고_403이다(fake_server, pipeline_factory, monkeypatch):
    port, _ = fake_server
    pipeline = pipeline_factory(port)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(addon_module, "filename_of", boom)
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)

    assert flow.response.stream is False
    assert flow.response.status_code == 403


async def test_보고되는_mime_type은_403이_아닌_원래_값이다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(b"prefix " + EICAR_BODY, content_type="application/zip; charset=binary")

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    [event] = servicer.report_events
    assert event.mime_type == "application/zip"


async def test_ReportEvent_실패는_판정을_바꾸지_않는다(fake_server, pipeline_factory, monkeypatch):
    port, _ = fake_server
    pipeline = pipeline_factory(port)

    async def fail(request):
        raise ReportFailed("down")

    monkeypatch.setattr(pipeline.client, "report_event", fail)
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 200
    assert flow.response.content == CLEAN_BODY


async def test_외부_취소는_다시_던지되_원본을_403으로_바꿔_둔다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    servicer.delay_seconds = 5
    flow = make_flow(CLEAN_BODY)
    pipeline.responseheaders(flow)

    task = asyncio.create_task(pipeline.response(flow))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert flow.response.status_code == 403


async def test_running은_body_size_limit을_걸고_stream_large_bodies를_끈다(fake_server, pipeline_factory, monkeypatch):
    port, _ = fake_server
    monkeypatch.setenv("BODY_SIZE_LIMIT", "1g")
    pipeline = HoldPipeline()
    with taddons.context(Proxyserver(), pipeline) as tctx:
        tctx.options.update(stream_large_bodies="1m")
        monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
        pipeline.running()
        try:
            assert tctx.options.body_size_limit == "1g"
            assert tctx.options.stream_large_bodies is None
        finally:
            await pipeline.done()


async def test_Config_파싱이_실패해도_옵션은_안전한_값으로_먼저_걸린다(monkeypatch):
    monkeypatch.setenv("HOLD_TIMEOUT_SECONDS", "abc")
    pipeline = HoldPipeline()
    with taddons.context(Proxyserver(), pipeline) as tctx:
        tctx.options.update(stream_large_bodies="1m")
        with pytest.raises(ValueError):
            pipeline.running()
        assert tctx.options.body_size_limit == "500m"
        assert tctx.options.stream_large_bodies is None
        assert pipeline.client is None


async def test_시작_뒤에는_stream_large_bodies를_켜거나_상한을_풀_수_없다(fake_server, monkeypatch):
    port, _ = fake_server
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    pipeline = HoldPipeline()
    with taddons.context(Proxyserver(), pipeline) as tctx:
        pipeline.running()
        try:
            with pytest.raises(exceptions.OptionsError):
                tctx.options.update(stream_large_bodies="1m")
            with pytest.raises(exceptions.OptionsError):
                tctx.options.update(body_size_limit=None)
            assert tctx.options.stream_large_bodies is None
            assert tctx.options.body_size_limit == "500m"
            tctx.options.update(body_size_limit="1g")  # 상한 변경 자체는 허용
        finally:
            await pipeline.done()


@pytest.mark.parametrize("encoding", ["gzip", "GZIP", "identity, br", "deflate,identity"])
async def test_인코딩된_다운로드는_풀지_않고_POLICY로_차단한다(fake_server, pipeline_factory, monkeypatch, encoding):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    decodes = []
    monkeypatch.setattr(mitmproxy.net.encoding, "decode", lambda *a, **k: decodes.append(a) or b"")

    async def no_rpc(*args, **kwargs):
        raise AssertionError("RPC가 호출되면 안 된다")

    monkeypatch.setattr(pipeline.client, "check_hash", no_rpc)
    monkeypatch.setattr(pipeline.client, "submit_file", no_rpc)
    flow = make_flow(gzip.compress(CLEAN_BODY), content_encoding=encoding)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 403
    assert decodes == []
    assert ENCODED_DOWNLOAD_REASON in flow.response.raw_content.decode()
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_BLOCKED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_POLICY
    assert event.bytes_uploaded == 0


async def test_identity_인코딩은_평문으로_검사한다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(CLEAN_BODY, content_encoding="identity")

    await run_flow(pipeline, flow)

    assert flow.response.status_code == 200
    assert servicer.last_submit_body == CLEAN_BODY


def test_요청_본문은_버퍼링하지_않는다():
    pipeline = HoldPipeline()
    flow = tflow.tflow()

    pipeline.requestheaders(flow)

    assert flow.request.stream is True


async def test_통과_표시_없이_스트리밍된_flow는_끊는다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(CLEAN_BODY)
    pipeline.responseheaders(flow)
    flow.response.stream = True  # 다른 경로(예: 늦은 스트리밍 전환)로 켜진 경우

    await pipeline.response(flow)
    await pipeline.drain_reports()

    assert flow.error is not None and flow.error.msg == Error.KILLED_MESSAGE
    assert servicer.report_events == []


async def test_비다운로드는_통과_표시를_남긴다(fake_server, pipeline_factory):
    port, _ = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(b"<html></html>", content_type="text/html", attachment=False)

    pipeline.responseheaders(flow)

    assert flow.metadata[PASSTHROUGH_KEY] is True


@pytest.mark.parametrize(("method", "body"), [("HEAD", CLEAN_BODY), ("GET", b"")])
async def test_본문이_없으면_검사하지_않고_보고하지도_않는다(fake_server, pipeline_factory, monkeypatch, method, body):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)

    async def no_rpc(*args, **kwargs):
        raise AssertionError("RPC가 호출되면 안 된다")

    monkeypatch.setattr(pipeline.client, "check_hash", no_rpc)
    flow = make_flow(body, method=method)

    await run_flow(pipeline, flow)
    await pipeline.drain_reports()

    assert flow.response.status_code == 200
    assert servicer.report_events == []


async def test_판정_전에_오류로_끝난_보류_flow도_보고한다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(CLEAN_BODY)
    pipeline.responseheaders(flow)
    flow.error = Error("Response body exceeds mitmproxy's body_size_limit.")

    pipeline.error(flow)
    pipeline.error(flow)  # 두 번 불려도 한 번만 보고한다
    await pipeline.drain_reports()

    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_FAIL_CLOSE
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_POLICY
    assert event.event_id == flow.metadata[HOLD_KEY].event_id


async def test_비다운로드_오류는_보고하지_않는다(fake_server, pipeline_factory):
    port, servicer = fake_server
    pipeline = pipeline_factory(port)
    flow = make_flow(b"<html></html>", content_type="text/html", attachment=False)
    pipeline.responseheaders(flow)
    flow.error = Error("connection closed")

    pipeline.error(flow)
    await pipeline.drain_reports()

    assert servicer.report_events == []
