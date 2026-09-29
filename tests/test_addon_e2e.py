"""실제 mitmproxy 프록시 레이어를 통과하는 종단 테스트. 훅 단위 테스트가 못 보는 것 — 헤더가 실제로
판정 전에 나가지 않는지, 차단 시 클라이언트가 200 상태 줄을 먼저 받지 않는지 — 를 선로에서 확인한다."""

import asyncio
import hashlib

import pytest
from fakes.verdict_server import EICAR_BODY, create_server
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from agent.addon import HoldPipeline
from teecher.verdict.v1 import verdict_pb2

CLEAN_BODY = bytes(range(256)) * 128  # 32KB — 상한(64k) 안


def _chunked(body: bytes, size: int = 1000) -> bytes:
    out = b"".join(b"%x\r\n%s\r\n" % (len(body[i : i + size]), body[i : i + size]) for i in range(0, len(body), size))
    return out + b"0\r\n\r\n"


ROUTES = {
    "/clean.bin": (b"Content-Length: %d\r\n" % len(CLEAN_BODY), CLEAN_BODY),
    # chunked — 헤더 타이밍이 가장 위험한 경우
    "/eicar.com": (b"Transfer-Encoding: chunked\r\n", _chunked(EICAR_BODY, 16)),
    "/big.bin": (b"Transfer-Encoding: chunked\r\n", _chunked(b"A" * 128 * 1024)),
}


async def _read_chunked(reader: asyncio.StreamReader) -> int:
    total = 0
    while size := int((await reader.readline()).strip(), 16):
        total += len(await reader.readexactly(size))
        await reader.readline()
    await reader.readline()
    return total


async def _origin(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    request_line = await reader.readline()
    request_headers = []
    while (line := await reader.readline()) not in (b"\r\n", b""):
        request_headers.append(line.lower())
    method, path = request_line.split()[:2]
    if method == b"POST":
        assert b"transfer-encoding: chunked\r\n" in request_headers
        received = b"%d" % await _read_chunked(reader)
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(received), received)
        )
    else:
        headers, body = ROUTES[path.decode()]
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b'Content-Disposition: attachment; filename="f"\r\nConnection: close\r\n' + headers + b"\r\n" + body
        )
    await writer.drain()
    writer.close()


async def _fetch(proxy_port: int, origin_port: int, path: str, upload: bytes | None = None) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    method, extra, body = ("GET", "", b"") if upload is None else ("POST", "Transfer-Encoding: chunked\r\n", upload)
    writer.write(
        f"{method} http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\nConnection: close\r\n{extra}\r\n".encode()
        + body
    )
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    return data


def _split(raw: bytes) -> tuple[bytes, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    return head, body


@pytest.fixture
async def proxy(tmp_path, monkeypatch):
    fake, fake_port, servicer = await create_server()
    origin = await asyncio.start_server(_origin, "127.0.0.1", 0)
    origin_port = origin.sockets[0].getsockname()[1]
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{fake_port}")
    monkeypatch.setenv("BODY_SIZE_LIMIT", "64k")

    master = DumpMaster(options.Options(), with_termlog=False, with_dumper=False)
    pipeline = HoldPipeline()
    master.addons.add(pipeline)
    master.options.update(listen_host="127.0.0.1", listen_port=0, confdir=str(tmp_path))
    run = asyncio.create_task(master.run())
    proxyserver = master.addons.get("proxyserver")
    for _ in range(200):
        if proxyserver.listen_addrs() and pipeline.client is not None:
            break
        await asyncio.sleep(0.01)
    proxy_port = proxyserver.listen_addrs()[0][1]

    yield proxy_port, origin_port, servicer, pipeline

    master.shutdown()
    await asyncio.wait_for(run, 10)
    origin.close()
    await origin.wait_closed()
    await fake.stop(None)


async def test_선로에서_깨끗한_파일은_200으로_온전히_EICAR는_200_없이_403으로_온다(proxy):
    proxy_port, origin_port, servicer, pipeline = proxy

    clean_head, clean_body = _split(await _fetch(proxy_port, origin_port, "/clean.bin"))
    eicar_raw = await _fetch(proxy_port, origin_port, "/eicar.com")
    await pipeline.drain_reports()

    assert clean_head.startswith(b"HTTP/1.1 200 ")
    assert hashlib.sha256(clean_body).digest() == hashlib.sha256(CLEAN_BODY).digest()
    # 차단 응답은 첫 바이트부터 403이어야 한다 — 200 상태 줄이 먼저 나갔다면 보류가 깨진 것이다
    assert eicar_raw.startswith(b"HTTP/1.1 403 ")
    assert b"200 OK" not in eicar_raw
    assert EICAR_BODY not in eicar_raw
    decisions = sorted(e.decision for e in servicer.report_events)
    assert decisions == [verdict_pb2.FINAL_DECISION_RELEASED, verdict_pb2.FINAL_DECISION_BLOCKED]


async def test_선로에서_상한을_넘는_chunked_다운로드는_502이고_이벤트가_남는다(proxy):
    proxy_port, origin_port, servicer, pipeline = proxy

    raw = await _fetch(proxy_port, origin_port, "/big.bin")
    await pipeline.drain_reports()

    assert raw.startswith(b"HTTP/1.1 502 ")
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_FAIL_CLOSE
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_POLICY


async def test_선로에서_상한을_넘는_chunked_업로드도_막지_않는다(proxy):
    # 요청 본문은 스트리밍한다 — 버퍼링하면 body_size_limit에 걸려 413이 난다
    proxy_port, origin_port, servicer, pipeline = proxy
    upload = b"U" * 128 * 1024

    raw = await _fetch(proxy_port, origin_port, "/upload", upload=_chunked(upload))

    head, body = _split(raw)
    assert head.startswith(b"HTTP/1.1 200 ")
    assert body == b"%d" % len(upload)
