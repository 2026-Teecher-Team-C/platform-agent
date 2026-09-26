import os
import socket

import grpc
import pytest
from fakes.verdict_server import EICAR_BODY, EICAR_SHA256, create_server
from grpc import aio as grpc_aio

from agent.config import Config
from agent.verdict_client import CHUNK_SIZE, ReportFailed, VerdictClient, VerdictUnavailable
from teecher.verdict.v1 import verdict_pb2, verdict_pb2_grpc


def unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def fake_server():
    server, port, servicer = await create_server()
    yield port, servicer
    await server.stop(None)


@pytest.fixture
async def client_factory():
    """만든 client를 기억해뒀다가 테스트가 끝나면 전부 close()한다."""
    clients: list[VerdictClient] = []

    def _make(config: Config) -> VerdictClient:
        client = VerdictClient(config)
        clients.append(client)
        return client

    yield _make

    for client in clients:
        await client.close()


async def test_EICAR_해시는_업로드_없이_BLOCK_BLACKLIST를_반환한다(fake_server, client_factory):
    port, _ = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    response = await client.check_hash(EICAR_SHA256, len(EICAR_BODY))

    assert response.decision == verdict_pb2.DECISION_BLOCK
    assert response.source == verdict_pb2.DECISION_SOURCE_BLACKLIST


async def test_미확인_해시는_UNKNOWN이고_이후_submit_file로_판정한다(fake_server, client_factory):
    port, _ = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    check = await client.check_hash("0" * 64, 11)
    assert check.decision == verdict_pb2.DECISION_UNKNOWN

    clean = await client.submit_file(
        sha256="0" * 64,
        file_size=11,
        filename="a.txt",
        mime_type="text/plain",
        event_id="e1",
        body=b"hello world",
        timeout=5,
    )
    assert clean.decision == verdict_pb2.DECISION_ALLOW

    blocked = await client.submit_file(
        sha256=EICAR_SHA256,
        file_size=len(EICAR_BODY),
        filename="eicar.com",
        mime_type="application/octet-stream",
        event_id="e2",
        body=EICAR_BODY,
        timeout=5,
    )
    assert blocked.decision == verdict_pb2.DECISION_BLOCK
    assert list(blocked.matched_rules) == ["EICAR"]


async def test_64KiB_초과_본문은_여러_청크로_전송되고_그대로_재조립된다(fake_server, client_factory):
    port, servicer = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))
    body = os.urandom(CHUNK_SIZE * 3 + 123)

    await client.submit_file(
        sha256="0" * 64,
        file_size=len(body),
        filename="big.bin",
        mime_type="application/octet-stream",
        event_id="e3",
        body=body,
        timeout=5,
    )

    assert servicer.last_submit_body == body


async def test_서버가_없으면_VerdictUnavailable(client_factory):
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{unused_port()}", rpc_timeout_seconds=3))

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_CheckHash_지연이_타임아웃보다_길면_VerdictUnavailable(fake_server, client_factory):
    port, servicer = fake_server
    servicer.delay_seconds = 1.0
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}", rpc_timeout_seconds=0.2))

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_SubmitFile_지연이_타임아웃보다_길면_VerdictUnavailable(fake_server, client_factory):
    port, servicer = fake_server
    servicer.delay_seconds = 1.0
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    with pytest.raises(VerdictUnavailable):
        await client.submit_file(
            sha256="0" * 64,
            file_size=4,
            filename="a",
            mime_type="text/plain",
            event_id="e",
            body=b"data",
            timeout=0.2,
        )


async def test_토큰이_있으면_Bearer_메타데이터로_전달된다(fake_server, client_factory):
    port, servicer = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}", agent_token="tok123"))

    await client.check_hash("0" * 64, 10)

    assert servicer.last_metadata.get("authorization") == "Bearer tok123"


async def test_토큰이_비어있으면_authorization_헤더가_없다(fake_server, client_factory):
    port, servicer = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}", agent_token=""))

    await client.check_hash("0" * 64, 10)

    assert "authorization" not in servicer.last_metadata


async def test_토큰에_개행이_있으면_VerdictUnavailable(fake_server, client_factory):
    port, _ = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}", agent_token="bad\ntoken"))

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_close_이후_호출하면_VerdictUnavailable(fake_server, client_factory):
    port, _ = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))
    await client.close()

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_CheckHash가_UNSPECIFIED를_반환하면_VerdictUnavailable(fake_server, client_factory):
    port, servicer = fake_server
    servicer.force_check_hash_decision = verdict_pb2.DECISION_UNSPECIFIED
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_CheckHash가_정의되지_않은_enum_값을_반환하면_VerdictUnavailable(fake_server, client_factory):
    # proto3 enum은 열려 있어 정의되지 않은 정수(7)도 그대로 돌아올 수 있다.
    port, servicer = fake_server
    servicer.force_check_hash_decision = 7
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    with pytest.raises(VerdictUnavailable):
        await client.check_hash("0" * 64, 10)


async def test_SubmitFile이_UNKNOWN을_반환하면_VerdictUnavailable(fake_server, client_factory):
    port, servicer = fake_server
    servicer.force_submit_file_decision = verdict_pb2.DECISION_UNKNOWN
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    with pytest.raises(VerdictUnavailable):
        await client.submit_file(
            sha256="0" * 64,
            file_size=4,
            filename="a",
            mime_type="text/plain",
            event_id="e",
            body=b"data",
            timeout=5,
        )


async def test_body가_bytes가_아니면_VerdictUnavailable(fake_server, client_factory):
    port, _ = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))

    with pytest.raises(VerdictUnavailable):
        await client.submit_file(
            sha256="0" * 64,
            file_size=3,
            filename="a",
            mime_type="text/plain",
            event_id="e",
            body="str",
            timeout=5,
        )


async def test_가짜_서버는_metadata가_아닌_메시지로_시작하면_INVALID_ARGUMENT를_반환한다(fake_server):
    # VerdictClient는 항상 metadata를 먼저 보내므로, 이 경로는 가짜 서버를 직접 두들겨 검증한다.
    port, _ = fake_server
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")
    stub = verdict_pb2_grpc.VerdictServiceStub(channel)

    async def bad_iterator():
        yield verdict_pb2.SubmitFileRequest(chunk=b"oops")

    with pytest.raises(grpc.RpcError) as exc_info:
        await stub.SubmitFile(bad_iterator())

    assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    await channel.close()


async def test_report_event는_가짜_서버에_기록된다(fake_server, client_factory):
    port, servicer = fake_server
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{port}"))
    request = verdict_pb2.ReportEventRequest(
        event_id="e-report", sha256="a" * 64, decision=verdict_pb2.FINAL_DECISION_RELEASED
    )

    await client.report_event(request)

    assert len(servicer.report_events) == 1
    assert servicer.report_events[0].event_id == "e-report"


async def test_report_event_실패는_ReportFailed다(client_factory):
    client = client_factory(Config(verdict_server_address=f"127.0.0.1:{unused_port()}", rpc_timeout_seconds=2))
    request = verdict_pb2.ReportEventRequest(event_id="e", decision=verdict_pb2.FINAL_DECISION_RELEASED)

    with pytest.raises(ReportFailed):
        await client.report_event(request)


@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on", "Yes"])
def test_TLS_환경변수가_참으로_해석되는_값들(monkeypatch, raw):
    monkeypatch.setenv("VERDICT_SERVER_TLS", raw)

    assert Config.from_env().verdict_server_tls is True


@pytest.mark.parametrize("raw", ["false", "FALSE", "0", "no", "off", ""])
def test_TLS_환경변수가_거짓으로_해석되는_값들(monkeypatch, raw):
    monkeypatch.setenv("VERDICT_SERVER_TLS", raw)

    assert Config.from_env().verdict_server_tls is False


def test_TLS_환경변수가_알_수_없는_값이면_ValueError(monkeypatch):
    monkeypatch.setenv("VERDICT_SERVER_TLS", "sure")

    with pytest.raises(ValueError):
        Config.from_env()


def test_시간초_환경변수가_유효하면_그대로_반영된다(monkeypatch):
    monkeypatch.setenv("HOLD_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("RPC_TIMEOUT_SECONDS", "3.5")

    config = Config.from_env()

    assert config.hold_timeout_seconds == 45
    assert config.rpc_timeout_seconds == 3.5


@pytest.mark.parametrize("var_name", ["HOLD_TIMEOUT_SECONDS", "RPC_TIMEOUT_SECONDS"])
@pytest.mark.parametrize("raw", ["0", "-1", "nan", "inf", "-inf", "abc", ""])
def test_시간초가_유한한_양수가_아니면_ValueError(monkeypatch, var_name, raw):
    monkeypatch.setenv(var_name, raw)

    with pytest.raises(ValueError):
        Config.from_env()


def test_BODY_SIZE_LIMIT_기본값은_500m다():
    assert Config.from_env().body_size_limit == "500m"


def test_BODY_SIZE_LIMIT_환경변수가_유효하면_그대로_반영된다(monkeypatch):
    monkeypatch.setenv("BODY_SIZE_LIMIT", "10k")

    assert Config.from_env().body_size_limit == "10k"


@pytest.mark.parametrize("raw", ["nope", "0m", "-1m", ""])
def test_BODY_SIZE_LIMIT이_잘못되면_ValueError(monkeypatch, raw):
    monkeypatch.setenv("BODY_SIZE_LIMIT", raw)

    with pytest.raises(ValueError):
        Config.from_env()
