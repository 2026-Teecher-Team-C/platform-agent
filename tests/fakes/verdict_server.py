"""테스트용 가짜 VerdictService. 실제 판정 로직(YARA 등) 없이 EICAR 문자열만 본다.

단독 실행(수동 브라우저 테스트용), 저장소 루트에서:

    PYTHONPATH=src uv run python -m tests.fakes.verdict_server --port 9090

(pytest는 pyproject.toml의 pythonpath=src로 이미 해결되어 있어 이 옵션이 필요 없다.)

compose에서 별도 컨테이너로 띄워 다른 서비스에서 fake-verdict:9090으로 붙게 하려면:

    PYTHONPATH=src uv run python -m tests.fakes.verdict_server --host 0.0.0.0 --port 9090
"""

import argparse
import asyncio

import grpc
from grpc import aio as grpc_aio

from teecher.verdict.v1 import verdict_pb2, verdict_pb2_grpc

EICAR_BODY = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _metadata_dict(context: grpc_aio.ServicerContext) -> dict[str, str]:
    return dict(context.invocation_metadata() or ())


class FakeVerdictServicer(verdict_pb2_grpc.VerdictServiceServicer):
    """delay_seconds를 걸면 응답 전에 대기한다 (데드라인 테스트용).

    force_*_decision을 설정하면 해시/본문 내용과 무관하게 그 값을 그대로 돌려준다.
    proto3 enum은 열려 있어 정의되지 않은 정수(예: 7)도 유효한 값이므로, 클라이언트가
    그런 응답을 화이트리스트로 거르는지 테스트할 때 쓴다.
    """

    def __init__(self, delay_seconds: float = 0.0) -> None:
        self.delay_seconds = delay_seconds
        self.report_events: list[verdict_pb2.ReportEventRequest] = []
        self.last_metadata: dict[str, str] = {}
        self.last_submit_body: bytes = b""
        self.force_check_hash_decision: int | None = None
        self.force_check_hash_source: int = verdict_pb2.DECISION_SOURCE_UNSPECIFIED
        self.force_submit_file_decision: int | None = None
        self.force_submit_file_matched_rules: list[str] = []

    async def CheckHash(self, request, context):
        self.last_metadata = _metadata_dict(context)
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.force_check_hash_decision is not None:
            response = verdict_pb2.CheckHashResponse(source=self.force_check_hash_source)
            response.decision = self.force_check_hash_decision
            return response
        if request.sha256 == EICAR_SHA256:
            return verdict_pb2.CheckHashResponse(
                decision=verdict_pb2.DECISION_BLOCK,
                source=verdict_pb2.DECISION_SOURCE_BLACKLIST,
                reason="EICAR test file",
            )
        return verdict_pb2.CheckHashResponse(decision=verdict_pb2.DECISION_UNKNOWN)

    async def SubmitFile(self, request_iterator, context):
        self.last_metadata = _metadata_dict(context)

        first = await request_iterator.__anext__()
        if first.WhichOneof("payload") != "metadata":
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("첫 메시지는 metadata여야 한다")
            return verdict_pb2.SubmitFileResponse()

        chunks = []
        async for message in request_iterator:
            chunks.append(message.chunk)
        body = b"".join(chunks)
        self.last_submit_body = body

        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)

        if self.force_submit_file_decision is not None:
            response = verdict_pb2.SubmitFileResponse(matched_rules=self.force_submit_file_matched_rules)
            response.decision = self.force_submit_file_decision
            return response

        if EICAR_BODY in body:
            return verdict_pb2.SubmitFileResponse(
                decision=verdict_pb2.DECISION_BLOCK,
                source=verdict_pb2.DECISION_SOURCE_ENGINE,
                matched_rules=["EICAR"],
            )
        return verdict_pb2.SubmitFileResponse(
            decision=verdict_pb2.DECISION_ALLOW, source=verdict_pb2.DECISION_SOURCE_ENGINE
        )

    async def ReportEvent(self, request, context):
        self.last_metadata = _metadata_dict(context)
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        self.report_events.append(request)
        return verdict_pb2.ReportEventResponse()


async def create_server(host: str = "127.0.0.1", port: int = 0) -> tuple[grpc_aio.Server, int, FakeVerdictServicer]:
    """port=0이면 빈 포트를 골라 바인딩한다. (server, bound_port, servicer)를 돌려준다."""
    servicer = FakeVerdictServicer()
    server = grpc_aio.server()
    verdict_pb2_grpc.add_VerdictServiceServicer_to_server(servicer, server)
    bound_port = server.add_insecure_port(f"{host}:{port}")
    await server.start()
    return server, bound_port, servicer


async def _main(host: str, port: int) -> None:
    server, bound_port, _ = await create_server(host=host, port=port)
    print(f"fake VerdictService listening on {host}:{bound_port}")
    await server.wait_for_termination()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # compose에서 별도 서비스로 띄울 때는 --host 0.0.0.0으로 다른 컨테이너(fake-verdict:9090)에서 붙게 한다.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    args = parser.parse_args()
    asyncio.run(_main(args.host, args.port))
