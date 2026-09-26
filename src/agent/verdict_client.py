"""검사 서버(VerdictService)와의 gRPC 클라이언트. fail-close 경계는 여기 하나뿐이다.

grpc.aio 채널은 현재 실행 중인 이벤트 루프에 묶인다. mitmproxy addon의 `running()` 훅
안에서 만들고 `done()` 훅에서 `close()`해야 한다 — 다른 루프에서 만들면 못 쓴다.
"""

import asyncio

import grpc
from grpc import aio as grpc_aio

from agent.config import Config
from teecher.verdict.v1 import verdict_pb2, verdict_pb2_grpc

CHUNK_SIZE = 64 * 1024

_VALID_CHECK_HASH_DECISIONS = frozenset(
    {verdict_pb2.DECISION_ALLOW, verdict_pb2.DECISION_BLOCK, verdict_pb2.DECISION_UNKNOWN}
)
_VALID_SUBMIT_FILE_DECISIONS = frozenset({verdict_pb2.DECISION_ALLOW, verdict_pb2.DECISION_BLOCK})


class VerdictUnavailable(Exception):
    """검사 서버 판정을 신뢰할 수 없을 때 던진다 — 호출자는 이걸 차단으로 취급한다.

    gRPC 오류(연결 실패·타임아웃 포함)든, 토큰에 개행이 섞여 생기는 gRPC 계층 오류든,
    닫힌 채널 사용이든, 응답의 decision이 알려지지 않은 값이든 — 무엇이든 이 예외 하나로
    수렴한다. fail-close 경계는 여기 하나뿐이다 (mitmproxy는 훅에서 새는 예외를 로그만
    남기고 원래 응답을 통과시키므로, VerdictUnavailable이 아닌 예외가 새면 fail-open이 된다).
    """


class ReportFailed(Exception):
    """ReportEvent 실패. 판정은 이미 끝난 뒤이므로 fail-close 대상이 아니다 — 호출자는
    로그만 남기고 무시한다."""


class VerdictClient:
    def __init__(self, config: Config, channel: grpc_aio.Channel | None = None) -> None:
        self._config = config
        if channel is not None:
            self._channel = channel
        elif config.verdict_server_tls:
            self._channel = grpc_aio.secure_channel(config.verdict_server_address, grpc.ssl_channel_credentials())
        else:
            self._channel = grpc_aio.insecure_channel(config.verdict_server_address)
        self._stub = verdict_pb2_grpc.VerdictServiceStub(self._channel)

    def _metadata(self) -> list[tuple[str, str]] | None:
        if not self._config.agent_token:
            return None
        return [("authorization", f"Bearer {self._config.agent_token}")]

    async def check_hash(self, sha256: str, file_size: int) -> verdict_pb2.CheckHashResponse:
        request = verdict_pb2.CheckHashRequest(sha256=sha256, file_size=file_size)
        try:
            response = await self._stub.CheckHash(
                request, timeout=self._config.rpc_timeout_seconds, metadata=self._metadata()
            )
        except grpc.RpcError as exc:
            raise VerdictUnavailable(f"CheckHash 실패: {exc}") from exc
        except Exception as exc:
            # 개행이 섞인 토큰(cygrpc.ExecuteBatchError), 닫힌 채널(cygrpc.UsageError) 등
            # RpcError가 아닌 gRPC 계층 예외도 전부 fail-close로 바꾼다.
            raise VerdictUnavailable(f"CheckHash 실패: {exc}") from exc
        # proto3 enum은 열려 있어 정의되지 않은 정수도 그대로 돌아올 수 있다 — 화이트리스트로만 통과시킨다.
        if response.decision not in _VALID_CHECK_HASH_DECISIONS:
            raise VerdictUnavailable(f"CheckHash가 알 수 없는 decision을 반환했다: {response.decision}")
        return response

    async def submit_file(
        self,
        *,
        sha256: str,
        file_size: int,
        filename: str,
        mime_type: str,
        event_id: str,
        body: bytes,
        timeout: float,
    ) -> verdict_pb2.SubmitFileResponse:
        try:
            metadata_message = verdict_pb2.SubmitFileRequest(
                metadata=verdict_pb2.SubmitFileMetadata(
                    sha256=sha256, file_size=file_size, filename=filename, mime_type=mime_type, event_id=event_id
                )
            )
        except Exception as exc:
            raise VerdictUnavailable(f"SubmitFile 실패: {exc}") from exc

        # 청크를 만드는 도중 예외(예: body가 bytes가 아님, S2의 스풀 I/O 오류)가 나면
        # grpc.aio는 이 스트림을 읽는 내부 태스크를 실패시키고, 우리 쪽 await에는
        # asyncio.CancelledError로 전달한다. 원래 예외를 저장해뒀다가 CancelledError를
        # 받으면 다시 꺼내 fail-close로 바꾼다. 진짜 외부 취소(cancelling() > 0)는 그대로 통과시킨다.
        iterator_error: Exception | None = None

        async def request_iterator():
            nonlocal iterator_error
            try:
                yield metadata_message
                # S1은 본문을 메모리에 담아 보낸다. S2에서 스풀 파일 스트리밍으로 바꾼다.
                for offset in range(0, len(body), CHUNK_SIZE):
                    yield verdict_pb2.SubmitFileRequest(chunk=body[offset : offset + CHUNK_SIZE])
            except Exception as exc:
                iterator_error = exc
                raise

        try:
            response = await self._stub.SubmitFile(request_iterator(), timeout=timeout, metadata=self._metadata())
        except asyncio.CancelledError:
            current_task = asyncio.current_task()
            if iterator_error is not None and current_task is not None and current_task.cancelling() == 0:
                raise VerdictUnavailable(f"SubmitFile 실패: {iterator_error}") from iterator_error
            raise
        except grpc.RpcError as exc:
            raise VerdictUnavailable(f"SubmitFile 실패: {exc}") from exc
        except Exception as exc:
            raise VerdictUnavailable(f"SubmitFile 실패: {exc}") from exc
        if response.decision not in _VALID_SUBMIT_FILE_DECISIONS:
            raise VerdictUnavailable(f"SubmitFile이 ALLOW/BLOCK이 아닌 decision을 반환했다: {response.decision}")
        return response

    async def report_event(self, request: verdict_pb2.ReportEventRequest) -> None:
        try:
            await self._stub.ReportEvent(request, timeout=self._config.rpc_timeout_seconds, metadata=self._metadata())
        except Exception as exc:
            raise ReportFailed(f"ReportEvent 실패: {exc}") from exc

    async def close(self) -> None:
        await self._channel.close()
