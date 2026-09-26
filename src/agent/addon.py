"""mitmproxy 보류 파이프라인 — 다운로드 응답을 붙잡고 검사 서버 판정에 따라 통과시키거나 403으로 바꾼다.

mitmdump 진입점은 `src/addon_entry.py`다. 이 모듈은 import 시 부작용이 없다.

mitmproxy는 훅에서 새는 예외를 로그만 남기고 원래 응답을 통과시킨다. 그래서 다운로드 경로의
모든 예외는 이 모듈 안에서 잡아 403으로 끝낸다 — 여기서 예외가 새면 그게 곧 fail-open이다.
"""

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass

from google.protobuf.timestamp_pb2 import Timestamp
from mitmproxy import ctx, exceptions, http

from agent.config import Config
from agent.detection import filename_of, is_download
from agent.verdict_client import VerdictClient
from teecher.verdict.v1 import verdict_pb2

logger = logging.getLogger(__name__)

HOLD_KEY = "agent.hold"
PASSTHROUGH_KEY = "agent.passthrough"
# Config 파싱 전에 먼저 거는 안전한 기본값. 파싱에 성공하면 config.body_size_limit으로 바꾼다.
SAFE_BODY_SIZE_LIMIT = "500m"
ENCODED_DOWNLOAD_REASON = "encoded download unsupported"


@dataclass
class Hold:
    """`responseheaders` 시점의 스냅샷. 403으로 바꾼 뒤에도 원래 헤더 값을 보고할 수 있게 먼저 떠 둔다."""

    event_id: str
    url: str
    request_host: str
    filename: str  # 공격자가 정한 값 — 표시·전송 전용
    mime_type: str
    content_disposition: str
    content_encoding: str
    held_at: float
    held_at_monotonic: float
    sha256: str = ""
    file_size: int = 0
    reported: bool = False


@dataclass(frozen=True)
class Outcome:
    decision: int  # verdict_pb2.FinalDecision
    source: int = verdict_pb2.DECISION_SOURCE_UNSPECIFIED
    reason: str = ""
    cache_hit: bool = False
    bytes_uploaded: int = 0


FAIL_CLOSE = Outcome(verdict_pb2.FINAL_DECISION_FAIL_CLOSE)


def _snapshot(flow: http.HTTPFlow) -> Hold:
    headers = flow.response.headers
    return Hold(
        event_id=str(uuid.uuid4()),
        url=flow.request.pretty_url,
        request_host=flow.request.pretty_host,
        filename=filename_of(flow.request.pretty_url, headers),
        mime_type=headers.get("content-type", "").split(";")[0].strip().lower(),
        content_disposition=headers.get("content-disposition", ""),
        content_encoding=",".join(headers.get_all("content-encoding")),
        held_at=time.time(),
        held_at_monotonic=time.monotonic(),
    )


def _is_encoded(content_encoding: str) -> bool:
    # `gzip, br`처럼 겹쳐 쓴 값도 있다. identity 외의 값이 하나라도 있으면 인코딩된 본문이다.
    return any(v.strip().lower() not in ("", "identity") for v in content_encoding.split(","))


def _forbidden(outcome: Outcome, event_id: str) -> http.Response:
    # 파일명 등 공격자가 채운 값은 넣지 않는다. text/plain이라 HTML로 해석될 여지도 없다.
    if outcome.decision == verdict_pb2.FINAL_DECISION_BLOCKED:
        body = f"다운로드가 차단되었습니다.\n사유: {outcome.reason or '(없음)'}\n"
    else:
        body = "다운로드가 차단되었습니다: 검사 서버의 판정을 받지 못했습니다 (fail-close).\n"
    body += f"이벤트 ID: {event_id}\n"
    return http.Response.make(
        403,
        body,
        {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
    )


def _timestamp(seconds: float) -> Timestamp:
    ts = Timestamp()
    ts.FromNanoseconds(int(seconds * 1e9))
    return ts


class HoldPipeline:
    def __init__(self) -> None:
        self.config: Config | None = None
        self.client: VerdictClient | None = None
        self._started = False
        self._report_tasks: set[asyncio.Task] = set()

    def running(self) -> None:
        # stream_large_bodies가 켜져 있으면 mitmproxy가 큰 다운로드를 스스로 스트리밍해 헤더를 먼저
        # 내보낸다 — 보류 우회(fail-open)다. Config 파싱이 실패해도 옵션은 안전하도록 먼저 건다.
        if ctx.options.stream_large_bodies:
            logger.warning("stream_large_bodies=%s 는 보류를 우회하므로 끈다", ctx.options.stream_large_bodies)
        ctx.options.update(stream_large_bodies=None, body_size_limit=SAFE_BODY_SIZE_LIMIT)

        # 여기서 예외가 나면 client가 None으로 남고, 이후 모든 다운로드는 403이 된다(fail-close).
        self.config = Config.from_env()
        ctx.options.update(body_size_limit=self.config.body_size_limit)
        # grpc.aio 채널은 실행 중인 루프에 묶인다 — running() 안에서 만든다.
        self.client = VerdictClient(self.config)
        self._started = True
        logger.info(
            "보류 파이프라인 시작: server=%s body_size_limit=%s hold_timeout=%ss",
            self.config.verdict_server_address,
            ctx.options.body_size_limit,
            self.config.hold_timeout_seconds,
        )

    def configure(self, updated: set[str]) -> None:
        # 시작 뒤 옵션 변경으로 보류 우회·상한 해제가 되지 않게 막는다. 시작 전 값은 running()이 덮어쓴다.
        if not self._started:
            return
        if "stream_large_bodies" in updated and ctx.options.stream_large_bodies is not None:
            raise exceptions.OptionsError("stream_large_bodies는 다운로드 보류를 우회하므로 켤 수 없다")
        if "body_size_limit" in updated and not ctx.options.body_size_limit:
            raise exceptions.OptionsError("body_size_limit을 해제할 수 없다")

    async def done(self) -> None:
        await self.drain_reports()
        if self.client is not None:
            await self.client.close()

    async def drain_reports(self) -> None:
        """진행 중인 ReportEvent를 기다린다. 종료 시와 테스트에서 쓴다."""
        while self._report_tasks:
            await asyncio.gather(*self._report_tasks, return_exceptions=True)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # 요청 본문은 보지 않는다. 버퍼링하면 업로드가 메모리에 쌓이고 body_size_limit에 걸려 413이 난다.
        flow.request.stream = True

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # 헤더가 나간 뒤에는 차단할 수 없으므로, 판별이 실패하면 다운로드로 간주해 붙잡는다.
        try:
            if not is_download(flow.request.headers, flow.response.headers).is_download:
                flow.metadata[PASSTHROUGH_KEY] = True
                flow.response.stream = True
                return
        except Exception:
            logger.exception("다운로드 판별 실패 — 다운로드로 간주해 보류한다: %s", flow.request.pretty_url)
        flow.response.stream = False
        try:
            flow.metadata[HOLD_KEY] = _snapshot(flow)
        except Exception:
            # response()가 스냅샷을 다시 만든다. 거기서도 실패하면 403이다.
            logger.exception("보류 스냅샷 생성 실패: %s", flow.request.pretty_url)

    async def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get(PASSTHROUGH_KEY):
            return
        if flow.response.stream:
            # 우리가 통과시키지 않았는데 스트리밍됐다 — 헤더는 이미 나갔으니 연결이라도 끊는다.
            logger.error("보류 대상이 스트리밍되었다 — flow를 끊는다: %s", flow.request.pretty_url)
            try:
                flow.kill()
            except Exception:
                logger.exception("flow kill 실패: %s", flow.request.pretty_url)
            return
        if flow.request.method == "HEAD" or not flow.response.raw_content:
            # 저장될 본문이 없다(HEAD/204/304 등) — 검사·보고하지 않는다.
            return

        hold: Hold | None = None
        try:
            hold = flow.metadata.get(HOLD_KEY) or _snapshot(flow)
            if self.client is None or self.config is None:
                raise RuntimeError("보류 파이프라인이 시작되지 않았다 (running() 실패?)")
            outcome = await asyncio.wait_for(self._decide(flow, hold), self.config.hold_timeout_seconds)
        except asyncio.CancelledError:
            # 외부 취소(종료 등)는 삼키지 않고 다시 던진다. 다만 호출자가 취소를 삼키고 응답을 내보내더라도
            # 원본이 나가지 않도록 먼저 403으로 바꿔 둔다.
            flow.response = _forbidden(FAIL_CLOSE, hold.event_id if hold else "-")
            raise
        except Exception:
            logger.exception("판정 실패 — fail-close로 차단한다: %s", flow.request.pretty_url)
            outcome = FAIL_CLOSE

        event_id = hold.event_id if hold else "-"
        if outcome.decision == verdict_pb2.FINAL_DECISION_RELEASED:
            logger.info("통과: %s (event=%s)", flow.request.pretty_url, event_id)
        else:
            flow.response = _forbidden(outcome, event_id)
            logger.warning("차단: %s (event=%s, reason=%s)", flow.request.pretty_url, event_id, outcome.reason)

        if hold is not None:
            self._schedule_report(hold, outcome)

    def error(self, flow: http.HTTPFlow) -> None:
        # 판정 전에 끝난 보류 flow(body_size_limit 초과 502, 연결 끊김 등)도 기록한다.
        try:
            hold = flow.metadata.get(HOLD_KEY)
            if hold is None or hold.reported:
                return
            reason = flow.error.msg if flow.error else ""
            self._schedule_report(
                hold, Outcome(verdict_pb2.FINAL_DECISION_FAIL_CLOSE, verdict_pb2.DECISION_SOURCE_POLICY, reason)
            )
        except Exception:
            logger.exception("오류 flow 보고 실패: %s", flow.request.pretty_url)

    async def _decide(self, flow: http.HTTPFlow, hold: Hold) -> Outcome:
        assert self.client is not None and self.config is not None  # response()에서 확인했다
        deadline = time.monotonic() + self.config.hold_timeout_seconds

        # 압축 해제는 에이전트가 하지 않는다(1MB gzip → 1GB, body_size_limit은 원본 바이트만 센다).
        # 서버의 격리 환경에서 풀려면 SubmitFileMetadata에 content_encoding을 더하는 S2 계약 변경이 필요하다.
        if _is_encoded(hold.content_encoding):
            return Outcome(
                verdict_pb2.FINAL_DECISION_BLOCKED, verdict_pb2.DECISION_SOURCE_POLICY, ENCODED_DOWNLOAD_REASON
            )

        # S1은 본문이 메모리에 있다(버퍼링). S2의 스트리밍 스풀은 mitmproxy 실측상 헤더를 붙잡은 채로는
        # 불가능하다 — 설계 레포 docs/superpowers/specs/2026-09-26-header-timing.md 참고.
        # `.content`는 Content-Encoding을 풀므로 쓰지 않는다.
        body = flow.response.raw_content or b""
        hold.file_size = len(body)
        hold.sha256 = (await asyncio.to_thread(hashlib.sha256, body)).hexdigest()

        check = await self.client.check_hash(hold.sha256, hold.file_size)
        if check.decision == verdict_pb2.DECISION_ALLOW:
            return Outcome(verdict_pb2.FINAL_DECISION_RELEASED, check.source, check.reason, cache_hit=True)
        if check.decision == verdict_pb2.DECISION_BLOCK:
            return Outcome(verdict_pb2.FINAL_DECISION_BLOCKED, check.source, check.reason, cache_hit=True)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("보류 시간 초과 (CheckHash 이후 남은 시간 없음)")
        submit = await self.client.submit_file(
            sha256=hold.sha256,
            file_size=hold.file_size,
            filename=hold.filename,
            mime_type=hold.mime_type,
            event_id=hold.event_id,
            body=body,
            timeout=remaining,
        )
        reason = submit.reason or ", ".join(submit.matched_rules)
        if submit.decision == verdict_pb2.DECISION_ALLOW:
            return Outcome(verdict_pb2.FINAL_DECISION_RELEASED, submit.source, reason, bytes_uploaded=len(body))
        return Outcome(verdict_pb2.FINAL_DECISION_BLOCKED, submit.source, reason, bytes_uploaded=len(body))

    def _schedule_report(self, hold: Hold, outcome: Outcome) -> None:
        # 판정 뒤의 일이라 보류 시간에 넣지 않는다. 실패해도 판정은 바뀌지 않는다.
        hold.reported = True
        try:
            decided_at = time.time()
            request = verdict_pb2.ReportEventRequest(
                event_id=hold.event_id,
                sha256=hold.sha256,
                url=hold.url,
                request_host=hold.request_host,
                filename=hold.filename,
                mime_type=hold.mime_type,
                content_disposition=hold.content_disposition,
                file_size=hold.file_size,
                decision=outcome.decision,
                decision_source=outcome.source,
                cache_hit=outcome.cache_hit,
                bytes_uploaded=outcome.bytes_uploaded,
                held_at=_timestamp(hold.held_at),
                decided_at=_timestamp(decided_at),
                hold_duration_ms=int((time.monotonic() - hold.held_at_monotonic) * 1000),
            )
            task = asyncio.create_task(self._report(request))
        except Exception:
            logger.exception("ReportEvent 준비 실패 (event=%s)", hold.event_id)
            return
        self._report_tasks.add(task)
        task.add_done_callback(self._report_tasks.discard)

    async def _report(self, request: verdict_pb2.ReportEventRequest) -> None:
        try:
            await self.client.report_event(request)
        except Exception:
            logger.exception("ReportEvent 실패 (event=%s)", request.event_id)
