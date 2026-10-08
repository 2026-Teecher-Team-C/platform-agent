"""에이전트 생명주기 — 자격 증명 확보(키체인 로드 또는 등록), 하트비트, 토큰 갱신, 정책 갱신.

판정 경로와 분리돼 있고, 여기서 무엇이 실패해도 다운로드는 막히는 쪽으로만 간다:
- 토큰이 없으면 VerdictService가 UNAUTHENTICATED를 돌려주고 VerdictClient가 fail-close로 차단한다
- 정책을 한 번도 못 받았거나 토큰이 거부되면 EMPTY_POLICY(바이패스 없음) — 모든 다운로드를 검사한다
어떤 메서드도 예외를 밖으로 던지지 않는다. 실패는 로그로 남기고 다음 주기에 다시 시도한다.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from agent.agent_client import AgentClient, AgentServiceError, AgentUnauthenticated
from agent.config import Config
from agent.credentials import Credentials, CredentialStore, CredentialStoreError
from agent.identity import AgentIdentity
from agent.policy import EMPTY_POLICY, Policy

logger = logging.getLogger(__name__)


class AgentLifecycle:
    def __init__(
        self,
        config: Config,
        client: AgentClient,
        store: CredentialStore,
        identity: AgentIdentity,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._store = store
        self._identity = identity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._creds: Credentials | None = None
        self._rejected_token = ""
        self._rejections = 0  # _reject가 정책을 비운 횟수. 응답을 기다리는 사이 거부가 있었는지 본다
        self._policy: Policy = EMPTY_POLICY
        self._tasks: list[asyncio.Task] = []

    def token(self) -> str:
        if self._config.agent_token:
            return self._config.agent_token
        return self._creds.agent_token if self._creds else ""

    @property
    def policy(self) -> Policy:
        return self._policy

    async def start(self) -> None:
        for step in (self._ensure_credentials, self.refresh_policy_once, self.heartbeat_once):
            try:
                await step()
            except Exception:
                logger.exception("시작 단계 실패 (%s) — 주기 작업이 다시 시도한다", step.__name__)
        self._tasks = [
            asyncio.create_task(self._every(self._config.heartbeat_interval_seconds, self.tick)),
            asyncio.create_task(self._every(self._config.policy_refresh_seconds, self.refresh_policy_once)),
        ]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    async def tick(self) -> None:
        """하트비트 주기마다: 자격 증명이 없으면 다시 확보, 갱신 시점이면 갱신, 그리고 하트비트."""
        if not self.token():
            await self._ensure_credentials()
            if self.token():
                await self.refresh_policy_once()
        await self.refresh_token_if_due()
        await self.heartbeat_once()

    async def _every(self, interval: float, fn: Callable[[], Awaitable[None]]) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await fn()
            except Exception:
                logger.exception("주기 작업 실패 — 다음 주기에 다시 시도한다")

    async def _ensure_credentials(self) -> None:
        if self._config.agent_token:
            return
        try:
            self._creds = await asyncio.to_thread(self._store.load)
        except Exception:
            logger.exception("자격 증명 로드 실패")
            self._creds = None
        if self._creds is not None and (
            self._creds.agent_token == self._rejected_token or self._creds.expires_at <= self._clock()
        ):
            logger.warning("저장된 자격 증명이 거부됐거나 만료됐다 — 다시 등록한다")
            self._creds = None
        if self._creds is not None:
            return
        if not self._config.enrollment_token:
            logger.error("자격 증명이 없고 ENROLLMENT_TOKEN도 없다 — 모든 다운로드가 fail-close로 차단된다")
            return
        try:
            creds = await self._client.register(enrollment_token=self._config.enrollment_token, identity=self._identity)
        except AgentServiceError as exc:
            logger.error("에이전트 등록 실패: %s", exc)
            return
        self._creds = creds
        logger.info("에이전트 등록 완료: agent_id=%s", creds.agent_id)
        await self._save(creds)

    async def _save(self, creds: Credentials) -> None:
        try:
            await asyncio.to_thread(self._store.save, creds)
        except CredentialStoreError as exc:
            logger.error("자격 증명 저장 실패 — 이번 실행 동안은 메모리의 토큰을 쓴다: %s", exc)

    def _reject(self, token: str, operation: str) -> None:
        if token != self.token():
            # 응답을 기다리는 사이 토큰이 갱신·재등록으로 바뀌었다. 예전 토큰의 거부로 새 자격 증명을 지우지 않는다
            logger.info("%s: 이미 바뀐 예전 토큰이 거부됐다 — 무시한다", operation)
            return
        self._rejections += 1
        # 거부된 토큰으로 받은 바이패스 정책을 계속 쓰면 검사 없이 통과시키게 된다. 수동 AGENT_TOKEN도 마찬가지로
        # 비우고, 토큰이 다시 통하면 다음 정책 갱신에서 새로 받는다. 일시적 오류에서는 부르지 않는다
        self._policy = EMPTY_POLICY
        if self._config.agent_token:
            logger.warning("%s: 수동 AGENT_TOKEN이 거부됐다", operation)
            return
        logger.warning("%s: 서버가 토큰을 거부했다 — 다음 주기에 다시 등록한다", operation)
        self._rejected_token = token
        self._creds = None

    async def heartbeat_once(self) -> None:
        token = self.token()
        if not token:
            return
        try:
            await self._client.heartbeat(token, self._identity.agent_version)
        except AgentUnauthenticated:
            self._reject(token, "하트비트")
        except AgentServiceError as exc:
            logger.warning("하트비트 실패: %s", exc)

    async def refresh_token_if_due(self) -> None:
        if self._config.agent_token or self._creds is None:
            return
        if not self._creds.refresh_due(self._clock()):
            return
        token = self._creds.agent_token
        try:
            creds = await self._client.refresh_token(self._creds)
        except AgentUnauthenticated:
            self._reject(token, "토큰 갱신")
            return
        except AgentServiceError as exc:
            logger.warning("토큰 갱신 실패 — 기존 토큰을 만료까지 쓴다: %s", exc)
            return
        self._creds = creds
        await self._save(creds)

    async def refresh_policy_once(self) -> None:
        token = self.token()
        if not token:
            return
        rejections = self._rejections
        try:
            policy = await self._client.get_policy(token)
        except AgentUnauthenticated:
            self._reject(token, "정책 수신")
            return
        except AgentServiceError as exc:
            logger.warning("정책 수신 실패 — 마지막으로 받은 정책을 유지한다: %s", exc)
            return
        if rejections != self._rejections or token != self.token():
            # 기다리는 사이 토큰이 거부됐거나 바뀌었다. 늦게 온 바이패스 정책으로 EMPTY_POLICY를 덮지 않는다
            logger.info("정책 수신 중 토큰이 거부되거나 바뀌었다 — 받은 정책을 버린다")
            return
        self._policy = policy
