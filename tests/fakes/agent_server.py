"""테스트용 가짜 AgentService. 등록 토큰은 1회용, 토큰 갱신 시 이전 토큰은 즉시 무효 — 실서버 계약과 같다."""

from datetime import UTC, datetime, timedelta

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from teecher.agent.v1 import agent_pb2, agent_pb2_grpc


def _timestamp(value: datetime) -> Timestamp:
    ts = Timestamp()
    ts.FromDatetime(value)
    return ts


class FakeAgentServicer(agent_pb2_grpc.AgentServiceServicer):
    def __init__(self) -> None:
        self.enrollment_tokens: set[str] = {"enroll-ok"}
        self.valid_tokens: set[str] = set()
        self.token_lifetime = timedelta(hours=24)
        self.registrations: list[agent_pb2.RegisterAgentRequest] = []
        self.heartbeats: list[tuple[str, str]] = []
        self.policy = agent_pb2.GetPolicyResponse()
        self.policy_calls = 0
        # 설정하면 모든 RPC가 이 코드로 실패한다
        self.fail_code: grpc.StatusCode | None = None
        self._seq = 0

    def _issue(self) -> tuple[str, Timestamp]:
        self._seq += 1
        token = f"tok-{self._seq}"
        self.valid_tokens.add(token)
        return token, _timestamp(datetime.now(UTC) + self.token_lifetime)

    async def _fail_if_forced(self, context) -> None:
        if self.fail_code is not None:
            await context.abort(self.fail_code, "forced failure")

    async def _authorized(self, context) -> str:
        await self._fail_if_forced(context)
        auth = dict(context.invocation_metadata() or ()).get("authorization", "")
        token = auth.removeprefix("Bearer ")
        if not auth.startswith("Bearer ") or token not in self.valid_tokens:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid agent token")
        return token

    async def RegisterAgent(self, request, context):
        await self._fail_if_forced(context)
        self.registrations.append(request)
        if request.enrollment_token not in self.enrollment_tokens:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid enrollment token")
        self.enrollment_tokens.discard(request.enrollment_token)
        token, expires = self._issue()
        return agent_pb2.RegisterAgentResponse(
            agent_id=f"agent-{self._seq}", agent_token=token, token_expires_at=expires
        )

    async def Heartbeat(self, request, context):
        token = await self._authorized(context)
        self.heartbeats.append((token, request.agent_version))
        return agent_pb2.HeartbeatResponse(server_time=_timestamp(datetime.now(UTC)))

    async def RefreshAgentToken(self, request, context):
        old = await self._authorized(context)
        self.valid_tokens.discard(old)
        token, expires = self._issue()
        return agent_pb2.RefreshAgentTokenResponse(agent_token=token, token_expires_at=expires)

    async def GetPolicy(self, request, context):
        await self._authorized(context)
        self.policy_calls += 1
        return self.policy
