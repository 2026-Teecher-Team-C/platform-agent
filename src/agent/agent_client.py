"""AgentService(등록·하트비트·토큰 갱신·정책) gRPC 클라이언트.

판정 경로가 아니므로 fail-close 경계(VerdictUnavailable)와 무관하다. 모든 실패는 AgentServiceError로 모으고,
호출자(AgentLifecycle)가 로그를 남긴 뒤 다음 주기에 다시 시도한다. 메시지에 토큰 값을 넣지 않는다.
"""

from datetime import UTC, datetime

import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from grpc import aio as grpc_aio

from agent.credentials import Credentials
from agent.identity import AgentIdentity
from agent.policy import Policy
from teecher.agent.v1 import agent_pb2, agent_pb2_grpc


class AgentServiceError(Exception):
    pass


class AgentUnauthenticated(AgentServiceError):
    """토큰(또는 등록 토큰)이 무효·만료·폐기됐다."""


def _credentials(agent_id: str, token: str, expires_at: Timestamp) -> Credentials:
    issued_at = datetime.now(UTC)
    try:
        expires = expires_at.ToDatetime(tzinfo=UTC)
    except (OverflowError, ValueError) as exc:
        raise AgentServiceError("서버가 쓸 수 없는 만료 시각을 돌려줬다") from exc
    if not agent_id or not token or expires <= issued_at:
        raise AgentServiceError("서버가 쓸 수 없는 자격 증명을 돌려줬다")
    return Credentials(agent_id, token, issued_at, expires)


class AgentClient:
    def __init__(self, channel: grpc_aio.Channel, rpc_timeout_seconds: float) -> None:
        self._stub = agent_pb2_grpc.AgentServiceStub(channel)
        self._timeout = rpc_timeout_seconds

    async def _call(self, name: str, method, request, token: str | None):
        metadata = [("authorization", f"Bearer {token}")] if token else None
        try:
            return await method(request, timeout=self._timeout, metadata=metadata)
        except grpc.RpcError as exc:
            code = exc.code() if hasattr(exc, "code") else None
            if code == grpc.StatusCode.UNAUTHENTICATED:
                raise AgentUnauthenticated(f"{name}: 인증 실패") from exc
            raise AgentServiceError(f"{name} 실패: {code}") from exc
        except Exception as exc:
            raise AgentServiceError(f"{name} 실패: {type(exc).__name__}") from exc

    async def register(self, *, enrollment_token: str, identity: AgentIdentity) -> Credentials:
        request = agent_pb2.RegisterAgentRequest(
            enrollment_token=enrollment_token,
            hostname=identity.hostname,
            os_platform=identity.os_platform,
            agent_version=identity.agent_version,
            hardware_uuid=identity.hardware_uuid,
        )
        response = await self._call("RegisterAgent", self._stub.RegisterAgent, request, None)
        return _credentials(response.agent_id, response.agent_token, response.token_expires_at)

    async def heartbeat(self, token: str, agent_version: str) -> None:
        request = agent_pb2.HeartbeatRequest(agent_version=agent_version)
        await self._call("Heartbeat", self._stub.Heartbeat, request, token)

    async def refresh_token(self, current: Credentials) -> Credentials:
        request = agent_pb2.RefreshAgentTokenRequest()
        response = await self._call("RefreshAgentToken", self._stub.RefreshAgentToken, request, current.agent_token)
        return _credentials(current.agent_id, response.agent_token, response.token_expires_at)

    async def get_policy(self, token: str) -> Policy:
        response = await self._call("GetPolicy", self._stub.GetPolicy, agent_pb2.GetPolicyRequest(), token)
        return Policy.from_proto(response)
