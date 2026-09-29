"""RegisterAgent에 보내는 호스트 정보. 사용자 신원은 담지 않는다(식별 단위는 장비)."""

import socket
import sys
from dataclasses import dataclass

from agent import __version__
from agent.platform import hardware_uuid
from teecher.agent.v1 import agent_pb2


@dataclass(frozen=True)
class AgentIdentity:
    hostname: str
    os_platform: int  # agent_pb2.OS_PLATFORM_*
    agent_version: str
    hardware_uuid: str


def os_platform_of(platform: str) -> int:
    if platform == "darwin":
        return agent_pb2.OS_PLATFORM_MACOS
    if platform == "win32":
        return agent_pb2.OS_PLATFORM_WINDOWS
    if platform.startswith("linux"):
        return agent_pb2.OS_PLATFORM_LINUX
    return agent_pb2.OS_PLATFORM_UNSPECIFIED


def current_identity() -> AgentIdentity:
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    try:
        uuid = hardware_uuid()
    except Exception:
        uuid = ""
    return AgentIdentity(hostname, os_platform_of(sys.platform), __version__, uuid)
