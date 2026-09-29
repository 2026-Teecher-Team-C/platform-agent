"""GetPolicy로 받은 정책. 메모리에만 둔다(에이전트는 정책을 저장하지 않는다).

- 바이패스 호스트는 와일드카드 없는 정확한 호스트만 인정한다(ERD ck_bypass_domains_exact_host).
  `*.google.com`은 drive.google.com까지 면제해 검사 구멍을 만든다.
- file_type_policies는 받아 보관만 한다(2026-09-29 결정). 에이전트가 유형을 판단할 근거는 공격자가 정한
  MIME·확장자뿐이라, 검사를 줄이는 값(NONE·HASH_ONLY)을 따르면 우회 경로가 된다.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from teecher.agent.v1 import agent_pb2

_KNOWN_CATEGORIES = frozenset({agent_pb2.BYPASS_CATEGORY_PINNED, agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE})


def normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


@dataclass(frozen=True)
class Policy:
    bypass_hosts: Mapping[str, int]
    file_type_policies: tuple[agent_pb2.FileTypePolicy, ...] = ()

    @staticmethod
    def from_proto(response: agent_pb2.GetPolicyResponse) -> "Policy":
        hosts: dict[str, int] = {}
        for entry in response.bypass_hosts:
            host = normalize_host(entry.host)
            if not host or "*" in host or entry.category not in _KNOWN_CATEGORIES:
                continue
            hosts[host] = entry.category
        return Policy(MappingProxyType(hosts), tuple(response.file_type_policies))

    def bypass_category(self, host: str) -> int | None:
        return self.bypass_hosts.get(normalize_host(host))


EMPTY_POLICY = Policy(MappingProxyType({}))
