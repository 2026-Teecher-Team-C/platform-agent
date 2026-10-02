"""보류된 다운로드 본문. 에이전트가 본문에 접근하는 길은 크기·해시·청크 읽기 셋뿐이다.

S2는 버퍼링을 유지한다(2026-09-29 팀 결정) — 본문은 mitmproxy가 메모리에 담아 둔 `raw_content`다.
고도화에서 디스크 스풀(설계 레포 docs/superpowers/specs/2026-09-29-spool-spike.md의 B안)로 바꿀 때는
`held_body_of`가 스풀 구현을 돌려주게 하면 된다. 호출부(addon, verdict_client)는 바뀌지 않는다.
"""

import asyncio
import hashlib
from collections.abc import AsyncIterator
from typing import Protocol

from mitmproxy import http


class HeldBody(Protocol):
    @property
    def size(self) -> int: ...

    async def sha256(self) -> str: ...

    def chunks(self, chunk_size: int) -> AsyncIterator[bytes]: ...


class MemoryBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    async def sha256(self) -> str:
        return (await asyncio.to_thread(hashlib.sha256, self._data)).hexdigest()

    async def chunks(self, chunk_size: int) -> AsyncIterator[bytes]:
        for offset in range(0, len(self._data), chunk_size):
            yield self._data[offset : offset + chunk_size]


def held_body_of(flow: http.HTTPFlow) -> HeldBody | None:
    """저장될 본문이 없으면(HEAD/204/304 등) None."""
    # `.content`는 Content-Encoding을 풀므로 쓰지 않는다.
    data = flow.response.raw_content
    return MemoryBody(data) if data else None
