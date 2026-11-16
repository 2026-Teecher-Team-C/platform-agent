"""보류된 다운로드 본문. 에이전트가 본문에 접근하는 길은 크기·해시·청크 읽기 셋뿐이다.

S2는 버퍼링을 유지한다(2026-09-29 팀 결정) — 본문은 mitmproxy가 메모리에 담아 둔 `raw_content`다.
고도화에서 디스크 스풀(설계 레포 docs/superpowers/specs/2026-09-29-spool-spike.md의 B안)로 바꿀 때는
`held_body_of`가 스풀 구현을 돌려주게 하면 된다. 호출부(addon, verdict_client)는 바뀌지 않는다.
"""

import asyncio
import hashlib
from collections.abc import AsyncIterator
from typing import Protocol

import tlsh as py_tlsh
from mitmproxy import http

# 서버 계산기(TLSH Java 포트, force 모드)의 최소 길이. 이보다 짧으면 TLSH가 없다.
TLSH_MIN_BYTES = 50
TLSH_UPDATE_BYTES = 256 * 1024


class HeldBody(Protocol):
    @property
    def size(self) -> int: ...

    async def sha256(self) -> str: ...

    async def tlsh(self) -> str | None: ...

    def chunks(self, chunk_size: int) -> AsyncIterator[bytes]: ...


class MemoryBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    async def sha256(self) -> str:
        return (await asyncio.to_thread(hashlib.sha256, self._data)).hexdigest()

    async def tlsh(self) -> str | None:
        """서버 형식(`T1` + 대문자 16진 70자)의 TLSH. 계산할 수 없으면 None.

        SHA-256처럼 바이트 수준 퍼지 해시일 뿐 파일 형식을 파싱하지 않는다.
        CPU 작업이므로 이벤트 루프 밖에서 돌린다.
        """
        return await asyncio.to_thread(self._compute_tlsh)

    def _compute_tlsh(self) -> str | None:
        if len(self._data) < TLSH_MIN_BYTES:
            return None
        # py-tlsh는 GIL을 쥔 채 계산한다. 한 번에 hash()하면 500MB에 약 6초 동안 스레드로 빼도 이벤트 루프가
        # 멈춘다. 조각으로 나눠 update()하면 호출 사이에 GIL이 풀려 다른 flow가 계속 돈다(결과는 같다).
        hasher = py_tlsh.Tlsh()
        for offset in range(0, len(self._data), TLSH_UPDATE_BYTES):
            hasher.update(self._data[offset : offset + TLSH_UPDATE_BYTES])
        try:
            hasher.final()
            digest = hasher.hexdigest()
        except ValueError:
            # 내용이 단조로워 분산이 부족하다(서버의 TNULL과 같다) — TLSH 없음.
            return None
        if not digest or digest == "TNULL":
            return None
        return digest

    async def chunks(self, chunk_size: int) -> AsyncIterator[bytes]:
        for offset in range(0, len(self._data), chunk_size):
            yield self._data[offset : offset + chunk_size]


def held_body_of(flow: http.HTTPFlow) -> HeldBody | None:
    """저장될 본문이 없으면(HEAD/204/304 등) None."""
    # `.content`는 Content-Encoding을 풀므로 쓰지 않는다.
    data = flow.response.raw_content
    return MemoryBody(data) if data else None
