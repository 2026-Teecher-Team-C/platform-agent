import gzip
import hashlib
import os

import pytest
from mitmproxy.test import tflow

from agent.held_body import MemoryBody, held_body_of


async def collect(body, chunk_size):
    return [chunk async for chunk in body.chunks(chunk_size)]


async def test_크기와_해시는_원본_바이트_기준이다():
    data = os.urandom(1000)
    body = MemoryBody(data)

    assert body.size == 1000
    assert await body.sha256() == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("size", [0, 1, 64, 65, 200])
async def test_청크를_이어_붙이면_원본이다(size):
    data = os.urandom(size)

    chunks = await collect(MemoryBody(data), 64)

    assert b"".join(chunks) == data
    assert all(0 < len(c) <= 64 for c in chunks)


def test_본문이_없으면_None이다():
    flow = tflow.tflow(resp=True)
    flow.response.raw_content = b""
    assert held_body_of(flow) is None

    flow.response.raw_content = None
    assert held_body_of(flow) is None


async def test_Content_Encoding을_풀지_않는다():
    compressed = gzip.compress(b"hello" * 100)
    flow = tflow.tflow(resp=True)
    flow.response.headers["content-encoding"] = "gzip"
    flow.response.raw_content = compressed

    body = held_body_of(flow)

    assert body is not None
    assert body.size == len(compressed)
    assert b"".join(await collect(body, 64)) == compressed
