import asyncio
import logging

import pytest
from fakes.verdict_server import create_server

from agent.runner import build_master, setup_logging


@pytest.fixture
async def fake_server(monkeypatch):
    fake, port, servicer = await create_server()
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
    monkeypatch.delenv("AGENT_TOKEN", raising=False)
    yield servicer
    await fake.stop(None)


async def test_전용_CA_폴더로_127_0_0_1에서_보류_파이프라인을_띄운다(fake_server, tmp_path):
    master, pipeline = build_master(tmp_path / "ca", port=0)
    run = asyncio.create_task(master.run())
    proxyserver = master.addons.get("proxyserver")
    for _ in range(200):
        if proxyserver.listen_addrs() and pipeline.client is not None:
            break
        await asyncio.sleep(0.01)

    host, port = proxyserver.listen_addrs()[0][:2]
    assert host == "127.0.0.1" and port > 0
    assert (tmp_path / "ca" / "mitmproxy-ca.pem").is_file()

    master.shutdown()
    await asyncio.wait_for(run, 10)


def test_로그를_파일에_남긴다(tmp_path):
    handler = setup_logging(tmp_path / "logs")
    try:
        logging.getLogger("agent.test").info("기동 확인")
        handler.flush()

        assert "기동 확인" in (tmp_path / "logs" / "agent.log").read_text(encoding="utf-8")
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
