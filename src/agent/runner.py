"""teecher-agent run — mitmproxy를 코드로 띄운다.

설치본(PyInstaller)에는 mitmdump -s 경로가 없다(설계 레포 2026-10-08 스펙 5.1). 개발용
`mitmdump -s src/addon_entry.py`는 그대로 쓸 수 있다.
"""

import asyncio
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from agent.addon import HoldPipeline
from agent.platform import PROXY_HOST, PROXY_PORT, AppDirs, install_shutdown_handler

LOG_MAX_BYTES = 1_000_000
LOG_BACKUPS = 5


def build_master(confdir: Path, port: int = PROXY_PORT) -> tuple[DumpMaster, HoldPipeline]:
    """실행 중인 이벤트 루프 안에서 부른다(DumpMaster가 현재 루프에 묶인다)."""
    master = DumpMaster(options.Options(), with_termlog=False, with_dumper=False)
    pipeline = HoldPipeline()
    master.addons.add(pipeline)
    master.options.update(listen_host=PROXY_HOST, listen_port=port, confdir=str(confdir))
    return master, pipeline


def setup_logging(logs: Path) -> logging.Handler:
    logs.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(logs / "agent.log", maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return handler


async def serve(dirs: AppDirs, port: int = PROXY_PORT) -> None:
    master, _ = build_master(dirs.ca, port)
    install_shutdown_handler(asyncio.get_running_loop(), master.shutdown)
    await master.run()
