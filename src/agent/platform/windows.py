import asyncio
import ctypes
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from agent.platform import base
from agent.platform.base import AppDirs, SpoolFile, create_spool_dir

__all__ = ["app_dirs", "create_spool_file", "hardware_uuid", "install_shutdown_handler", "prepare_spool_dir"]


def hardware_uuid() -> str:
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except Exception:
        return ""
    return result.stdout.strip()


# Windows Search가 내용을 색인하지 않는다. 디렉터리에 걸면 새로 만드는 파일이 상속한다.
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000


def _add_attribute(path: Path, attribute: int) -> None:
    kernel32 = ctypes.windll.kernel32
    current = kernel32.GetFileAttributesW(str(path))
    if current == -1 or current == 0xFFFFFFFF:
        raise ctypes.WinError()
    if not kernel32.SetFileAttributesW(str(path), current | attribute):
        raise ctypes.WinError()


def prepare_spool_dir(path: Path) -> Path:
    create_spool_dir(path)
    _add_attribute(path, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    return path


def create_spool_file(spool_dir: Path) -> SpoolFile:
    spool_file = base.create_spool_file(spool_dir)
    # 상속에 기대지 않고 파일에도 직접 건다.
    _add_attribute(spool_file.path, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    return spool_file


def app_dirs(home: Path) -> AppDirs:
    # 기본 홈이면 폴더 리디렉션을 따라 LOCALAPPDATA를 쓴다. 다른 홈을 주면 그 아래 표준 위치다
    if home == Path.home() and os.environ.get("LOCALAPPDATA"):
        local = Path(os.environ["LOCALAPPDATA"])
    else:
        local = home / "AppData" / "Local"
    data = local / "Teecher"
    return AppDirs(data=data, logs=data / "logs")


def install_shutdown_handler(loop: asyncio.AbstractEventLoop, callback: Callable[[], None]) -> None:
    # Windows 이벤트 루프는 add_signal_handler가 없다. 작업 스케줄러의 /End는 프로세스를 바로 끝낸다
    return None
