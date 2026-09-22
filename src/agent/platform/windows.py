import ctypes
from pathlib import Path

from agent.platform import base
from agent.platform.base import SpoolFile, create_spool_dir

__all__ = ["create_spool_file", "prepare_spool_dir"]

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
