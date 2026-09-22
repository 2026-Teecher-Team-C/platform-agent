import os
import uuid
from dataclasses import dataclass
from pathlib import Path

SPOOL_SUFFIX = ".tmp"


@dataclass(frozen=True)
class SpoolFile:
    path: Path
    fd: int


def create_spool_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir의 mode는 umask 영향을 받으므로 한 번 더 고정한다.
    os.chmod(path, 0o700)
    return path


def create_spool_file(spool_dir: Path) -> SpoolFile:
    """UUID.tmp 이름, 0600(실행 비트 없음)으로 새 파일을 만든다.

    원본 파일명은 공격자가 정한 값이므로 디스크 경로에 절대 쓰지 않는다.
    O_EXCL로 이미 있는 파일(심볼릭 링크 포함)을 열지 않는다.
    """
    path = spool_dir / f"{uuid.uuid4()}{SPOOL_SUFFIX}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    return SpoolFile(path=path, fd=fd)
