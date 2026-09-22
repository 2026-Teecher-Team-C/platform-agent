from pathlib import Path

from agent.platform.base import create_spool_dir, create_spool_file

__all__ = ["create_spool_file", "prepare_spool_dir"]

# 이 파일이 있는 디렉터리는 Spotlight가 색인하지 않는다.
SPOTLIGHT_EXCLUSION_MARKER = ".metadata_never_index"


def prepare_spool_dir(path: Path) -> Path:
    create_spool_dir(path)
    (path / SPOTLIGHT_EXCLUSION_MARKER).touch(mode=0o600, exist_ok=True)
    return path
