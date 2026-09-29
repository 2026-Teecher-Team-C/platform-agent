from pathlib import Path

from agent.platform.base import create_spool_dir, create_spool_file

__all__ = ["create_spool_file", "hardware_uuid", "prepare_spool_dir"]


def hardware_uuid() -> str:
    # 보통 root만 읽을 수 있다. 못 읽으면 빈 문자열.
    try:
        return Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    except OSError:
        return ""


def prepare_spool_dir(path: Path) -> Path:
    # 리눅스 데스크톱에는 표준 인덱싱 제외 장치가 없다. 권한(0700/0600)과 .tmp 이름으로 막는다.
    return create_spool_dir(path)
