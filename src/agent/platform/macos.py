import re
import subprocess
from pathlib import Path

from agent.platform.base import AppDirs, create_spool_dir, create_spool_file, install_shutdown_handler

__all__ = ["app_dirs", "create_spool_file", "hardware_uuid", "install_shutdown_handler", "prepare_spool_dir"]

_IOREG_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')


def parse_ioreg(output: str) -> str:
    match = _IOREG_UUID.search(output)
    return match.group(1) if match else ""


def hardware_uuid() -> str:
    # 위조 가능한 값이라 서버는 식별 근거가 아닌 재설치 매칭 후보로만 쓴다. 못 얻으면 빈 문자열.
    try:
        result = subprocess.run(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except Exception:
        return ""
    return parse_ioreg(result.stdout)


# 이 파일이 있는 디렉터리는 Spotlight가 색인하지 않는다.
SPOTLIGHT_EXCLUSION_MARKER = ".metadata_never_index"


def prepare_spool_dir(path: Path) -> Path:
    create_spool_dir(path)
    (path / SPOTLIGHT_EXCLUSION_MARKER).touch(mode=0o600, exist_ok=True)
    return path


def app_dirs(home: Path) -> AppDirs:
    return AppDirs(
        data=home / "Library" / "Application Support" / "Teecher",
        logs=home / "Library" / "Logs" / "Teecher",
    )
