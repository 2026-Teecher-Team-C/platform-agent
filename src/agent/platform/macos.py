import logging
import os
import plistlib
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from agent.platform.base import (
    PROXY_HOST,
    PROXY_PORT,
    AppDirs,
    create_spool_dir,
    create_spool_file,
    install_shutdown_handler,
)

if TYPE_CHECKING:
    from agent.ca import CaFiles

__all__ = [
    "agent_run_command",
    "app_dirs",
    "create_spool_file",
    "hardware_uuid",
    "install_shutdown_handler",
    "os_integration",
    "prepare_spool_dir",
]

logger = logging.getLogger(__name__)

Run = Callable[[list[str]], str]

NETWORKSETUP = "/usr/sbin/networksetup"
SECURITY = "/usr/bin/security"
LAUNCHCTL = "/bin/launchctl"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
LAUNCH_AGENT_LABEL = "kr.teecher.agent"
# macOS 예외 목록은 <local>을 모른다. 도메인 패턴으로 쓴다
MAC_PROXY_BYPASS = ("localhost", "127.0.0.1", "*.local")

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


def run_command(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60).stdout


def parse_network_services(output: str) -> list[str]:
    # 첫 줄은 "An asterisk (*) denotes that a network service is disabled." 안내 문구다
    services = []
    for line in output.splitlines()[1:]:
        name = line.strip()
        if name and not name.startswith("*"):
            services.append(name)
    return services


def parse_proxy(output: str) -> tuple[bool, str, int]:
    fields = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
    try:
        port = int(fields.get("Port", "0"))
    except ValueError:
        port = 0
    return fields.get("Enabled") == "Yes", fields.get("Server", "").strip(), port


def launch_agent_plist(command: list[str], logs: Path) -> bytes:
    return plistlib.dumps(
        {
            "Label": LAUNCH_AGENT_LABEL,
            "ProgramArguments": command,
            "RunAtLoad": True,
            # 프록시가 켜진 채 에이전트가 죽으면 모든 웹이 끊긴다 — 바로 다시 띄운다(스펙 3.2)
            "KeepAlive": True,
            "StandardErrorPath": str(logs / "launchd.err.log"),
        }
    )


class MacIntegration:
    def __init__(self, dirs: AppDirs, home: Path, uid: int, run: Run = run_command) -> None:
        self._dirs = dirs
        self._uid = uid
        self._run = run
        self.plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"

    def ca_trusted(self, ca: "CaFiles") -> bool:
        try:
            out = self._run([SECURITY, "find-certificate", "-a", "-Z", "-c", "mitmproxy", SYSTEM_KEYCHAIN])
        except subprocess.CalledProcessError:
            return False  # 이름이 맞는 인증서가 하나도 없으면 실패한다
        return f"SHA-1 hash: {ca.sha1}" in out

    def trust_ca(self, ca: "CaFiles") -> None:
        self._run([SECURITY, "add-trusted-cert", "-d", "-r", "trustRoot", "-k", SYSTEM_KEYCHAIN, str(ca.cert_pem)])

    def untrust_ca(self, ca: "CaFiles") -> None:
        if not self.ca_trusted(ca):
            return
        self._run([SECURITY, "remove-trusted-cert", "-d", str(ca.cert_pem)])
        # 같은 이름의 개발용 mitmproxy CA를 지우지 않도록 핑거프린트로 지운다(스펙 4.1)
        self._run([SECURITY, "delete-certificate", "-Z", ca.sha1, SYSTEM_KEYCHAIN])

    def _services(self) -> list[str]:
        return parse_network_services(self._run([NETWORKSETUP, "-listallnetworkservices"]))

    def _ours(self, getter: str, service: str) -> bool:
        return parse_proxy(self._run([NETWORKSETUP, getter, service])) == (True, PROXY_HOST, PROXY_PORT)

    def proxy_is_ours(self) -> bool:
        services = self._services()
        return bool(services) and all(
            self._ours("-getwebproxy", s) and self._ours("-getsecurewebproxy", s) for s in services
        )

    def _warn_if_foreign_proxy(self, service: str) -> None:
        for getter in ("-getwebproxy", "-getsecurewebproxy"):
            enabled, server, port = parse_proxy(self._run([NETWORKSETUP, getter, service]))
            if enabled and (server, port) != (PROXY_HOST, PROXY_PORT):
                logger.warning("네트워크 서비스 %s에 다른 프록시(%s:%s)가 켜져 있다. 덮어쓴다", service, server, port)

    def enable_proxy(self) -> None:
        for service in self._services():
            self._warn_if_foreign_proxy(service)
            self._run([NETWORKSETUP, "-setwebproxy", service, PROXY_HOST, str(PROXY_PORT)])
            self._run([NETWORKSETUP, "-setsecurewebproxy", service, PROXY_HOST, str(PROXY_PORT)])
            self._run([NETWORKSETUP, "-setproxybypassdomains", service, *MAC_PROXY_BYPASS])

    def disable_proxy_if_ours(self) -> None:
        # 설치 뒤 사용자가 바꾼 값은 건드리지 않는다(스펙 4장 1단계)
        for service in self._services():
            if self._ours("-getwebproxy", service):
                self._run([NETWORKSETUP, "-setwebproxystate", service, "off"])
            if self._ours("-getsecurewebproxy", service):
                self._run([NETWORKSETUP, "-setsecurewebproxystate", service, "off"])

    def autostart_installed(self) -> bool:
        return self.plist_path.is_file()

    def _bootout(self) -> None:
        try:
            self._run([LAUNCHCTL, "bootout", f"gui/{self._uid}/{LAUNCH_AGENT_LABEL}"])
        except subprocess.CalledProcessError:
            pass  # 떠 있지 않다

    def install_autostart(self, command: list[str]) -> None:
        self.plist_path.parent.mkdir(parents=True, exist_ok=True)
        self._dirs.logs.mkdir(parents=True, exist_ok=True)
        self._bootout()
        self.plist_path.write_bytes(launch_agent_plist(command, self._dirs.logs))
        # RunAtLoad라 bootstrap하면 바로 뜬다
        self._run([LAUNCHCTL, "bootstrap", f"gui/{self._uid}", str(self.plist_path)])

    def remove_autostart(self) -> None:
        self._bootout()
        self.plist_path.unlink(missing_ok=True)


def os_integration(dirs: AppDirs, home: Path) -> MacIntegration:
    return MacIntegration(dirs, home, os.getuid())


def agent_run_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "run"]
    return [sys.executable, "-m", "agent", "run"]
