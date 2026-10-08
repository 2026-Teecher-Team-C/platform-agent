import asyncio
import ctypes
import logging
import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from agent.platform import base
from agent.platform.base import PROXY_HOST, PROXY_PORT, AppDirs, SpoolFile, create_spool_dir

if TYPE_CHECKING:
    from agent.ca import CaFiles

__all__ = ["app_dirs", "create_spool_file", "hardware_uuid", "install_shutdown_handler", "prepare_spool_dir"]

logger = logging.getLogger(__name__)

Run = Callable[[list[str]], str]

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
TASK_NAME = "TeecherAgent"
PROXY_SERVER = f"{PROXY_HOST}:{PROXY_PORT}"
PROXY_OVERRIDE = "localhost;127.0.0.1;<local>"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


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


def run_command(cmd: list[str]) -> str:
    return subprocess.run(
        cmd, capture_output=True, text=True, check=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW
    ).stdout


def notify_proxy_change() -> None:
    # 브라우저를 다시 켜지 않아도 새 프록시 설정을 읽게 한다
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def task_xml(command: list[str], user: str) -> str:
    exe, *args = command
    # RestartOnFailure는 시작 실패에만 걸린다. 떠 있던 에이전트가 죽으면 1분 반복 트리거가 다시 띄우고,
    # 이미 떠 있으면 IgnoreNew가 두 번째 실행을 막는다
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{escape(user)}</UserId>
      <Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(exe)}</Command>
      <Arguments>{escape(subprocess.list2cmdline(args))}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _current_user() -> str:
    return f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"


class WindowsIntegration:
    def __init__(
        self,
        run: Run = run_command,
        settings_key: str = INTERNET_SETTINGS,
        task_name: str = TASK_NAME,
        user: str | None = None,
        notify: Callable[[], None] = notify_proxy_change,
    ) -> None:
        self._run = run
        self._settings_key = settings_key
        self._task = task_name
        self._user = user or _current_user()
        self._notify = notify

    def ca_trusted(self, ca: "CaFiles") -> bool:
        try:
            self._run(["certutil", "-store", "Root", ca.sha1])
        except subprocess.CalledProcessError:
            return False
        return True

    def trust_ca(self, ca: "CaFiles") -> None:
        self._run(["certutil", "-addstore", "-f", "Root", str(ca.cert_der)])

    def untrust_ca(self, ca: "CaFiles") -> None:
        if self.ca_trusted(ca):
            # 같은 이름의 개발용 mitmproxy CA를 지우지 않도록 썸프린트로 지운다(스펙 4.1)
            self._run(["certutil", "-delstore", "Root", ca.sha1])

    def _read_proxy(self) -> tuple[int, str]:
        import winreg

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._settings_key)
        except FileNotFoundError:
            return 0, ""
        with key:
            # 값이 하나라도 없으면 QueryValueEx가 FileNotFoundError를 낸다. 값마다 따로 읽는다
            try:
                enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                enable = 0
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
        return enable, server

    def proxy_is_ours(self) -> bool:
        return self._read_proxy() == (1, PROXY_SERVER)

    def enable_proxy(self) -> None:
        import winreg

        enable, server = self._read_proxy()
        if enable == 1 and server != PROXY_SERVER:
            logger.warning("다른 프록시(%s)가 켜져 있다. 덮어쓴다", server)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self._settings_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, PROXY_SERVER)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, PROXY_OVERRIDE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        self._notify()

    def disable_proxy_if_ours(self) -> None:
        import winreg

        if not self.proxy_is_ours():
            return  # 설치 뒤 사용자가 바꾼 값은 건드리지 않는다
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._settings_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        self._notify()

    def autostart_installed(self) -> bool:
        try:
            self._run(["schtasks", "/Query", "/TN", self._task])
        except subprocess.CalledProcessError:
            return False
        return True

    def install_autostart(self, command: list[str]) -> None:
        fd, path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-16") as f:
                f.write(task_xml(command, self._user))
            self._run(["schtasks", "/Create", "/F", "/TN", self._task, "/XML", path])
        finally:
            os.unlink(path)
        self._run(["schtasks", "/Run", "/TN", self._task])

    def remove_autostart(self) -> None:
        if not self.autostart_installed():
            return
        try:
            self._run(["schtasks", "/End", "/TN", self._task])
        except subprocess.CalledProcessError:
            pass  # 실행 중이 아니다
        self._run(["schtasks", "/Delete", "/F", "/TN", self._task])
