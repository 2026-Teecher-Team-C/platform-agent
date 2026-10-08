import logging
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from agent.ca import CaFiles
from agent.platform.windows import PROXY_OVERRIDE, PROXY_SERVER, TASK_NAME, WindowsIntegration, task_xml

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
CA = CaFiles(Path(r"C:\x\mitmproxy-ca-cert.pem"), Path(r"C:\x\mitmproxy-ca-cert.cer"), "AB" * 20, "CD" * 32)
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="레지스트리")


class FakeRun:
    def __init__(self, fail: set[tuple[str, ...]] | None = None):
        self.fail = fail or set()
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> str:
        self.commands.append(cmd)
        if tuple(cmd) in self.fail:
            raise subprocess.CalledProcessError(1, cmd)
        return ""


def win(run, **kwargs) -> WindowsIntegration:
    return WindowsIntegration(run=run, user=r"PC\hang", notify=lambda: None, **kwargs)


def test_작업은_로그온에_시작하고_1분마다_꺼져_있으면_다시_띄운다():
    root = ET.fromstring(task_xml([r"C:\Program Files\Teecher Agent\teecher-agentw.exe", "run"], r"PC\hang"))

    trigger = root.find("t:Triggers/t:LogonTrigger", NS)
    assert trigger.find("t:UserId", NS).text == r"PC\hang"
    assert trigger.find("t:Repetition/t:Interval", NS).text == "PT1M"
    assert root.find("t:Settings/t:MultipleInstancesPolicy", NS).text == "IgnoreNew"
    assert root.find("t:Settings/t:ExecutionTimeLimit", NS).text == "PT0S"
    assert root.find("t:Principals/t:Principal/t:RunLevel", NS).text == "LeastPrivilege"
    exec_ = root.find("t:Actions/t:Exec", NS)
    assert exec_.find("t:Command", NS).text == r"C:\Program Files\Teecher Agent\teecher-agentw.exe"
    assert exec_.find("t:Arguments", NS).text == "run"


def test_작업_XML은_경로의_특수문자를_이스케이프한다():
    xml = task_xml([r"C:\A & B\teecher-agentw.exe", "run"], r"PC\a<b")

    root = ET.fromstring(xml)  # 이스케이프가 깨지면 여기서 파싱 오류
    assert root.find("t:Actions/t:Exec/t:Command", NS).text == r"C:\A & B\teecher-agentw.exe"


def test_CA는_LocalMachine_Root에_넣고_핑거프린트로_찾고_지운다():
    run = FakeRun()
    integration = win(run)

    integration.trust_ca(CA)
    assert integration.ca_trusted(CA)
    integration.untrust_ca(CA)

    assert run.commands == [
        ["certutil", "-addstore", "-f", "Root", str(CA.cert_der)],
        ["certutil", "-store", "Root", CA.sha1],
        ["certutil", "-store", "Root", CA.sha1],
        ["certutil", "-delstore", "Root", CA.sha1],
    ]


def test_신뢰되지_않은_CA는_지우지_않는다():
    run = FakeRun(fail={("certutil", "-store", "Root", CA.sha1)})

    win(run).untrust_ca(CA)

    assert run.commands == [["certutil", "-store", "Root", CA.sha1]]


def test_자동_실행은_XML로_작업을_만들고_바로_실행한다(tmp_path):
    run = FakeRun()

    win(run).install_autostart([r"C:\T\teecher-agentw.exe", "run"])

    create, start = run.commands
    assert create[:5] == ["schtasks", "/Create", "/F", "/TN", TASK_NAME]
    assert create[5] == "/XML"
    assert start == ["schtasks", "/Run", "/TN", TASK_NAME]


def test_자동_실행_해제는_멈추고_지운다():
    run = FakeRun()

    win(run).remove_autostart()

    assert run.commands == [
        ["schtasks", "/Query", "/TN", TASK_NAME],
        ["schtasks", "/End", "/TN", TASK_NAME],
        ["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
    ]


def test_작업이_없으면_해제할_것이_없다():
    run = FakeRun(fail={("schtasks", "/Query", "/TN", TASK_NAME)})

    win(run).remove_autostart()

    assert run.commands == [["schtasks", "/Query", "/TN", TASK_NAME]]


@pytest.fixture
def test_key():
    import winreg

    path = r"Software\TeecherAgentTest\Internet Settings"
    yield path
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\TeecherAgentTest")


@windows_only
def test_레지스트리에_프록시를_켜고_우리_것일_때만_끈다(test_key):
    import winreg

    notified = []
    integration = WindowsIntegration(run=FakeRun(), settings_key=test_key, notify=lambda: notified.append(1))

    integration.enable_proxy()
    assert integration.proxy_is_ours()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key) as key:
        assert winreg.QueryValueEx(key, "ProxyServer")[0] == PROXY_SERVER
        assert winreg.QueryValueEx(key, "ProxyOverride")[0] == PROXY_OVERRIDE

    integration.disable_proxy_if_ours()
    assert not integration.proxy_is_ours()
    assert len(notified) == 2


@windows_only
def test_사용자가_바꾼_프록시는_끄지_않는다(test_key):
    # Review Focus 4
    import winreg

    integration = WindowsIntegration(run=FakeRun(), settings_key=test_key, notify=lambda: None)
    integration.enable_proxy()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "corp-proxy:3128")

    integration.disable_proxy_if_ours()

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key) as key:
        assert winreg.QueryValueEx(key, "ProxyEnable")[0] == 1


@windows_only
def test_다른_프록시가_켜져_있으면_경고하고_덮어쓴다(test_key, caplog):
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "corp-proxy:3128")
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    integration = WindowsIntegration(run=FakeRun(), settings_key=test_key, notify=lambda: None)

    with caplog.at_level(logging.WARNING, logger="agent.platform.windows"):
        integration.enable_proxy()

    assert "corp-proxy:3128" in caplog.text
    assert integration.proxy_is_ours()
