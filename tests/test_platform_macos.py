import logging
import plistlib
import subprocess
from pathlib import Path

from agent.ca import CaFiles
from agent.platform import AppDirs
from agent.platform.macos import (
    LAUNCH_AGENT_LABEL,
    SYSTEM_KEYCHAIN,
    MacIntegration,
    launch_agent_plist,
    parse_network_services,
    parse_proxy,
)

SERVICES = (
    "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB 10/100/1000 LAN\n*Thunderbolt Bridge\n"
)
OURS = "Enabled: Yes\nServer: 127.0.0.1\nPort: 18080\nAuthenticated Proxy Enabled: 0\n"
OTHER = "Enabled: Yes\nServer: corp-proxy\nPort: 3128\nAuthenticated Proxy Enabled: 0\n"
OFF = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n"
CA = CaFiles(Path("/x/mitmproxy-ca-cert.pem"), Path("/x/mitmproxy-ca-cert.cer"), "AB" * 20, "CD" * 32)


class FakeRun:
    def __init__(self, outputs: dict[tuple[str, ...], str] | None = None, fail: set[tuple[str, ...]] | None = None):
        self.outputs = outputs or {}
        self.fail = fail or set()
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> str:
        self.commands.append(cmd)
        key = tuple(cmd)
        if key in self.fail:
            raise subprocess.CalledProcessError(1, cmd)
        return self.outputs.get(key, "")


def mac(tmp_path, run) -> MacIntegration:
    return MacIntegration(AppDirs(tmp_path / "data", tmp_path / "logs"), tmp_path, 501, run=run)


def test_활성_네트워크_서비스만_공백_포함_이름_그대로_고른다():
    # Review Focus 5
    assert parse_network_services(SERVICES) == ["Wi-Fi", "USB 10/100/1000 LAN"]


def test_프록시_출력을_읽는다():
    assert parse_proxy(OURS) == (True, "127.0.0.1", 18080)
    assert parse_proxy(OFF) == (False, "", 0)


def test_모든_활성_서비스에_HTTP_HTTPS_프록시와_예외를_건다(tmp_path):
    run = FakeRun({("/usr/sbin/networksetup", "-listallnetworkservices"): SERVICES})

    mac(tmp_path, run).enable_proxy()

    assert ["/usr/sbin/networksetup", "-setwebproxy", "USB 10/100/1000 LAN", "127.0.0.1", "18080"] in run.commands
    assert ["/usr/sbin/networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "18080"] in run.commands
    assert [
        "/usr/sbin/networksetup",
        "-setproxybypassdomains",
        "Wi-Fi",
        "localhost",
        "127.0.0.1",
        "*.local",
    ] in run.commands
    assert not any("*Thunderbolt Bridge" in c or "Thunderbolt Bridge" in c for c in map(" ".join, run.commands))


def test_우리_프록시일_때만_끈다(tmp_path):
    # Review Focus 4 — Wi-Fi는 사용자가 다른 프록시로 바꿨다
    ns = "/usr/sbin/networksetup"
    run = FakeRun(
        {
            (ns, "-listallnetworkservices"): SERVICES,
            (ns, "-getwebproxy", "Wi-Fi"): OTHER,
            (ns, "-getsecurewebproxy", "Wi-Fi"): OTHER,
            (ns, "-getwebproxy", "USB 10/100/1000 LAN"): OURS,
            (ns, "-getsecurewebproxy", "USB 10/100/1000 LAN"): OURS,
        }
    )

    mac(tmp_path, run).disable_proxy_if_ours()

    assert [ns, "-setwebproxystate", "USB 10/100/1000 LAN", "off"] in run.commands
    assert [ns, "-setsecurewebproxystate", "USB 10/100/1000 LAN", "off"] in run.commands
    assert not any(
        c[1:3] in (["-setwebproxystate", "Wi-Fi"], ["-setsecurewebproxystate", "Wi-Fi"]) for c in run.commands
    )


def test_모든_활성_서비스가_우리_프록시여야_켜진_것으로_본다(tmp_path):
    ns = "/usr/sbin/networksetup"
    outputs = {(ns, "-listallnetworkservices"): SERVICES}
    for svc in ("Wi-Fi", "USB 10/100/1000 LAN"):
        outputs[(ns, "-getwebproxy", svc)] = OURS
        outputs[(ns, "-getsecurewebproxy", svc)] = OURS
    assert mac(tmp_path, FakeRun(outputs)).proxy_is_ours()

    outputs[(ns, "-getsecurewebproxy", "Wi-Fi")] = OFF
    assert not mac(tmp_path, FakeRun(outputs)).proxy_is_ours()


def test_CA를_System_키체인에_신뢰_루트로_넣는다(tmp_path):
    run = FakeRun()

    mac(tmp_path, run).trust_ca(CA)

    assert run.commands == [
        ["/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", SYSTEM_KEYCHAIN, str(CA.cert_pem)]
    ]


def test_CA_신뢰_여부는_SHA1_핑거프린트로_찾는다(tmp_path):
    find = ("/usr/bin/security", "find-certificate", "-a", "-Z", "-c", "mitmproxy", SYSTEM_KEYCHAIN)

    assert mac(tmp_path, FakeRun({find: f"SHA-256 hash: X\nSHA-1 hash: {CA.sha1}\n"})).ca_trusted(CA)
    assert not mac(tmp_path, FakeRun({find: "SHA-1 hash: 0000\n"})).ca_trusted(CA)
    assert not mac(tmp_path, FakeRun(fail={find})).ca_trusted(CA)


def test_CA_신뢰_해제는_신뢰_설정을_지우고_핑거프린트로_삭제한다(tmp_path):
    find = ("/usr/bin/security", "find-certificate", "-a", "-Z", "-c", "mitmproxy", SYSTEM_KEYCHAIN)
    run = FakeRun({find: f"SHA-1 hash: {CA.sha1}\n"})

    mac(tmp_path, run).untrust_ca(CA)

    assert run.commands[1:] == [
        ["/usr/bin/security", "remove-trusted-cert", "-d", str(CA.cert_pem)],
        ["/usr/bin/security", "delete-certificate", "-Z", CA.sha1, SYSTEM_KEYCHAIN],
    ]


def test_LaunchAgent는_로그인_시_실행하고_죽으면_다시_띄운다(tmp_path):
    plist = plistlib.loads(launch_agent_plist(["/Applications/Teecher Agent/teecher-agent", "run"], tmp_path))

    assert plist["Label"] == LAUNCH_AGENT_LABEL
    assert plist["ProgramArguments"] == ["/Applications/Teecher Agent/teecher-agent", "run"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is True


def test_자동_실행_등록은_이전_것을_내리고_plist를_쓴_뒤_bootstrap한다(tmp_path):
    bootout = ("/bin/launchctl", "bootout", f"gui/501/{LAUNCH_AGENT_LABEL}")
    run = FakeRun(fail={bootout})  # 떠 있지 않으면 bootout은 실패한다 — 무시해야 한다
    integration = mac(tmp_path, run)

    integration.install_autostart(["teecher-agent", "run"])

    plist_path = tmp_path / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    assert integration.autostart_installed()
    assert run.commands == [list(bootout), ["/bin/launchctl", "bootstrap", "gui/501", str(plist_path)]]


def test_자동_실행_해제는_내리고_plist를_지운다(tmp_path):
    run = FakeRun()
    integration = mac(tmp_path, run)
    integration.install_autostart(["teecher-agent", "run"])
    run.commands.clear()

    integration.remove_autostart()

    assert not integration.autostart_installed()
    assert run.commands == [["/bin/launchctl", "bootout", f"gui/501/{LAUNCH_AGENT_LABEL}"]]


def test_다른_프록시가_켜져_있으면_경고하고_덮어쓴다(tmp_path, caplog):
    ns = "/usr/sbin/networksetup"
    run = FakeRun(
        {
            (ns, "-listallnetworkservices"): SERVICES,
            (ns, "-getwebproxy", "Wi-Fi"): OTHER,
        }
    )

    with caplog.at_level(logging.WARNING, logger="agent.platform.macos"):
        mac(tmp_path, run).enable_proxy()

    assert any("Wi-Fi" in r.getMessage() and "corp-proxy:3128" in r.getMessage() for r in caplog.records)
    assert [ns, "-setwebproxy", "Wi-Fi", "127.0.0.1", "18080"] in run.commands
    assert [ns, "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "18080"] in run.commands
