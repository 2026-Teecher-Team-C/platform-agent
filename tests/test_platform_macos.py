import logging
import plistlib
import subprocess
from pathlib import Path

import pytest

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


class FakeKeychain:
    """System 키체인과 관리자 신뢰 설정을 흉내 낸다. trust-settings-export는 파일에 plist를 쓴다."""

    def __init__(self, present: bool, trusted: bool, fail: set[str] | None = None):
        self.present = present
        self.trusted = trusted
        self.fail = fail or set()
        self.commands: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> str:
        self.commands.append(cmd)
        verb = cmd[1]
        if verb in self.fail:
            raise subprocess.CalledProcessError(1, cmd)
        if verb == "find-certificate":
            if not self.present:
                raise subprocess.CalledProcessError(44, cmd)
            return f"SHA-256 hash: X\nSHA-1 hash: {CA.sha1}\n"
        if verb == "trust-settings-export":
            trust_list = {CA.sha1: {}} if self.trusted else {}
            if not trust_list:
                raise subprocess.CalledProcessError(1, cmd)  # 관리자 신뢰 설정이 하나도 없으면 실패한다
            Path(cmd[-1]).write_bytes(plistlib.dumps({"trustList": trust_list, "trustVersion": 1}))
        elif verb == "remove-trusted-cert":
            self.trusted = False
        elif verb == "delete-certificate":
            self.present = False
        return ""


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


def test_한_서비스라도_우리_프록시면_가리키는_것으로_본다(tmp_path):
    # 설치 뒤 추가된 USB 서비스는 우리 것이 아니다 — proxy_is_ours는 False, proxy_points_to_us는 True
    ns = "/usr/sbin/networksetup"
    outputs = {(ns, "-listallnetworkservices"): SERVICES}
    for getter in ("-getwebproxy", "-getsecurewebproxy"):
        outputs[(ns, getter, "Wi-Fi")] = OURS
        outputs[(ns, getter, "USB 10/100/1000 LAN")] = OFF
    integration = mac(tmp_path, FakeRun(outputs))
    assert not integration.proxy_is_ours()
    assert integration.proxy_points_to_us()

    # 보안 웹 프록시만 남아도 가리키는 것이다
    outputs[(ns, "-getwebproxy", "Wi-Fi")] = OFF
    assert mac(tmp_path, FakeRun(outputs)).proxy_points_to_us()


def test_우리_프록시가_하나도_없으면_가리키지_않는다(tmp_path):
    ns = "/usr/sbin/networksetup"
    outputs = {(ns, "-listallnetworkservices"): SERVICES}
    for svc in ("Wi-Fi", "USB 10/100/1000 LAN"):
        outputs[(ns, "-getwebproxy", svc)] = OTHER
        outputs[(ns, "-getsecurewebproxy", svc)] = OFF
    assert not mac(tmp_path, FakeRun(outputs)).proxy_points_to_us()


def test_CA를_System_키체인에_신뢰_루트로_넣는다(tmp_path):
    run = FakeRun()

    mac(tmp_path, run).trust_ca(CA)

    assert run.commands == [
        ["/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", SYSTEM_KEYCHAIN, str(CA.cert_pem)]
    ]


@pytest.mark.parametrize(
    ("present", "trusted", "expected"),
    [(True, True, True), (True, False, False), (False, False, False)],
)
def test_CA_신뢰_여부는_관리자_신뢰_설정의_SHA1로_본다(tmp_path, present, trusted, expected):
    # 인증서가 키체인에 있어도 신뢰 설정이 없으면 HTTPS가 깨진다 — 재설치가 trust를 건너뛰면 안 된다
    run = FakeKeychain(present, trusted)

    assert mac(tmp_path, run).ca_trusted(CA) is expected


def test_신뢰_설정을_내보낼_때_관리자_설정을_임시_파일로_받는다(tmp_path):
    run = FakeKeychain(present=True, trusted=True)

    mac(tmp_path, run).ca_trusted(CA)

    export = next(c for c in run.commands if c[1] == "trust-settings-export")
    assert export[:3] == ["/usr/bin/security", "trust-settings-export", "-d"]
    assert not Path(export[3]).exists()  # 다 읽은 뒤 지운다


def test_CA_신뢰_해제는_신뢰_설정을_지우고_핑거프린트로_삭제한다(tmp_path):
    run = FakeKeychain(present=True, trusted=True)

    mac(tmp_path, run).untrust_ca(CA)

    assert ["/usr/bin/security", "remove-trusted-cert", "-d", str(CA.cert_pem)] in run.commands
    assert ["/usr/bin/security", "delete-certificate", "-Z", CA.sha1, SYSTEM_KEYCHAIN] in run.commands
    assert not run.present


def test_신뢰_설정_삭제가_실패해도_인증서는_핑거프린트로_지운다(tmp_path):
    run = FakeKeychain(present=True, trusted=True, fail={"remove-trusted-cert"})

    mac(tmp_path, run).untrust_ca(CA)

    assert ["/usr/bin/security", "delete-certificate", "-Z", CA.sha1, SYSTEM_KEYCHAIN] in run.commands
    assert not run.present


def test_신뢰_설정만_없어도_키체인에_남은_인증서를_지운다(tmp_path):
    run = FakeKeychain(present=True, trusted=False)

    mac(tmp_path, run).untrust_ca(CA)

    assert not run.present


def test_인증서가_남으면_신뢰_해제는_실패한다(tmp_path):
    run = FakeKeychain(present=True, trusted=True, fail={"delete-certificate"})

    with pytest.raises(RuntimeError, match=CA.sha1):
        mac(tmp_path, run).untrust_ca(CA)


def test_키체인에_없는_CA는_지우지_않는다(tmp_path):
    run = FakeKeychain(present=False, trusted=False)

    mac(tmp_path, run).untrust_ca(CA)

    assert [c[1] for c in run.commands] == ["find-certificate"]


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
