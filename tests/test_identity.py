import tomllib
from pathlib import Path

import agent
from agent.identity import current_identity, os_platform_of
from agent.platform.macos import parse_ioreg
from teecher.agent.v1 import agent_pb2

IOREG_SAMPLE = """
+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000240, registered, matched, active, busy 0 (0 ms), retain 34>
    {
      "IOPlatformSerialNumber" = "ABCDEF123"
      "IOPlatformUUID" = "0A1B2C3D-1111-2222-3333-444455556666"
    }
"""


def test_ioreg_출력에서_IOPlatformUUID를_꺼낸다():
    assert parse_ioreg(IOREG_SAMPLE) == "0A1B2C3D-1111-2222-3333-444455556666"
    assert parse_ioreg("no uuid here") == ""


def test_OS_이름을_proto_값으로_바꾼다():
    assert os_platform_of("darwin") == agent_pb2.OS_PLATFORM_MACOS
    assert os_platform_of("win32") == agent_pb2.OS_PLATFORM_WINDOWS
    assert os_platform_of("linux") == agent_pb2.OS_PLATFORM_LINUX
    assert os_platform_of("freebsd14") == agent_pb2.OS_PLATFORM_UNSPECIFIED


def test_버전은_pyproject와_같다():
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())

    assert agent.__version__ == pyproject["project"]["version"]


def test_현재_호스트_정보는_예외_없이_채워진다():
    identity = current_identity()

    assert identity.hostname
    assert identity.agent_version == agent.__version__
    assert isinstance(identity.hardware_uuid, str)  # 얻지 못하면 "" — 서버는 재설치 매칭 후보로만 쓴다
