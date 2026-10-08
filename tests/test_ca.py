import hashlib
import stat
import sys

import pytest

from agent.ca import ensure_ca, load_ca

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX 권한 비트")


def test_CA가_없으면_None이다(tmp_path):
    assert load_ca(tmp_path / "ca") is None


def test_CA를_만들고_핑거프린트를_DER에서_계산한_값과_같게_낸다(tmp_path):
    ca = ensure_ca(tmp_path / "ca")

    der = ca.cert_der.read_bytes()
    assert ca.sha1 == hashlib.sha1(der).hexdigest().upper()
    assert ca.sha256 == hashlib.sha256(der).hexdigest().upper()
    assert ca.cert_pem.name == "mitmproxy-ca-cert.pem"
    assert (tmp_path / "ca" / "mitmproxy-ca.pem").is_file()  # mitmproxy가 confdir에서 찾는 키+인증서


def test_두_번_불러도_같은_CA를_쓴다(tmp_path):
    first = ensure_ca(tmp_path / "ca")
    second = ensure_ca(tmp_path / "ca")

    assert first == second


@posix_only
def test_CA_폴더는_0700_개인_키는_0600이다(tmp_path):
    ensure_ca(tmp_path / "ca")

    assert stat.S_IMODE((tmp_path / "ca").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "ca" / "mitmproxy-ca.pem").stat().st_mode) == 0o600
