"""설치본 전용 mitmproxy CA.

CA 개인 키(mitmproxy-ca.pem)가 새면 이 PC의 HTTPS를 누구나 가로챌 수 있다 — 폴더는 0700, 키는 0600이다.
신뢰 등록·해제는 이름(전부 "mitmproxy")이 아니라 핑거프린트로 한다(설계 레포 2026-10-08 스펙 4.1).
핑거프린트는 이 파일에서 다시 계산하므로 따로 저장하지 않는다.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from mitmproxy.certs import CertStore

CA_BASENAME = "mitmproxy"  # mitmproxy가 confdir에서 이 이름으로 CA를 찾는다
KEY_SIZE = 2048
PRIVATE_FILES = ("mitmproxy-ca.pem", "mitmproxy-ca.p12")


@dataclass(frozen=True)
class CaFiles:
    cert_pem: Path
    cert_der: Path
    sha1: str  # 대문자 16진수, 구분자 없음 — security -Z, certutil이 받는 형식
    sha256: str


def load_ca(confdir: Path) -> CaFiles | None:
    pem = confdir / f"{CA_BASENAME}-ca-cert.pem"
    der = confdir / f"{CA_BASENAME}-ca-cert.cer"
    if not (pem.is_file() and der.is_file()):
        return None
    cert = x509.load_pem_x509_certificate(pem.read_bytes())
    return CaFiles(
        cert_pem=pem,
        cert_der=der,
        sha1=cert.fingerprint(hashes.SHA1()).hex().upper(),
        sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
    )


def ensure_ca(confdir: Path) -> CaFiles:
    confdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir의 mode는 umask 영향을 받으므로 한 번 더 고정한다
    os.chmod(confdir, 0o700)
    if not (confdir / f"{CA_BASENAME}-ca.pem").is_file():
        CertStore.create_store(confdir, CA_BASENAME, KEY_SIZE)
    for name in PRIVATE_FILES:
        path = confdir / name
        if path.exists():
            os.chmod(path, 0o600)
    _write_der(confdir)
    ca = load_ca(confdir)
    if ca is None:
        raise RuntimeError(f"CA 파일을 만들지 못했다: {confdir}")
    return ca


def _write_der(confdir: Path) -> None:
    # mitmproxy 12.2.3의 create_store는 .cer에 PEM을 그대로 쓴다(Android용). 신뢰 등록에는 진짜 DER가 필요하다
    pem = confdir / f"{CA_BASENAME}-ca-cert.pem"
    if not pem.is_file():
        return
    der = x509.load_pem_x509_certificate(pem.read_bytes()).public_bytes(serialization.Encoding.DER)
    path = confdir / f"{CA_BASENAME}-ca-cert.cer"
    if not path.is_file() or path.read_bytes() != der:
        path.write_bytes(der)
