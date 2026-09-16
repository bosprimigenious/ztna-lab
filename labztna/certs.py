"""Ephemeral CA and localhost server certificates for the lab."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class TLSBundle:
    ca_cert: Path
    control_cert: Path
    control_key: Path
    gateway_cert: Path
    gateway_key: Path


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _issue_server_certificate(
    *, ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey, common_name: str, now: datetime
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def create_ephemeral_bundle(directory: str | Path) -> TLSBundle:
    """Create a CA and localhost server certificate in *directory*.

    The key is intentionally unencrypted because this bundle exists only for
    the lifetime of a local demo. Production deployments must use a real PKI.
    """

    target = Path(directory)
    if target.exists() and any(target.iterdir()):
        raise ValueError("certificate directory must be new or empty")
    target.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZTNA Lab Ephemeral CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    control_key, control_cert = _issue_server_certificate(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name="ZTNA Lab Control",
        now=now,
    )
    gateway_key, gateway_cert = _issue_server_certificate(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name="ZTNA Lab Gateway",
        now=now,
    )

    ca_cert_path = target / "ca.crt"
    control_cert_path = target / "control.crt"
    control_key_path = target / "control.key"
    gateway_cert_path = target / "gateway.crt"
    gateway_key_path = target / "gateway.key"
    _write_cert(ca_cert_path, ca_cert)
    _write_cert(control_cert_path, control_cert)
    _write_key(control_key_path, control_key)
    _write_cert(gateway_cert_path, gateway_cert)
    _write_key(gateway_key_path, gateway_key)
    return TLSBundle(
        ca_cert_path,
        control_cert_path,
        control_key_path,
        gateway_cert_path,
        gateway_key_path,
    )
