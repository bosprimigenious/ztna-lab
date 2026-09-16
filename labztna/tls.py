"""TLS 1.3 contexts used by both sides of the lab."""

from __future__ import annotations

import ssl
from pathlib import Path


def server_context(cert_file: str | Path, key_file: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(str(cert_file), str(key_file))
    return context


def client_context(ca_file: str | Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.check_hostname = True
    return context

