"""Network boundary checks for the disposable lab.

Every listener and every outbound hop is deliberately limited to an IPv4
loopback literal.  The lab must never become a generic proxy by accident.
"""

from __future__ import annotations

import ipaddress


def require_loopback(host: str) -> str:
    """Return *host* if it is exactly an IPv4 loopback literal.

    Hostnames are rejected to avoid DNS rebinding and ambiguous IPv4/IPv6
    resolution.  The lab uses ``127.0.0.1`` everywhere on purpose.
    """

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("lab endpoints must use the 127.0.0.1 literal") from exc
    if not (address.version == 4 and address.is_loopback and host == "127.0.0.1"):
        raise ValueError("lab endpoints must be 127.0.0.1")
    return host

