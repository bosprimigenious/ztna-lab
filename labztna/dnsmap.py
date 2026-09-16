"""Fake-IP DNS mapping without installing a system DNS hook."""

from __future__ import annotations

import ipaddress
from threading import Lock


class FakeDNSMap:
    """Map configured resource domains into a documentation-only fake range."""

    def __init__(self, network: str = "198.18.0.0/24") -> None:
        parsed = ipaddress.ip_network(network, strict=True)
        if parsed.version != 4 or parsed.prefixlen < 24 or parsed.prefixlen > 30:
            raise ValueError("fake DNS pool must be an IPv4 /24-/30 network")
        self.network = parsed
        self._addresses = iter(parsed.hosts())
        self._mapping: dict[str, str] = {}
        self._lock = Lock()

    def register(self, domain: str) -> str:
        domain = domain.lower().rstrip(".")
        if not domain or len(domain) > 253 or any(ch in domain for ch in " /\\\r\n"):
            raise ValueError("invalid domain")
        with self._lock:
            if domain in self._mapping:
                return self._mapping[domain]
            try:
                address = str(next(self._addresses))
            except StopIteration as exc:
                raise RuntimeError("fake DNS pool exhausted") from exc
            self._mapping[domain] = address
            return address

    def resolve(self, domain: str) -> str | None:
        with self._lock:
            return self._mapping.get(domain.lower().rstrip("."))

    def manifest(self) -> dict[str, str]:
        with self._lock:
            return dict(self._mapping)

