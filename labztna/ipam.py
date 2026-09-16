"""In-memory virtual IPv4 allocation for the lab control plane."""

from __future__ import annotations

import ipaddress
from collections import deque
from threading import Lock


class VirtualIPPool:
    def __init__(self, network: str = "100.64.0.0/24") -> None:
        parsed = ipaddress.ip_network(network, strict=True)
        if parsed.version != 4 or parsed.prefixlen < 24 or parsed.prefixlen > 30:
            raise ValueError("lab virtual IP pool must be an IPv4 /24-/30 network")
        self.network = parsed
        self._available = deque(str(address) for address in parsed.hosts())
        self._allocated: dict[str, ipaddress.IPv4Address] = {}
        self._released: set[str] = set()
        self._lock = Lock()

    def allocate(self, session_id: str) -> str:
        with self._lock:
            if session_id in self._allocated:
                return str(self._allocated[session_id])
            try:
                address = ipaddress.ip_address(self._available.popleft())
            except IndexError as exc:
                raise RuntimeError("virtual IP pool exhausted") from exc
            self._allocated[session_id] = address
            self._released.discard(str(address))
            return str(address)

    def release(self, session_id: str) -> None:
        with self._lock:
            address = self._allocated.pop(session_id, None)
            if address is not None and str(address) not in self._released:
                self._available.append(str(address))
                self._released.add(str(address))

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return {session: str(address) for session, address in self._allocated.items()}
