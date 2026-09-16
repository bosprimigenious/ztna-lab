"""Resource registry and least-privilege policy evaluation."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Iterable

from .netguard import require_loopback


MANIFEST_VERSION = 1
RESOURCE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def covers_entire_ipv4(networks: Iterable[ipaddress.IPv4Network]) -> bool:
    """Return whether a route set is equivalent to an IPv4 default route."""

    collapsed = tuple(ipaddress.collapse_addresses(networks))
    return any(network.prefixlen == 0 for network in collapsed)


def canonical_json(value: object) -> bytes:
    """Serialize a manifest deterministically for hashing/signing."""

    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def manifest_digest(manifest: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


@dataclass(frozen=True)
class DevicePosture:
    device_id: str
    os: str
    managed: bool
    client_version: str
    public_key: bytes = b""

    def is_compliant(self) -> bool:
        return (
            1 <= len(self.device_id) <= 128
            and self.os == "windows-lab"
            and self.managed is True
            and self.client_version.startswith("ztna-lab/")
            and len(self.public_key) == 32
        )

    @property
    def key_fingerprint(self) -> str:
        return hashlib.sha256(self.public_key).hexdigest()


@dataclass(frozen=True)
class ResourceDefinition:
    resource_id: str
    host: str
    port: int
    domains: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    actions: frozenset[str] = field(default_factory=lambda: frozenset({"read"}))

    def __post_init__(self) -> None:
        require_loopback(self.host)
        if not (1 <= self.port <= 65_535):
            raise ValueError("resource port must be in range")
        if RESOURCE_ID_PATTERN.fullmatch(self.resource_id) is None:
            raise ValueError("resource id is invalid")
        parsed_routes: list[ipaddress.IPv4Network] = []
        for route in self.routes:
            network = ipaddress.ip_network(route, strict=False)
            if network.version != 4 or network.prefixlen == 0 or network.is_multicast:
                raise ValueError("lab route is not permitted")
            parsed_routes.append(network)
        if covers_entire_ipv4(parsed_routes):
            raise ValueError("lab routes cannot form a full tunnel")
        for domain in self.domains:
            if not domain or len(domain) > 253 or any(ch in domain for ch in " /\\\r\n"):
                raise ValueError("invalid resource domain")


class ResourceRegistry:
    def __init__(self, resources: Iterable[ResourceDefinition]) -> None:
        items = list(resources)
        table: dict[str, ResourceDefinition] = {}
        for resource in items:
            if resource.resource_id in table:
                raise ValueError(f"duplicate resource id: {resource.resource_id}")
            table[resource.resource_id] = resource
        if not table:
            raise ValueError("at least one resource is required")
        all_routes = [
            ipaddress.ip_network(route, strict=False)
            for resource in items
            for route in resource.routes
        ]
        if covers_entire_ipv4(all_routes):
            raise ValueError("resource routes cannot form a full tunnel")
        self._resources = table

    def get(self, resource_id: str) -> ResourceDefinition | None:
        return self._resources.get(resource_id)

    def all(self) -> tuple[ResourceDefinition, ...]:
        return tuple(self._resources.values())

    def manifest(self) -> dict[str, object]:
        return {
            "version": MANIFEST_VERSION,
            "resources": [
                {
                    "id": resource.resource_id,
                    "domains": list(resource.domains),
                    "routes": list(resource.routes),
                    "actions": sorted(resource.actions),
                }
                for resource in self.all()
            ],
            "split_tunnel": True,
            "route_installation": "client-memory-only",
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(self, registry: ResourceRegistry) -> None:
        self.registry = registry

    def decide(
        self,
        *,
        subject: str,
        resource_id: str,
        action: str,
        posture: DevicePosture,
    ) -> PolicyDecision:
        if not subject or len(subject) > 128:
            return PolicyDecision(False, "invalid_subject")
        if not posture.is_compliant():
            return PolicyDecision(False, "device_not_compliant")
        resource = self.registry.get(resource_id)
        if resource is None:
            return PolicyDecision(False, "unknown_resource")
        if action not in resource.actions:
            return PolicyDecision(False, "action_not_allowed")
        return PolicyDecision(True, "policy_allow")
