"""Client-side in-memory route/DNS plan derived from an authorization manifest."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .policy import covers_entire_ipv4


@dataclass(frozen=True)
class RouteEntry:
    prefix: str
    resource_id: str
    next_hop: str


@dataclass(frozen=True)
class RoutePlan:
    version: int
    virtual_ip: str
    routes: tuple[RouteEntry, ...]
    fake_dns: dict[str, str]

    def lookup(self, address: str) -> RouteEntry | None:
        target = ipaddress.ip_address(address)
        matches = []
        for route in self.routes:
            network = ipaddress.ip_network(route.prefix, strict=False)
            if target.version == network.version and target in network:
                matches.append((network.prefixlen, route))
        return max(matches, key=lambda item: item[0])[1] if matches else None


class ManifestError(ValueError):
    """Raised when a gateway manifest cannot be safely converted to a plan."""


def build_route_plan(manifest: dict[str, Any]) -> RoutePlan:
    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be an object")
    version = manifest.get("version")
    if version != 1:
        raise ManifestError("unsupported manifest version")
    if manifest.get("split_tunnel") is not True or manifest.get("route_installation") != "client-memory-only":
        raise ManifestError("manifest is not a split-tunnel lab manifest")
    session = manifest.get("session")
    if not isinstance(session, dict):
        raise ManifestError("missing session")
    virtual_ip = session.get("virtual_ip")
    if not isinstance(virtual_ip, str):
        raise ManifestError("virtual IP must be a string")
    try:
        parsed_virtual_ip = ipaddress.ip_address(virtual_ip)
    except ValueError as exc:
        raise ManifestError("invalid virtual IP") from exc
    if parsed_virtual_ip.version != 4 or not parsed_virtual_ip in ipaddress.ip_network("100.64.0.0/24"):
        raise ManifestError("virtual IP is outside lab pool")
    raw_resources = manifest.get("resources")
    if not isinstance(raw_resources, list) or not raw_resources:
        raise ManifestError("missing resources")
    routes: list[RouteEntry] = []
    route_networks: list[ipaddress.IPv4Network] = []
    owners: dict[str, str] = {}
    for resource in raw_resources:
        if not isinstance(resource, dict):
            raise ManifestError("invalid resource entry")
        resource_id = resource.get("id")
        raw_routes = resource.get("routes", [])
        if not isinstance(resource_id, str) or not (1 <= len(resource_id) <= 128):
            raise ManifestError("invalid resource id")
        if not isinstance(raw_routes, list):
            raise ManifestError("invalid resource routes")
        for prefix in raw_routes:
            if not isinstance(prefix, str):
                raise ManifestError("route prefix must be a string")
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError as exc:
                raise ManifestError("invalid route prefix") from exc
            if (
                network.version != 4
                or network.prefixlen == 0
                or network.is_unspecified
                or network.is_multicast
            ):
                raise ManifestError("route prefix is not permitted")
            canonical = str(network)
            prior_owner = owners.get(canonical)
            if prior_owner is not None and prior_owner != resource_id:
                raise ManifestError("ambiguous route ownership")
            if prior_owner == resource_id:
                continue
            owners[canonical] = resource_id
            route_networks.append(network)
            routes.append(RouteEntry(str(network), resource_id, str(virtual_ip)))
    if covers_entire_ipv4(route_networks):
        raise ManifestError("route set cannot form a full tunnel")
    raw_dns = manifest.get("dns", {})
    if not isinstance(raw_dns, dict) or any(
        not isinstance(domain, str) or not isinstance(value, str) for domain, value in raw_dns.items()
    ):
        raise ManifestError("invalid fake DNS map")
    for value in raw_dns.values():
        if not isinstance(value, str):
            raise ManifestError("fake DNS address must be a string")
        try:
            fake_ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ManifestError("invalid fake DNS address") from exc
        if fake_ip.version != 4 or fake_ip not in ipaddress.ip_network("198.18.0.0/24"):
            raise ManifestError("fake DNS address is outside lab pool")
    normalized_dns: dict[str, str] = {}
    for domain, value in raw_dns.items():
        canonical_domain = domain.lower().rstrip(".")
        if (
            not canonical_domain
            or len(canonical_domain) > 253
            or any(ch in canonical_domain for ch in " /\\\r\n")
            or canonical_domain in normalized_dns
        ):
            raise ManifestError("invalid or duplicate DNS name")
        normalized_dns[canonical_domain] = value
    return RoutePlan(version, str(parsed_virtual_ip), tuple(routes), normalized_dns)
