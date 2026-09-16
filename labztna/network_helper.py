"""Dry-run boundary for applying a verified client network plan.

The production counterpart of this component would be the only privileged
process allowed to touch TUN, routes, or DNS. This lab implementation performs
no operating-system calls and changes in-memory state only.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any

from .manifest import ManifestBinding, ManifestVerifier, require_manifest_binding
from .routeplan import RouteEntry, RoutePlan, build_route_plan


@dataclass(frozen=True)
class NetworkState:
    generation: int
    virtual_ip: str | None
    routes: tuple[RouteEntry, ...]
    fake_dns: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class NetworkChange:
    before: NetworkState
    after: NetworkState
    added_routes: tuple[RouteEntry, ...]
    removed_routes: tuple[RouteEntry, ...]
    added_dns: tuple[tuple[str, str], ...]
    removed_dns: tuple[tuple[str, str], ...]


class DryRunNetworkHelper:
    """Verify, preview, apply, and roll back plans without touching the host."""

    mutates_os = False

    def __init__(self, verifier: ManifestVerifier, binding: ManifestBinding) -> None:
        self._verifier = verifier
        self._binding = binding
        self._state = NetworkState(0, None, (), ())
        self._lock = Lock()

    def snapshot(self) -> NetworkState:
        with self._lock:
            return self._state

    def preview(self, envelope: dict[str, Any]) -> NetworkChange:
        plan = self._verified_plan(envelope)
        with self._lock:
            return self._change(self._state, plan)

    def apply(self, envelope: dict[str, Any]) -> NetworkChange:
        plan = self._verified_plan(envelope)
        with self._lock:
            change = self._change(self._state, plan)
            self._state = change.after
            return change

    def rollback(self) -> NetworkChange:
        with self._lock:
            before = self._state
            if before.virtual_ip is None and not before.routes and not before.fake_dns:
                return NetworkChange(before, before, (), (), (), ())
            after = NetworkState(before.generation + 1, None, (), ())
            change = self._delta(before, after)
            self._state = after
            return change

    def _verified_plan(self, envelope: dict[str, Any]) -> RoutePlan:
        manifest = self._verifier.verify(envelope)
        require_manifest_binding(manifest, self._binding)
        return build_route_plan(manifest)

    def _change(self, before: NetworkState, plan: RoutePlan) -> NetworkChange:
        target_routes = tuple(plan.routes)
        target_dns = tuple(sorted(plan.fake_dns.items()))
        if (
            before.virtual_ip == plan.virtual_ip
            and before.routes == target_routes
            and before.fake_dns == target_dns
        ):
            return NetworkChange(before, before, (), (), (), ())
        after = NetworkState(
            before.generation + 1,
            plan.virtual_ip,
            target_routes,
            target_dns,
        )
        return self._delta(before, after)

    @staticmethod
    def _delta(before: NetworkState, after: NetworkState) -> NetworkChange:
        old_routes = set(before.routes)
        new_routes = set(after.routes)
        old_dns = set(before.fake_dns)
        new_dns = set(after.fake_dns)
        return NetworkChange(
            before,
            after,
            tuple(sorted(new_routes - old_routes, key=lambda item: (item.prefix, item.resource_id))),
            tuple(sorted(old_routes - new_routes, key=lambda item: (item.prefix, item.resource_id))),
            tuple(sorted(new_dns - old_dns)),
            tuple(sorted(old_dns - new_dns)),
        )
