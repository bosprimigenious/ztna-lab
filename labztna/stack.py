"""Lifecycle helper for the all-local lab stack."""

from __future__ import annotations

import tempfile
from pathlib import Path
import secrets

from .auth import TokenSigner, new_totp_secret
from .audit import AuditLog
from .certs import TLSBundle, create_ephemeral_bundle
from .control import ControlPlane
from .dnsmap import FakeDNSMap
from .gateway import Gateway
from .ipam import VirtualIPPool
from .manifest import ManifestSigner
from .policy import MANIFEST_VERSION, PolicyEngine, ResourceDefinition, ResourceRegistry, manifest_digest
from .resource import ResourceServer
from .session import SessionStore


class LabStack:
    """Start a complete disposable stack on loopback addresses."""

    def __init__(self, root: str | Path | None = None) -> None:
        if root is not None:
            raise ValueError("LabStack only permits an internally managed temporary directory")
        self._temporary_root = tempfile.TemporaryDirectory(prefix="ztna-lab-")
        self.root = Path(self._temporary_root.name)
        try:
            self.bundle: TLSBundle = create_ephemeral_bundle(self.root / "certs")
        except BaseException:
            self._temporary_root.cleanup()
            raise
        self.username = "lab-user"
        self.password = secrets.token_urlsafe(18)
        self.otp_secret = new_totp_secret()
        self.resource = ResourceServer()
        self.registry: ResourceRegistry | None = None
        self.policy: PolicyEngine | None = None
        self.sessions = SessionStore(VirtualIPPool())
        self.dns = FakeDNSMap()
        self.audit = AuditLog()
        self.signer = TokenSigner()
        self.manifest_signer = ManifestSigner()
        self.gateway: Gateway | None = None
        self.control: ControlPlane | None = None

    def start(self) -> None:
        try:
            self.resource.start()
            resource_host, resource_port = self.resource.address
            self.registry = ResourceRegistry(
                [
                    ResourceDefinition(
                        "demo-resource",
                        resource_host,
                        resource_port,
                        domains=("demo.internal",),
                        routes=("10.60.0.0/16",),
                    )
                ]
            )
            self.policy = PolicyEngine(self.registry)
            for definition in self.registry.all():
                for domain in definition.domains:
                    self.dns.register(domain)
            manifest_hash = manifest_digest({**self.registry.manifest(), "dns": self.dns.manifest()})
            self.gateway = Gateway(
                cert_file=str(self.bundle.gateway_cert),
                key_file=str(self.bundle.gateway_key),
                signer=self.signer.verifier(),
                resource_id=self.resource.resource_id,
                registry=self.registry,
                policy=self.policy,
                sessions=self.sessions,
                audit=self.audit,
                manifest_hash=manifest_hash,
                manifest_version=MANIFEST_VERSION,
            )
            self.gateway.start()
            self.control = ControlPlane(
                cert_file=str(self.bundle.control_cert),
                key_file=str(self.bundle.control_key),
                username=self.username,
                password=self.password,
                otp_secret=self.otp_secret,
                resource_id=self.resource.resource_id,
                gateway_port=self.gateway.address[1],
                signer=self.signer,
                registry=self.registry,
                policy=self.policy,
                sessions=self.sessions,
                dns=self.dns,
                audit=self.audit,
                manifest_signer=self.manifest_signer,
            )
            self.control.start()
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        if self.control:
            self.control.stop()
        if self.gateway:
            self.gateway.stop()
        self.resource.stop()
        self._temporary_root.cleanup()

    def __enter__(self) -> "LabStack":
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()
