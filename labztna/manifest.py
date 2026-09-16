"""Asymmetric signing and verification for route/resource manifests."""

from __future__ import annotations

import base64
import binascii
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .policy import MANIFEST_VERSION, canonical_json, manifest_digest


class ManifestError(ValueError):
    """Raised when a signed manifest envelope is invalid or expired."""


@dataclass(frozen=True)
class ManifestBinding:
    session_id: str
    virtual_ip: str
    device_id: str
    lease_generation: int
    resource_id: str


def require_manifest_binding(manifest: dict[str, Any], binding: ManifestBinding) -> None:
    """Bind a valid signature to the client's current session and device."""

    session = manifest.get("session")
    if not isinstance(session, dict):
        raise ManifestError("manifest is missing its session binding")
    expected = {
        "id": binding.session_id,
        "virtual_ip": binding.virtual_ip,
        "device_id": binding.device_id,
        "lease_generation": binding.lease_generation,
    }
    if any(session.get(name) != value for name, value in expected.items()):
        raise ManifestError("manifest belongs to a different session or device")
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not any(
        isinstance(resource, dict) and resource.get("id") == binding.resource_id
        for resource in resources
    ):
        raise ManifestError("manifest does not contain the authorized resource")


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("base64 value must be text")
    return base64.b64decode(
        (value + "=" * (-len(value) % 4)).encode("ascii"),
        altchars=b"-_",
        validate=True,
    )


class ManifestVerifier:
    def __init__(self, public_key: Ed25519PublicKey, key_id: str = "lab-manifest-1") -> None:
        self._public_key = public_key
        self.key_id = key_id

    def verify(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(envelope, dict):
            raise ManifestError("manifest envelope must be an object")
        if set(envelope) != {"alg", "kid", "issued_at", "expires_at", "manifest", "signature"}:
            raise ManifestError("manifest envelope has unknown or missing fields")
        signed = {
            "alg": envelope.get("alg"),
            "kid": envelope.get("kid"),
            "issued_at": envelope.get("issued_at"),
            "expires_at": envelope.get("expires_at"),
            "manifest": envelope.get("manifest"),
        }
        signature = envelope.get("signature")
        if signed["alg"] != "Ed25519" or signed["kid"] != self.key_id:
            raise ManifestError("unsupported manifest signature")
        if not isinstance(signature, str) or len(signature) > 256:
            raise ManifestError("invalid manifest signature")
        issued_at = signed["issued_at"]
        expires_at = signed["expires_at"]
        manifest = signed["manifest"]
        now = int(time.time())
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < issued_at
            or expires_at - issued_at > 600
            or issued_at > now + 30
            or expires_at <= now
            or not isinstance(manifest, dict)
        ):
            raise ManifestError("invalid manifest lifetime or body")
        try:
            self._public_key.verify(_b64d(signature), canonical_json(signed))
        except (InvalidSignature, ValueError, TypeError, binascii.Error) as exc:
            raise ManifestError("invalid manifest signature") from exc
        if manifest.get("version") != MANIFEST_VERSION:
            raise ManifestError("unsupported manifest version")
        expected_hash = manifest.get("manifest_hash")
        base = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_hash", "session"}
        }
        if not isinstance(expected_hash, str) or manifest_digest(base) != expected_hash:
            raise ManifestError("manifest digest mismatch")
        return manifest


class ManifestSigner(ManifestVerifier):
    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        key_id: str = "lab-manifest-1",
    ) -> None:
        self._private_key = private_key or Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
        super().__init__(self._private_key.public_key(), key_id=key_id)

    def verifier(self) -> ManifestVerifier:
        return ManifestVerifier(self._public_key, key_id=self.key_id)

    def issue(self, manifest: dict[str, Any], ttl_seconds: int = 120) -> dict[str, Any]:
        if not (1 <= ttl_seconds <= 600):
            raise ValueError("manifest TTL must be between 1 and 600 seconds")
        now = int(time.time())
        signed: dict[str, Any] = {
            "alg": "Ed25519",
            "kid": self.key_id,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "manifest": manifest,
        }
        return {**signed, "signature": _b64e(self._private_key.sign(canonical_json(signed)))}
