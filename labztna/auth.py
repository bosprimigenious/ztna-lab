"""Authentication and short-lived authorization tokens for the lab.

The implementation is intentionally small and local-only. It is not a JWT
replacement or a production identity provider.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


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


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_key(secret: str) -> bytes:
    normalized = "".join(secret.split()).upper()
    return base64.b32decode(normalized + "=" * (-len(normalized) % 8))


def totp_now(secret: str, timestamp: float | None = None) -> str:
    """Return a six-digit RFC 6238-compatible TOTP value."""

    counter = int((time.time() if timestamp is None else timestamp) // 30)
    digest = hmac.new(_totp_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def matching_totp_step(secret: str, supplied: str, timestamp: float | None = None) -> int | None:
    """Return the matching 30-second counter, or ``None`` if invalid."""

    supplied = str(supplied or "")
    if len(supplied) != 6 or not supplied.isdigit():
        return None
    now = time.time() if timestamp is None else timestamp
    current = int(now // 30)
    for window in (-1, 0, 1):
        counter = current + window
        if hmac.compare_digest(totp_now(secret, counter * 30), supplied):
            return counter
    return None


def verify_totp(secret: str, supplied: str, timestamp: float | None = None) -> bool:
    return matching_totp_step(secret, supplied, timestamp) is not None


@dataclass(frozen=True)
class PasswordHash:
    salt: bytes
    digest: bytes


def hash_password(password: str, salt: bytes | None = None) -> PasswordHash:
    salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return PasswordHash(salt=salt, digest=digest)


def verify_password(password: str, record: PasswordHash) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), record.salt, 210_000)
    return hmac.compare_digest(candidate, record.digest)


class TokenError(ValueError):
    """Raised when a lab access token is invalid or expired."""


class TokenVerifier:
    """Verify-only half of a grant signer, suitable for a gateway process."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        issuer: str = "ztna-lab",
        key_id: str = "lab-signing-1",
    ) -> None:
        self._public_key = public_key
        self.issuer = issuer
        self.key_id = key_id

    def verify(self, token: str, *, expected_resource: str | None = None) -> dict[str, Any]:
        if not isinstance(token, str) or not (1 <= len(token) <= 8_192):
            raise TokenError("malformed token")
        try:
            header_part, payload_part, signature_part = token.split(".")
            signing_input = f"{header_part}.{payload_part}".encode("ascii")
            self._public_key.verify(_b64d(signature_part), signing_input)
            header = json.loads(_b64d(header_part))
            payload = json.loads(_b64d(payload_part))
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeError, binascii.Error) as exc:
            raise TokenError("malformed token") from exc
        except Exception as exc:
            # InvalidSignature is deliberately indistinguishable from any other
            # invalid bearer token at the API boundary.
            raise TokenError("bad signature") from exc

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise TokenError("malformed token")
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "ZTNA1"
            or header.get("kid") != self.key_id
        ):
            raise TokenError("unsupported token")
        scopes = payload.get("scope")
        if (
            payload.get("iss") != self.issuer
            or payload.get("aud") != "ztna-gateway"
            or not isinstance(payload.get("sub"), str)
            or not payload.get("sub")
            or not isinstance(payload.get("resource"), str)
            or not payload.get("resource")
            or not isinstance(scopes, list)
            or any(not isinstance(scope, str) for scope in scopes)
        ):
            raise TokenError("wrong issuer")
        if expected_resource is not None and payload.get("resource") != expected_resource:
            raise TokenError("resource denied")
        if "resource:read" not in scopes:
            raise TokenError("scope denied")
        now = int(time.time())
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at < issued_at
            or expires_at - issued_at > 600
            or expires_at <= now
        ):
            raise TokenError("expired token")
        if issued_at > now + 30:
            raise TokenError("invalid issue time")
        if not isinstance(payload.get("jti"), str) or not (8 <= len(payload["jti"]) <= 128):
            raise TokenError("invalid token id")
        return payload


class TokenSigner(TokenVerifier):
    """Ed25519 signer for short-lived, audience-bound lab grants."""

    def __init__(
        self,
        key: bytes | None = None,
        issuer: str = "ztna-lab",
        key_id: str = "lab-signing-1",
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        if private_key is not None and key is not None:
            raise ValueError("provide either key or private_key")
        seed = secrets.token_bytes(32) if key is None else key
        if private_key is None:
            if len(seed) != 32:
                raise ValueError("test seed must be 32 bytes")
            private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self._private_key = private_key
        super().__init__(private_key.public_key(), issuer=issuer, key_id=key_id)

    def verifier(self) -> TokenVerifier:
        return TokenVerifier(self._public_key, issuer=self.issuer, key_id=self.key_id)

    def issue(
        self,
        subject: str,
        resource: str,
        ttl_seconds: int = 120,
        *,
        session_id: str | None = None,
        device_id: str | None = None,
        device_key_hash: str | None = None,
        manifest_hash: str | None = None,
        manifest_version: int | None = None,
        virtual_ip: str | None = None,
        lease_generation: int | None = None,
    ) -> str:
        if not (1 <= ttl_seconds <= 600):
            raise ValueError("token TTL must be between 1 and 600 seconds")
        now = int(time.time())
        header = {"alg": "EdDSA", "kid": self.key_id, "typ": "ZTNA1"}
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "aud": "ztna-gateway",
            "sub": subject,
            "resource": resource,
            "scope": ["resource:read"],
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_urlsafe(16),
        }
        if session_id is not None:
            payload["sid"] = session_id
        if device_id is not None:
            payload["device_id"] = device_id
        if device_key_hash is not None:
            payload["device_key_hash"] = device_key_hash
        if manifest_hash is not None:
            payload["manifest_hash"] = manifest_hash
        if manifest_version is not None:
            payload["manifest_version"] = manifest_version
        if virtual_ip is not None:
            payload["virtual_ip"] = virtual_ip
        if lease_generation is not None:
            payload["lease_generation"] = lease_generation
        encoded_header = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        encoded_payload = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = self._private_key.sign(signing_input)
        return f"{encoded_header}.{encoded_payload}.{_b64e(signature)}"

    def private_bytes_for_test(self) -> bytes:
        """Expose raw key bytes only to in-process test fixtures."""

        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
