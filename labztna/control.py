"""Local HTTPS control plane: password + TOTP -> short-lived token."""

from __future__ import annotations

import base64
import binascii
import json
import hmac
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .auth import (
    PasswordHash,
    TokenSigner,
    hash_password,
    matching_totp_step,
    verify_password,
)
from .audit import AuditLog
from .dnsmap import FakeDNSMap
from .ipam import VirtualIPPool
from .manifest import ManifestSigner
from .netguard import require_loopback
from .policy import (
    MANIFEST_VERSION,
    DevicePosture,
    PolicyEngine,
    ResourceDefinition,
    ResourceRegistry,
    manifest_digest,
)
from .protocol import ProtocolError, control_proof_message
from .session import SessionStore
from .tls import server_context


MAX_CONTROL_PROOF_SKEW = 30
MAX_CONTROL_REPLAY_IDS = 4_096


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)


class _ControlHandler(BaseHTTPRequestHandler):
    server_version = "ZTNA-Lab-Control/0.2"

    @property
    def control(self) -> "ControlPlane":
        return self.server.control

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/health":
            _json_response(self, 200, {"ok": True, "service": "control"})
            return
        if self.path == "/v1/resources":
            session = self._authorized_session()
            if session is None:
                return
            _json_response(self, 200, self.control.manifest_envelope_for(session))
            return
        if self.path == "/v1/audit":
            supplied = self.headers.get("X-Lab-Admin", "")
            if not hmac.compare_digest(supplied, self.control.admin_secret):
                _json_response(self, 401, {"error": "admin_authorization_required"})
                return
            _json_response(self, 200, {"events": self.control.audit.snapshot()})
            return
        _json_response(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path not in {"/v1/login", "/v1/heartbeat", "/v1/logout"}:
            _json_response(self, 404, {"error": "not_found"})
            return
        payload = self._read_json(required=self.path == "/v1/login")
        if payload is None:
            return

        if self.path == "/v1/heartbeat":
            session = self._authorized_session()
            if session is None:
                return
            refreshed = self.control.sessions.heartbeat(session.session_id)
            if refreshed is None:
                _json_response(self, 401, {"error": "session_expired"})
                return
            self.control.audit.record(
                "heartbeat", "allow", subject=session.subject, device_id=session.posture.device_id
            )
            _json_response(
                self,
                200,
                {
                    "ok": True,
                    "token": self.control.grant_for(refreshed),
                    "expires_in": self.control.grant_ttl_seconds,
                    "manifest": self.control.manifest_envelope_for(refreshed),
                },
            )
            return

        if self.path == "/v1/logout":
            session = self._authorized_session()
            if session is None:
                return
            self.control.sessions.revoke(session.session_id)
            self.control.audit.record(
                "logout", "allow", subject=session.subject, device_id=session.posture.device_id
            )
            _json_response(self, 200, {"ok": True})
            return

        required_types = {
            "username": str,
            "password": str,
            "otp": str,
            "device_id": str,
            "os": str,
            "managed": bool,
            "client_version": str,
            "device_public_key": str,
        }
        if any(
            name not in payload or type(payload[name]) is not expected_type
            for name, expected_type in required_types.items()
        ):
            _json_response(self, 400, {"error": "invalid_login_request"})
            return
        username = payload["username"]
        password = payload["password"]
        otp = payload["otp"]
        if username != self.control.username or not verify_password(password, self.control.password_hash):
            _json_response(self, 401, {"error": "invalid_credentials"})
            return
        if not self.control.consume_otp(otp):
            _json_response(self, 401, {"error": "invalid_otp"})
            return

        posture = DevicePosture(
            device_id=payload["device_id"],
            os=payload["os"],
            managed=payload["managed"],
            client_version=payload["client_version"],
            public_key=self._decode_device_key(payload["device_public_key"]),
        )
        decision = self.control.policy.decide(
            subject=username,
            resource_id=self.control.resource_id,
            action="read",
            posture=posture,
        )
        if not decision.allowed:
            self.control.audit.record(
                "login", "deny", subject=username, device_id=posture.device_id, detail=decision.reason
            )
            _json_response(self, 403, {"error": decision.reason})
            return

        session = self.control.sessions.create(username, posture)
        token = self.control.grant_for(session)
        self.control.audit.record(
            "login", "allow", subject=username, device_id=posture.device_id, resource=self.control.resource_id
        )
        _json_response(
            self,
            200,
            {
                "token": token,
                "resource": self.control.resource_id,
                "expires_in": self.control.grant_ttl_seconds,
                "gateway_port": self.control.gateway_port,
                "session_id": session.session_id,
                "virtual_ip": session.virtual_ip,
                "lease_generation": session.lease_generation,
                "manifest": self.control.manifest_envelope_for(session),
            },
        )

    @staticmethod
    def _decode_device_key(value: object) -> bytes:
        if not isinstance(value, str) or not (40 <= len(value) <= 64):
            return b""
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, binascii.Error):
            return b""
        return decoded if len(decoded) == 32 else b""

    def _read_json(self, *, required: bool) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0 and not required:
                return {}
            if length <= 0 or length > 16_384:
                raise ValueError("invalid body size")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("body must be an object")
            return payload
        except (ValueError, TypeError, json.JSONDecodeError):
            _json_response(self, 400, {"error": "invalid_json"})
            return None

    def _authorized_session(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            _json_response(self, 401, {"error": "authorization_required"})
            return None
        token = header[7:].strip()
        try:
            claims = self.control.signer.verify(token)
        except TokenError:
            _json_response(self, 401, {"error": "invalid_token"})
            return None
        session_id = claims.get("sid")
        if not isinstance(session_id, str):
            _json_response(self, 401, {"error": "invalid_session"})
            return None
        session = self.control.sessions.get_active(session_id)
        if (
            session is None
            or session.subject != claims.get("sub")
            or claims.get("resource") != self.control.resource_id
            or claims.get("device_id") != session.posture.device_id
            or claims.get("device_key_hash") != session.posture.key_fingerprint
            or claims.get("virtual_ip") != session.virtual_ip
            or claims.get("lease_generation") != session.lease_generation
            or claims.get("manifest_hash") != self.control.manifest_hash
            or claims.get("manifest_version") != self.control.manifest_version
        ):
            _json_response(self, 401, {"error": "session_expired"})
            return None
        request_id = self.headers.get("X-ZTNA-Request-ID", "")
        timestamp_text = self.headers.get("X-ZTNA-Timestamp", "")
        proof_text = self.headers.get("X-ZTNA-Proof", "")
        try:
            if not (1 <= len(request_id) <= 128 and 1 <= len(proof_text) <= 256):
                raise ValueError("invalid proof headers")
            timestamp = int(timestamp_text)
            if abs(int(time.time()) - timestamp) > MAX_CONTROL_PROOF_SKEW:
                raise ValueError("stale control proof")
            proof = base64.b64decode(
                (proof_text + "=" * (-len(proof_text) % 4)).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            Ed25519PublicKey.from_public_bytes(session.posture.public_key).verify(
                proof,
                control_proof_message(
                    token=token,
                    method=self.command,
                    path=self.path,
                    request_id=request_id,
                    timestamp=timestamp,
                ),
            )
        except (InvalidSignature, ProtocolError, ValueError, TypeError, UnicodeError, binascii.Error):
            _json_response(self, 401, {"error": "invalid_device_proof"})
            return None
        if not self.control.consume_control_request_id(session.session_id, request_id):
            _json_response(self, 401, {"error": "replayed_device_proof"})
            return None
        return session

    def log_message(self, *_args: object) -> None:
        return


class ControlPlane:
    def __init__(
        self,
        *,
        cert_file: str,
        key_file: str,
        username: str,
        password: str,
        otp_secret: str,
        resource_id: str,
        gateway_port: int,
        registry: ResourceRegistry,
        policy: PolicyEngine | None = None,
        sessions: SessionStore | None = None,
        dns: FakeDNSMap | None = None,
        audit: AuditLog | None = None,
        admin_secret: str | None = None,
        manifest_signer: ManifestSigner,
        host: str = "127.0.0.1",
        port: int = 0,
        signer: TokenSigner | None = None,
    ) -> None:
        require_loopback(host)
        self.username = username
        self.password_hash: PasswordHash = hash_password(password)
        self.otp_secret = otp_secret
        self.resource_id = resource_id
        self.gateway_port = gateway_port
        if not (1 <= gateway_port <= 65_535):
            raise ValueError("invalid gateway port")
        self.signer = signer or TokenSigner()
        self.registry = registry
        self.policy = policy or PolicyEngine(registry)
        self.sessions = sessions or SessionStore(VirtualIPPool())
        self.dns = dns or FakeDNSMap()
        for resource in self.registry.all():
            for domain in resource.domains:
                self.dns.register(domain)
        self.audit = audit or AuditLog()
        self.admin_secret = admin_secret or secrets.token_urlsafe(24)
        if not (16 <= len(self.admin_secret) <= 256):
            raise ValueError("admin secret length is invalid")
        self._manifest_base = {
            **self.registry.manifest(),
            "dns": self.dns.manifest(),
        }
        self.manifest_version = MANIFEST_VERSION
        self.manifest_hash = manifest_digest(self._manifest_base)
        self.manifest_signer = manifest_signer
        self.grant_ttl_seconds = 120
        self._used_otp_steps: set[int] = set()
        self._otp_lock = threading.Lock()
        self._control_replay_ids: set[tuple[str, str]] = set()
        self._control_replay_order: list[tuple[str, str]] = []
        self._control_replay_lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), _ControlHandler)
        self._server.control = self
        self._server.socket = server_context(cert_file, key_file).wrap_socket(
            self._server.socket, server_side=True
        )
        self._thread: Thread | None = None
        self._started = False

    def manifest_for(self, session) -> dict[str, object]:
        return {
            **self._manifest_base,
            "manifest_hash": self.manifest_hash,
            "session": {
                "id": session.session_id,
                "virtual_ip": session.virtual_ip,
                "lease_generation": session.lease_generation,
                "expires_at": int(session.expires_at),
                "device_id": session.posture.device_id,
            },
        }

    def manifest_envelope_for(self, session) -> dict[str, object]:
        return self.manifest_signer.issue(self.manifest_for(session))

    def grant_for(self, session) -> str:
        return self.signer.issue(
            session.subject,
            self.resource_id,
            ttl_seconds=self.grant_ttl_seconds,
            session_id=session.session_id,
            device_id=session.posture.device_id,
            device_key_hash=session.posture.key_fingerprint,
            manifest_hash=self.manifest_hash,
            manifest_version=self.manifest_version,
            virtual_ip=session.virtual_ip,
            lease_generation=session.lease_generation,
        )

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address

    def start(self) -> None:
        if self._started:
            return
        self._thread = Thread(target=self._server.serve_forever, name="ztna-control", daemon=True)
        self._thread.start()
        self._started = True

    def consume_otp(self, otp: str) -> bool:
        """Validate and consume a TOTP counter once for this short-lived demo."""

        step = matching_totp_step(self.otp_secret, otp)
        if step is None:
            return False
        current = int(time.time() // 30)
        with self._otp_lock:
            self._used_otp_steps.intersection_update({current - 2, current - 1, current, current + 1})
            if step in self._used_otp_steps:
                return False
            self._used_otp_steps.add(step)
        return True

    def consume_control_request_id(self, session_id: str, request_id: str) -> bool:
        key = (session_id, request_id)
        with self._control_replay_lock:
            if key in self._control_replay_ids:
                return False
            self._control_replay_ids.add(key)
            self._control_replay_order.append(key)
            while len(self._control_replay_order) > MAX_CONTROL_REPLAY_IDS:
                old = self._control_replay_order.pop(0)
                self._control_replay_ids.discard(old)
            return True

    def stop(self) -> None:
        if not self._started:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._started = False
