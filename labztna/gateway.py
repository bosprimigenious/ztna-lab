"""TLS gateway with a fixed, non-user-selectable local resource target."""

from __future__ import annotations

import base64
import binascii
import json
import socket
import socketserver
import threading
import time
from threading import BoundedSemaphore, Thread

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .auth import TokenError, TokenVerifier
from .audit import AuditLog
from .netguard import require_loopback
from .policy import PolicyEngine, ResourceRegistry
from .protocol import (
    FLAG_FIN,
    FLAG_RST,
    Frame,
    FrameCodec,
    FrameType,
    ProtocolError,
    connection_proof_message,
    decode_control,
    encode_control,
)
from .l3 import L3Packet
from .session import SessionStore
from .tls import server_context


MAX_TOKEN_LENGTH = 8_192
MAX_RESOURCE_LENGTH = 256
MAX_RELAY_BYTES = 4 * 1024 * 1024
MAX_RELAY_SECONDS = 30.0
TLS_HANDSHAKE_TIMEOUT = 10.0
MAX_CONNECTIONS = 32
MAX_HTTP_REQUEST = 16 * 1024
MAX_PROOF_SKEW = 30
MAX_REPLAY_IDS = 4_096


class _GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = self.request
        request.settimeout(10)
        try:
            header = self._readline(request, 8_192)
            hello = json.loads(header.decode("utf-8"))
            if not isinstance(hello, dict):
                self._reply({"ok": False, "error": "invalid_handshake"})
                return
            token = hello.get("token")
            resource = hello.get("resource")
            device_id = hello.get("device_id")
            mode = hello.get("mode", "tcp")
            request_id = hello.get("request_id")
            timestamp = hello.get("timestamp")
            proof_encoded = hello.get("proof")
            if (
                request_id is not None
                and (not isinstance(request_id, str) or len(request_id) > 128)
            ):
                self._reply({"ok": False, "error": "invalid_request_id"})
                return
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(timestamp, int)
                or isinstance(timestamp, bool)
                or not isinstance(proof_encoded, str)
                or not (1 <= len(proof_encoded) <= 256)
            ):
                self._reply({"ok": False, "error": "invalid_proof"})
                return
            if (
                not isinstance(token, str)
                or not isinstance(resource, str)
                or not isinstance(device_id, str)
                or not isinstance(mode, str)
                or mode not in {"tcp", "l3"}
                or not (1 <= len(token) <= MAX_TOKEN_LENGTH)
                or not (1 <= len(resource) <= MAX_RESOURCE_LENGTH)
                or not (1 <= len(device_id) <= 128)
            ):
                self._reply({"ok": False, "error": "invalid_handshake"})
                return
            try:
                claims = self.server.gateway.signer.verify(token, expected_resource=resource)
            except TokenError:
                self.server.gateway.audit.record(
                    "connect", "deny", resource=resource, request_id=request_id, detail="invalid_token"
                )
                self._reply({"ok": False, "error": "access_denied"})
                return
            definition = self.server.gateway.registry.get(resource)
            session_id = claims.get("sid")
            session = (
                self.server.gateway.sessions.get_active(session_id)
                if isinstance(session_id, str)
                else None
            )
            if definition is None or session is None or session.subject != claims.get("sub"):
                self.server.gateway.audit.record(
                    "connect", "deny", resource=resource, request_id=request_id, detail="session_denied"
                )
                self._reply({"ok": False, "error": "resource_denied"})
                return
            if (
                claims.get("manifest_hash") != self.server.gateway.manifest_hash
                or claims.get("manifest_version") != self.server.gateway.manifest_version
            ):
                self.server.gateway.audit.record(
                    "connect", "deny", subject=session.subject, resource=resource,
                    device_id=session.posture.device_id, request_id=request_id, detail="stale_manifest"
                )
                self._reply({"ok": False, "error": "stale_manifest"})
                return
            token_device = claims.get("device_id")
            if token_device != session.posture.device_id or device_id != session.posture.device_id:
                self.server.gateway.audit.record(
                    "connect", "deny", subject=session.subject, resource=resource,
                    device_id=session.posture.device_id, request_id=request_id, detail="device_mismatch"
                )
                self._reply({"ok": False, "error": "device_denied"})
                return
            if claims.get("device_key_hash") != session.posture.key_fingerprint:
                self._reply({"ok": False, "error": "device_denied"})
                return
            if (
                claims.get("virtual_ip") != session.virtual_ip
                or claims.get("lease_generation") != session.lease_generation
            ):
                self._reply({"ok": False, "error": "lease_denied"})
                return
            if abs(int(time.time()) - timestamp) > MAX_PROOF_SKEW:
                self._reply({"ok": False, "error": "stale_proof"})
                return
            try:
                proof = base64.urlsafe_b64decode(proof_encoded + "=" * (-len(proof_encoded) % 4))
                Ed25519PublicKey.from_public_bytes(session.posture.public_key).verify(
                    proof,
                    connection_proof_message(
                        token=token,
                        resource=resource,
                        mode=mode,
                        request_id=request_id,
                        timestamp=timestamp,
                    ),
                )
            except (InvalidSignature, ValueError, TypeError, UnicodeError, binascii.Error):
                self._reply({"ok": False, "error": "invalid_proof"})
                return
            if not self.server.gateway.consume_request_id(session.session_id, request_id):
                self._reply({"ok": False, "error": "replayed_request"})
                return
            decision = self.server.gateway.policy.decide(
                subject=session.subject,
                resource_id=resource,
                action="read",
                posture=session.posture,
            )
            if not decision.allowed:
                self.server.gateway.audit.record(
                    "connect", "deny", subject=session.subject, resource=resource,
                    device_id=session.posture.device_id, request_id=request_id, detail=decision.reason
                )
                self._reply({"ok": False, "error": decision.reason})
                return

            if mode == "l3":
                self._reply(
                    {
                        "ok": True,
                        "resource": resource,
                        "virtual_ip": session.virtual_ip,
                        "session_expires_at": int(session.expires_at),
                    }
                )
                self._handle_l3(request, session, definition, request_id)
                return

            self._reply(
                {
                    "ok": True,
                    "resource": resource,
                    "virtual_ip": session.virtual_ip,
                    "session_expires_at": int(session.expires_at),
                }
            )
            self._handle_tcp(request, session, definition, request_id)
        except (OSError, ValueError, json.JSONDecodeError, UnicodeError):
            return

    def _handle_tcp(self, request: socket.socket, session, definition, request_id: str) -> None:
        """Relay one bounded HTTP request over the framed TCP stream."""

        codec = FrameCodec(max_frames=64)
        opened = False
        complete = False
        request_bytes = bytearray()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not complete:
            data = request.recv(65_536)
            if not data:
                return
            try:
                frames = codec.feed(data)
            except ProtocolError:
                return
            for frame in frames:
                if not opened:
                    if frame.frame_type != FrameType.TCP_OPEN or frame.stream_id != 1:
                        return
                    try:
                        options = decode_control(frame)
                    except ProtocolError:
                        return
                    if options != {"protocol": "http/1.1", "resource": definition.resource_id}:
                        return
                    opened = True
                    continue
                if frame.frame_type != FrameType.TCP_DATA or frame.stream_id != 1:
                    return
                if frame.flags & FLAG_RST:
                    return
                request_bytes.extend(frame.payload)
                if len(request_bytes) > MAX_HTTP_REQUEST:
                    return
                if frame.flags & FLAG_FIN:
                    complete = True
        try:
            codec.finish()
        except ProtocolError:
            return
        if not opened or not complete or not self._valid_http_request(bytes(request_bytes), definition.resource_id):
            return

        upstream = socket.create_connection((definition.host, definition.port), timeout=5)
        try:
            upstream.sendall(request_bytes)
            request.sendall(
                encode_control(
                    FrameType.TCP_OPEN,
                    0,
                    {"ok": True, "resource": definition.resource_id},
                    stream_id=1,
                ).encode()
            )
            self.server.gateway.audit.record(
                "connect", "allow", subject=session.subject, resource=definition.resource_id,
                device_id=session.posture.device_id, request_id=request_id
            )
            sequence = 1
            transferred = 0
            relay_deadline = time.monotonic() + MAX_RELAY_SECONDS
            upstream.settimeout(0.5)
            while time.monotonic() < relay_deadline:
                if self.server.gateway.sessions.get_active(session.session_id) is None:
                    return
                try:
                    chunk = upstream.recv(65_536)
                except socket.timeout:
                    continue
                if not chunk:
                    request.sendall(
                        Frame(
                            FrameType.TCP_DATA,
                            sequence,
                            b"",
                            stream_id=1,
                            flags=FLAG_FIN,
                        ).encode()
                    )
                    return
                transferred += len(chunk)
                if transferred > MAX_RELAY_BYTES:
                    return
                request.sendall(
                    Frame(FrameType.TCP_DATA, sequence, chunk, stream_id=1).encode()
                )
                sequence += 1
        finally:
            upstream.close()

    @staticmethod
    def _valid_http_request(payload: bytes, resource_id: str) -> bool:
        if not payload.endswith(b"\r\n\r\n") or b"\x00" in payload:
            return False
        lines = payload[:-4].split(b"\r\n")
        if not lines or not lines[0].startswith(b"GET ") or not lines[0].endswith(b" HTTP/1.1"):
            return False
        target = lines[0][4:-9]
        if (
            not target.startswith(b"/")
            or any(byte < 0x21 or byte > 0x7E for byte in target)
        ):
            return False
        host_values: list[str] = []
        for line in lines[1:]:
            if b":" not in line:
                return False
            name, value = line.split(b":", 1)
            lowered = name.strip().lower()
            if lowered == b"host":
                try:
                    host_values.append(value.strip().decode("ascii"))
                except UnicodeError:
                    return False
            if lowered in {b"content-length", b"transfer-encoding"}:
                return False
        return host_values == [resource_id]

    def _handle_l3(self, request: socket.socket, session, definition, request_id: str) -> None:
        """Validate one user-space L3 frame and return a simulated acknowledgement."""

        codec = FrameCodec(max_frames=2)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            data = request.recv(65_536)
            if not data:
                return
            try:
                frames = codec.feed(data)
            except ProtocolError:
                return
            if not frames:
                continue
            for frame in frames:
                if frame.frame_type != FrameType.L3_DATA or frame.stream_id != 1:
                    return
                try:
                    packet = L3Packet.decode(frame.payload)
                except ProtocolError:
                    return
                route = None
                for prefix in definition.routes:
                    import ipaddress

                    network = ipaddress.ip_network(prefix, strict=False)
                    if ipaddress.ip_address(packet.destination) in network:
                        route = network
                        break
                if route is None or packet.source != session.virtual_ip:
                    self.server.gateway.audit.record(
                        "l3_packet", "deny", subject=session.subject, resource=definition.resource_id,
                        device_id=session.posture.device_id, request_id=request_id, detail="route_denied"
                    )
                    return
                ack = encode_control(
                    FrameType.PONG,
                    0,
                    {
                        "ok": True,
                        "mode": "l3",
                        "resource": definition.resource_id,
                        "destination": packet.destination,
                        "bytes": len(packet.payload),
                    },
                )
                request.sendall(ack.encode())
                self.server.gateway.audit.record(
                    "l3_packet", "allow", subject=session.subject, resource=definition.resource_id,
                    device_id=session.posture.device_id, request_id=request_id,
                    detail=f"bytes={len(packet.payload)}",
                )
                return
        return

    @staticmethod
    def _readline(connection: socket.socket, limit: int) -> bytes:
        data = bytearray()
        while len(data) < limit:
            chunk = connection.recv(1)
            if not chunk:
                raise ConnectionError("incomplete gateway handshake")
            data.extend(chunk)
            if chunk == b"\n":
                line = bytes(data[:-1])
                return line[:-1] if line.endswith(b"\r") else line
        raise ValueError("gateway handshake too large")

    def _reply(self, payload: dict[str, object]) -> None:
        self.request.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")

class _TLSGatewayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address, handler, gateway, context):
        self.gateway = gateway
        self.context = context
        self._slots = BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(TLS_HANDSHAKE_TIMEOUT)
        try:
            wrapped = self.context.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            raise
        return wrapped, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Gateway:
    def __init__(
        self,
        *,
        cert_file: str,
        key_file: str,
        signer: TokenVerifier,
        resource_id: str,
        registry: ResourceRegistry,
        policy: PolicyEngine | None = None,
        sessions: SessionStore,
        audit: AuditLog | None = None,
        manifest_hash: str = "",
        manifest_version: int = 1,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        require_loopback(host)
        self.signer = signer
        self.resource_id = resource_id
        self.registry = registry
        self.policy = policy or PolicyEngine(self.registry)
        self.sessions = sessions
        self.audit = audit or AuditLog()
        if len(manifest_hash) != 64 or any(ch not in "0123456789abcdef" for ch in manifest_hash):
            raise ValueError("invalid manifest hash")
        if manifest_version != 1:
            raise ValueError("unsupported manifest version")
        self.manifest_hash = manifest_hash
        self.manifest_version = manifest_version
        self._replay_ids: set[tuple[str, str]] = set()
        self._replay_order: list[tuple[str, str]] = []
        self._replay_lock = threading.Lock()
        self._server = _TLSGatewayServer(
            (host, port), _GatewayHandler, self, server_context(cert_file, key_file)
        )
        self._thread: Thread | None = None
        self._started = False

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address

    def consume_request_id(self, session_id: str, request_id: str) -> bool:
        key = (session_id, request_id)
        with self._replay_lock:
            if key in self._replay_ids:
                return False
            self._replay_ids.add(key)
            self._replay_order.append(key)
            while len(self._replay_order) > MAX_REPLAY_IDS:
                old = self._replay_order.pop(0)
                self._replay_ids.discard(old)
            return True

    def start(self) -> None:
        if self._started:
            return
        self._thread = Thread(target=self._server.serve_forever, name="ztna-gateway", daemon=True)
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        if not self._started:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._started = False
