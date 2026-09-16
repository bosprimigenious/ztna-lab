"""Strict client for the local lab control plane and gateway."""

from __future__ import annotations

import base64
import json
import socket
import ssl
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .netguard import require_loopback
from .routeplan import RoutePlan, build_route_plan
from .l3 import L3Packet
from .manifest import ManifestBinding, ManifestError, ManifestVerifier, require_manifest_binding
from .protocol import (
    FLAG_FIN,
    FLAG_RST,
    Frame,
    FrameCodec,
    FrameType,
    ProtocolError,
    connection_proof_message,
    control_proof_message,
    decode_control,
    encode_control,
)
from .policy import RESOURCE_ID_PATTERN, manifest_digest
from .tls import client_context


MAX_HTTP_RESPONSE = 1 * 1024 * 1024
MAX_PATH_LENGTH = 2_048
IO_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class LoginResult:
    token: str
    resource: str
    expires_in: int
    gateway_port: int
    session_id: str = ""
    virtual_ip: str = ""
    lease_generation: int = 0
    manifest: dict[str, object] | None = None


class LabClient:
    def __init__(
        self,
        *,
        ca_file: str,
        control_address: tuple[str, int],
        gateway_address: tuple[str, int],
        manifest_verifier: ManifestVerifier,
    ):
        self._ca_file = ca_file
        require_loopback(control_address[0])
        require_loopback(gateway_address[0])
        if not (1 <= control_address[1] <= 65_535 and 1 <= gateway_address[1] <= 65_535):
            raise ValueError("invalid loopback port")
        self._control_address = control_address
        self._gateway_address = gateway_address
        self._manifest_verifier = manifest_verifier
        self._token: str | None = None
        self._resource: str | None = None
        self._session_id: str | None = None
        self._device_id: str | None = None
        self._binding: ManifestBinding | None = None
        self._manifest: dict[str, object] = {}
        self._device_key = Ed25519PrivateKey.generate()

    def login(
        self,
        username: str,
        password: str,
        otp: str,
        *,
        device_id: str = "lab-device",
        os_name: str = "windows-lab",
        managed: bool = True,
        client_version: str = "ztna-lab/0.2",
    ) -> LoginResult:
        device_public_key = self._device_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        payload = json.dumps(
            {
                "username": username,
                "password": password,
                "otp": otp,
                "device_id": device_id,
                "os": os_name,
                "managed": managed,
                "client_version": client_version,
                "device_public_key": base64.urlsafe_b64encode(device_public_key)
                .rstrip(b"=")
                .decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        status, body = self._http_json_request(
            self._control_address,
            "POST",
            "/v1/login",
            payload,
            content_type="application/json",
        )
        if status != 200:
            raise PermissionError(f"control plane rejected login ({status})")
        try:
            body = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ConnectionError("control plane returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise ConnectionError("control plane returned an invalid object")
        try:
            token = body["token"]
            resource = body["resource"]
            expires_in = body["expires_in"]
            gateway_port = body["gateway_port"]
            session_id = body["session_id"]
            virtual_ip = body["virtual_ip"]
            lease_generation = body["lease_generation"]
            manifest_envelope = body["manifest"]
            if (
                not isinstance(token, str)
                or not isinstance(resource, str)
                or not isinstance(session_id, str)
                or not isinstance(virtual_ip, str)
                or not isinstance(lease_generation, int)
                or isinstance(lease_generation, bool)
                or lease_generation <= 0
                or not isinstance(manifest_envelope, dict)
            ):
                raise TypeError("grant fields must be strings")
            result = LoginResult(
                token=token,
                resource=resource,
                expires_in=int(expires_in),
                gateway_port=int(gateway_port),
                session_id=session_id,
                virtual_ip=virtual_ip,
                lease_generation=lease_generation,
                manifest=self._manifest_verifier.verify(manifest_envelope),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectionError("control plane returned an invalid authorization grant") from exc
        if (
            not result.token
            or RESOURCE_ID_PATTERN.fullmatch(result.resource) is None
            or result.gateway_port != self._gateway_address[1]
            or not 1 <= result.expires_in <= 600
        ):
            raise ConnectionError("control plane returned an invalid authorization grant")
        binding = ManifestBinding(
            result.session_id,
            result.virtual_ip,
            device_id,
            result.lease_generation,
            result.resource,
        )
        try:
            require_manifest_binding(result.manifest or {}, binding)
        except ManifestError as exc:
            raise ConnectionError("authorization manifest binding mismatch") from exc
        self._token = result.token
        self._resource = result.resource
        self._session_id = result.session_id
        self._device_id = device_id
        self._binding = binding
        self._manifest = result.manifest or {}
        return result

    def resources(self) -> dict[str, object]:
        self._require_login()
        status, body = self._http_json_request(
            self._control_address,
            "GET",
            "/v1/resources",
            b"",
            content_type="application/json",
            extra_headers=self._control_auth_headers("GET", "/v1/resources"),
        )
        if status != 200:
            raise PermissionError(f"resource manifest rejected ({status})")
        try:
            envelope = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ConnectionError("invalid resource manifest JSON") from exc
        if not isinstance(envelope, dict):
            raise ConnectionError("invalid resource manifest")
        result = self._manifest_verifier.verify(envelope)
        try:
            require_manifest_binding(result, self._binding_or_raise())
        except ManifestError as exc:
            raise ConnectionError("resource manifest binding mismatch") from exc
        self._manifest = result
        return result

    def resolve(self, domain: str) -> str | None:
        if not isinstance(domain, str) or not (1 <= len(domain) <= 253):
            raise ValueError("invalid DNS name")
        manifest = self._manifest or self.resources()
        try:
            require_manifest_binding(manifest, self._binding_or_raise())
        except ManifestError as exc:
            raise ConnectionError("resource manifest binding mismatch") from exc
        dns = manifest.get("dns", {})
        return dns.get(domain.lower().rstrip(".")) if isinstance(dns, dict) else None

    def route_plan(self) -> RoutePlan:
        self._require_login()
        manifest = self._manifest or self.resources()
        try:
            require_manifest_binding(manifest, self._binding_or_raise())
        except ManifestError as exc:
            raise ConnectionError("resource manifest binding mismatch") from exc
        expected = manifest.get("manifest_hash")
        base = {key: value for key, value in manifest.items() if key not in {"manifest_hash", "session"}}
        if not isinstance(expected, str) or manifest_digest(base) != expected:
            raise ConnectionError("resource manifest hash mismatch")
        return build_route_plan(manifest)

    def heartbeat(self) -> None:
        self._require_login()
        status, body = self._http_json_request(
            self._control_address,
            "POST",
            "/v1/heartbeat",
            b"{}",
            content_type="application/json",
            extra_headers=self._control_auth_headers("POST", "/v1/heartbeat"),
        )
        if status != 200:
            raise PermissionError(f"heartbeat rejected ({status})")
        try:
            response = json.loads(body)
            token = response["token"]
            expires_in = response["expires_in"]
            envelope = response["manifest"]
            if (
                not isinstance(token, str)
                or not isinstance(expires_in, int)
                or isinstance(expires_in, bool)
                or not (1 <= expires_in <= 600)
                or not isinstance(envelope, dict)
            ):
                raise TypeError("invalid heartbeat response")
            manifest = self._manifest_verifier.verify(envelope)
            require_manifest_binding(manifest, self._binding_or_raise())
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ConnectionError("control plane returned an invalid heartbeat grant") from exc
        self._token = token
        self._manifest = manifest

    def logout(self) -> None:
        self._require_login()
        status, _body = self._http_json_request(
            self._control_address,
            "POST",
            "/v1/logout",
            b"{}",
            content_type="application/json",
            extra_headers=self._control_auth_headers("POST", "/v1/logout"),
        )
        if status != 200:
            raise PermissionError(f"logout rejected ({status})")
        self._token = None
        self._resource = None
        self._session_id = None
        self._device_id = None
        self._binding = None
        self._manifest = {}

    def _require_login(self) -> None:
        if (
            self._token is None
            or self._resource is None
            or self._session_id is None
            or self._binding is None
        ):
            raise RuntimeError("login is required")

    def _binding_or_raise(self) -> ManifestBinding:
        if self._binding is None:
            raise RuntimeError("login is required")
        return self._binding

    def _control_auth_headers(self, method: str, path: str) -> dict[str, str]:
        self._require_login()
        token = self._token or ""
        request_id = uuid.uuid4().hex
        timestamp = int(time.time())
        proof = self._device_key.sign(
            control_proof_message(
                token=token,
                method=method,
                path=path,
                request_id=request_id,
                timestamp=timestamp,
            )
        )
        return {
            "Authorization": f"Bearer {token}",
            "X-ZTNA-Request-ID": request_id,
            "X-ZTNA-Timestamp": str(timestamp),
            "X-ZTNA-Proof": base64.urlsafe_b64encode(proof).rstrip(b"=").decode("ascii"),
        }

    def fetch(self, path: str = "/") -> tuple[int, bytes, str]:
        self._require_login()
        if (
            not path.startswith("/")
            or len(path) > MAX_PATH_LENGTH
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in path)
        ):
            raise ValueError("path must be a safe HTTP path")
        host, port = self._gateway_address
        raw = socket.create_connection((host, port), timeout=IO_TIMEOUT_SECONDS)
        context = client_context(self._ca_file)
        with context.wrap_socket(raw, server_hostname="localhost") as connection:
            connection.settimeout(IO_TIMEOUT_SECONDS)
            hello = json.dumps(
                {
                    "token": self._token,
                    "resource": self._resource,
                    "device_id": self._device_id,
                    "mode": "tcp",
                    "request_id": uuid.uuid4().hex,
                },
                separators=(",", ":"),
            ).encode() + b"\n"
            request_id = json.loads(hello.decode("utf-8"))["request_id"]
            timestamp = int(time.time())
            proof = self._device_key.sign(
                connection_proof_message(
                    token=self._token,
                    resource=self._resource,
                    mode="tcp",
                    request_id=request_id,
                    timestamp=timestamp,
                )
            )
            hello_payload = json.loads(hello.decode("utf-8"))
            hello_payload.update(
                {
                    "timestamp": timestamp,
                    "proof": base64.urlsafe_b64encode(proof).rstrip(b"=").decode("ascii"),
                }
            )
            hello = json.dumps(hello_payload, separators=(",", ":")).encode() + b"\n"
            connection.sendall(hello)
            ack = self._readline(connection, 8_192)
            response = json.loads(ack.decode("utf-8"))
            if not isinstance(response, dict):
                raise PermissionError("access_denied")
            if not response.get("ok"):
                raise PermissionError(str(response.get("error", "access_denied")))
            if response.get("resource") != self._resource:
                raise PermissionError("gateway returned an unexpected resource")
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self._resource}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            connection.sendall(
                encode_control(
                    FrameType.TCP_OPEN,
                    0,
                    {"protocol": "http/1.1", "resource": self._resource},
                    stream_id=1,
                ).encode()
            )
            connection.sendall(
                Frame(
                    FrameType.TCP_DATA,
                    1,
                    request,
                    stream_id=1,
                    flags=FLAG_FIN,
                ).encode()
            )
            framed_response = self._read_all(connection)
        codec = FrameCodec(max_frames=1_024)
        try:
            frames = codec.feed(framed_response)
            codec.finish()
        except ProtocolError as exc:
            raise ConnectionError("invalid framed gateway response") from exc
        if not frames or frames[0].frame_type != FrameType.TCP_OPEN or frames[0].stream_id != 1:
            raise ConnectionError("gateway did not open the response stream")
        open_response = decode_control(frames[0])
        if open_response != {"ok": True, "resource": self._resource}:
            raise ConnectionError("gateway returned an invalid stream acknowledgement")
        data_frames = frames[1:]
        if (
            not data_frames
            or not (data_frames[-1].flags & FLAG_FIN)
            or any(frame.frame_type != FrameType.TCP_DATA or frame.flags & FLAG_RST for frame in data_frames)
        ):
            raise ConnectionError("gateway returned an incomplete response stream")
        raw_response = b"".join(frame.payload for frame in data_frames)
        head, _, body = raw_response.partition(b"\r\n\r\n")
        status_line = head.splitlines()[0].decode("ascii", "replace")
        status = int(status_line.split()[1])
        return status, body, status_line

    def send_l3(self, destination: str, payload: bytes) -> dict[str, object]:
        """Send one authorized user-space L3 frame and return its gateway ack.

        This method intentionally stops at the lab gateway. It does not open a
        raw socket, install a route, or emit a packet onto the host network.
        """

        self._require_login()
        plan = self.route_plan()
        packet = L3Packet(plan.virtual_ip, destination, payload)
        frame = Frame(FrameType.L3_DATA, 0, packet.encode(), stream_id=1)
        route = plan.lookup(destination)
        if route is None:
            raise PermissionError("destination is outside the authorized route plan")
        host, port = self._gateway_address
        raw = socket.create_connection((host, port), timeout=IO_TIMEOUT_SECONDS)
        context = client_context(self._ca_file)
        request_id = uuid.uuid4().hex
        timestamp = int(time.time())
        proof = self._device_key.sign(
            connection_proof_message(
                token=self._token or "",
                resource=self._resource or "",
                mode="l3",
                request_id=request_id,
                timestamp=timestamp,
            )
        )
        hello = json.dumps(
            {
                "token": self._token,
                "resource": self._resource,
                "device_id": self._device_id,
                "mode": "l3",
                "request_id": request_id,
                "timestamp": timestamp,
                "proof": base64.urlsafe_b64encode(proof).rstrip(b"=").decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        try:
            with context.wrap_socket(raw, server_hostname="localhost") as connection:
                connection.settimeout(IO_TIMEOUT_SECONDS)
                connection.sendall(hello)
                ack = self._readline(connection, 8_192)
                handshake = json.loads(ack.decode("utf-8"))
                if not isinstance(handshake, dict) or not handshake.get("ok"):
                    raise PermissionError("gateway denied L3 session")
                connection.sendall(frame.encode())
                response = self._read_all(connection)
        finally:
            try:
                raw.close()
            except OSError:
                pass
        codec = FrameCodec(max_frames=2)
        frames = codec.feed(response)
        codec.finish()
        if len(frames) != 1 or frames[0].frame_type != FrameType.PONG:
            raise ConnectionError("invalid L3 gateway response")
        return decode_control(frames[0])

    @staticmethod
    def _readline(connection: ssl.SSLSocket, limit: int) -> bytes:
        data = bytearray()
        while len(data) < limit:
            chunk = connection.recv(1)
            if not chunk:
                break
            data.extend(chunk)
            if chunk == b"\n":
                return bytes(data)
        raise ConnectionError("incomplete gateway response")

    @staticmethod
    def _read_all(connection: ssl.SSLSocket) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > MAX_HTTP_RESPONSE:
                raise ConnectionError("HTTP response exceeds lab limit")
            chunks.append(chunk)

    def _http_json_request(
        self,
        address: tuple[str, int],
        method: str,
        path: str,
        payload: bytes,
        *,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        host, port = address
        require_loopback(host)
        if not (1 <= port <= 65_535):
            raise ValueError("invalid loopback port")
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise ValueError("unsafe HTTP path")
        raw = socket.create_connection((host, port), timeout=IO_TIMEOUT_SECONDS)
        context = client_context(self._ca_file)
        try:
            with context.wrap_socket(raw, server_hostname="localhost") as connection:
                connection.settimeout(IO_TIMEOUT_SECONDS)
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n"
                ).encode("ascii")
                for name, value in (extra_headers or {}).items():
                    if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                        raise ValueError("unsafe HTTP header")
                    request += f"{name}: {value}\r\n".encode("ascii")
                request += b"\r\n" + payload
                connection.sendall(request)
                raw_response = self._read_all(connection)
        finally:
            # ``wrap_socket`` may fail before it owns the raw socket.
            try:
                raw.close()
            except OSError:
                pass
        head, separator, body = raw_response.partition(b"\r\n\r\n")
        if not separator or len(head) > 16_384:
            raise ConnectionError("invalid HTTP response")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError) as exc:
            raise ConnectionError("invalid HTTP status line") from exc
        declared_length: int | None = None
        for line in lines[1:]:
            if b":" not in line:
                raise ConnectionError("invalid HTTP header")
            name, value = line.split(b":", 1)
            if name.lower() == b"content-length":
                try:
                    declared_length = int(value.strip())
                except ValueError as exc:
                    raise ConnectionError("invalid Content-Length") from exc
        if declared_length is not None and declared_length != len(body):
            raise ConnectionError("truncated HTTP response")
        return status, body
