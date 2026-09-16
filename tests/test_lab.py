from __future__ import annotations

import base64
import copy
import json
import socket
import ssl
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from labztna.auth import totp_now
from labztna.client import LabClient
from labztna.stack import LabStack
from labztna.tls import client_context
from labztna.netguard import require_loopback
from labztna.auth import TokenError, TokenSigner
from labztna.certs import create_ephemeral_bundle
from labztna.gateway import Gateway
from labztna.resource import ResourceServer
from labztna.ipam import VirtualIPPool
from labztna.l3 import MAX_PACKET, L3Packet, frame_to_packet, packet_to_frame
from labztna.manifest import (
    ManifestBinding,
    ManifestError as SignedManifestError,
    ManifestSigner,
    require_manifest_binding,
)
from labztna.network_helper import DryRunNetworkHelper
from labztna.policy import DevicePosture, manifest_digest
from labztna.protocol import (
    FLAG_FIN,
    FLAG_RST,
    Frame,
    FrameCodec,
    FrameType,
    ProtocolError,
    decode_control,
    encode_control,
)
from labztna.routeplan import ManifestError as RouteManifestError, build_route_plan
from labztna.session import SessionStore


@pytest.fixture()
def stack():
    with LabStack() as value:
        yield value


def make_client(stack: LabStack) -> LabClient:
    assert stack.control is not None and stack.gateway is not None
    return LabClient(
        ca_file=str(stack.bundle.ca_cert),
        control_address=stack.control.address,
        gateway_address=stack.gateway.address,
        manifest_verifier=stack.manifest_signer.verifier(),
    )


def test_authenticated_request_reaches_fixed_resource(stack: LabStack) -> None:
    client = make_client(stack)
    login = client.login(stack.username, stack.password, totp_now(stack.otp_secret))
    original_token = login.token
    status, body, status_line = client.fetch("/health-check")
    assert login.resource == "demo-resource"
    assert status == 200
    assert status_line.startswith("HTTP/1.0 200") or status_line.startswith("HTTP/1.1 200")
    payload = json.loads(body)
    assert payload["resource"] == "demo-resource"
    assert payload["path"] == "/health-check"
    manifest = client.resources()
    assert manifest["split_tunnel"] is True
    assert manifest["session"]["lease_generation"] == 1
    assert client.resolve("demo.internal") in {"198.18.0.1"}
    with pytest.raises(ValueError, match="safe HTTP path"):
        client.fetch("/space is-not-encoded")
    client.heartbeat()
    assert client._token != original_token
    client.logout()
    with pytest.raises(RuntimeError):
        client.fetch("/")


def test_authorized_l3_frame_is_checked_without_raw_network_io(stack: LabStack) -> None:
    client = make_client(stack)
    client.login(stack.username, stack.password, totp_now(stack.otp_secret))
    result = client.send_l3("10.60.1.20", b"synthetic-ip-payload")
    assert result["ok"] is True
    assert result["mode"] == "l3"
    assert result["destination"] == "10.60.1.20"
    with pytest.raises(PermissionError):
        client.send_l3("192.0.2.1", b"outside-route")


def test_noncompliant_device_is_rejected(stack: LabStack) -> None:
    assert stack.control is not None
    client = make_client(stack)
    with pytest.raises(PermissionError):
        client.login(
            stack.username,
            stack.password,
            totp_now(stack.otp_secret),
            managed=False,
        )


def test_missing_posture_fields_are_not_defaulted_to_compliant(stack: LabStack) -> None:
    assert stack.control is not None
    client = make_client(stack)
    public_key = client._device_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    payload = json.dumps(
        {
            "username": stack.username,
            "password": stack.password,
            "otp": totp_now(stack.otp_secret),
            "device_public_key": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii"),
        }
    ).encode("utf-8")
    status, body = client._http_json_request(
        stack.control.address,
        "POST",
        "/v1/login",
        payload,
        content_type="application/json",
    )
    assert status == 400
    assert json.loads(body)["error"] == "invalid_login_request"


def test_bad_otp_is_rejected(stack: LabStack) -> None:
    assert stack.control is not None
    client = make_client(stack)
    public_key = client._device_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    valid_otp = totp_now(stack.otp_secret)
    bad_otp = "000000" if valid_otp != "000000" else "000001"
    payload = json.dumps(
        {
            "username": stack.username,
            "password": stack.password,
            "otp": bad_otp,
            "device_id": "lab-device",
            "os": "windows-lab",
            "managed": True,
            "client_version": "ztna-lab/0.2",
            "device_public_key": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii"),
        }
    ).encode("utf-8")
    status, body = client._http_json_request(
        stack.control.address,
        "POST",
        "/v1/login",
        payload,
        content_type="application/json",
    )
    assert status == 401
    assert json.loads(body)["error"] == "invalid_otp"


def test_same_otp_cannot_be_reused(stack: LabStack) -> None:
    assert stack.control is not None
    otp = totp_now(stack.otp_secret)
    assert stack.control.consume_otp(otp)
    assert not stack.control.consume_otp(otp)


def test_tls_12_is_rejected(stack: LabStack) -> None:
    assert stack.gateway is not None
    raw = socket.create_connection(stack.gateway.address, timeout=5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ssl.SSLError):
        context.wrap_socket(raw, server_hostname="localhost")


def test_gateway_rejects_non_loopback_egress(stack: LabStack) -> None:
    with pytest.raises(ValueError):
        from labztna.policy import ResourceDefinition

        ResourceDefinition("bad-resource", "10.0.0.1", 80)


def test_resource_registry_rejects_a_default_route() -> None:
    from labztna.policy import ResourceDefinition, ResourceRegistry

    with pytest.raises(ValueError, match="not permitted"):
        ResourceDefinition(
            "bad-default-route",
            "127.0.0.1",
            8080,
            routes=("0.0.0.0/0",),
        )
    with pytest.raises(ValueError, match="resource id"):
        ResourceDefinition("bad\r\nid", "127.0.0.1", 8080)
    with pytest.raises(ValueError, match="full tunnel"):
        ResourceDefinition(
            "two-halves",
            "127.0.0.1",
            8080,
            routes=("0.0.0.0/1", "128.0.0.0/1"),
        )
    with pytest.raises(ValueError, match="full tunnel"):
        ResourceRegistry(
            [
                ResourceDefinition("lower", "127.0.0.1", 8080, routes=("0.0.0.0/1",)),
                ResourceDefinition("upper", "127.0.0.1", 8081, routes=("128.0.0.0/1",)),
            ]
        )


def test_resource_rejects_non_loopback_listener() -> None:
    with pytest.raises(ValueError):
        ResourceServer(host="0.0.0.0")


def test_versioned_frames_handle_fragmentation_and_replay() -> None:
    first = encode_control(FrameType.PING, 0, {"nonce": "a"}).encode()
    second = encode_control(
        FrameType.TCP_OPEN,
        0,
        {"protocol": "http/1.1", "resource": "demo-resource"},
        stream_id=1,
    ).encode()
    third = Frame(FrameType.TCP_DATA, 1, b"payload", stream_id=1, flags=FLAG_FIN).encode()
    codec = FrameCodec()
    assert codec.feed(first[:5]) == []
    decoded = codec.feed(first[5:] + second + third)
    codec.finish()
    assert [frame.frame_type for frame in decoded] == [
        FrameType.PING,
        FrameType.TCP_OPEN,
        FrameType.TCP_DATA,
    ]
    assert decode_control(decoded[0]) == {"nonce": "a"}
    with pytest.raises(ProtocolError):
        codec.feed(Frame(FrameType.PING, 0, b"").encode())


def test_frame_state_machine_rejects_illegal_transitions() -> None:
    with pytest.raises(ProtocolError):
        Frame(FrameType.L3_DATA, 0, b"packet", stream_id=0).encode()
    with pytest.raises(ProtocolError):
        Frame(
            FrameType.TCP_DATA,
            0,
            b"",
            stream_id=1,
            flags=FLAG_FIN | FLAG_RST,
        ).encode()
    codec = FrameCodec()
    with pytest.raises(ProtocolError):
        codec.feed(Frame(FrameType.TCP_DATA, 0, b"no-open", stream_id=1).encode())

    codec = FrameCodec()
    opened = encode_control(FrameType.TCP_OPEN, 0, {}, stream_id=7).encode()
    closed = Frame(FrameType.TCP_DATA, 1, b"", stream_id=7, flags=FLAG_FIN).encode()
    assert len(codec.feed(opened + closed)) == 2
    with pytest.raises(ProtocolError):
        codec.feed(Frame(FrameType.TCP_DATA, 2, b"late", stream_id=7).encode())


def test_frame_codec_rejects_truncated_eof() -> None:
    encoded = encode_control(FrameType.PING, 0, {"nonce": "x"}).encode()
    codec = FrameCodec()
    assert codec.feed(encoded[:-1]) == []
    with pytest.raises(ProtocolError):
        codec.finish()


def test_frame_codec_requires_tcp_close_and_honors_connection_close() -> None:
    codec = FrameCodec()
    codec.feed(encode_control(FrameType.TCP_OPEN, 0, {}, stream_id=3).encode())
    with pytest.raises(ProtocolError, match="without FIN"):
        codec.finish()

    codec = FrameCodec()
    codec.feed(encode_control(FrameType.CLOSE, 0, {}).encode())
    with pytest.raises(ProtocolError, match="after connection close"):
        codec.feed(encode_control(FrameType.PING, 1, {}).encode())


def test_frame_codec_accepts_multiple_large_complete_frames_in_one_read() -> None:
    encoded = bytearray(
        encode_control(FrameType.TCP_OPEN, 0, {}, stream_id=1).encode()
    )
    for sequence in range(1, 4):
        encoded.extend(
            Frame(
                FrameType.TCP_DATA,
                sequence,
                b"x" * (50 * 1024),
                stream_id=1,
                flags=FLAG_FIN if sequence == 3 else 0,
            ).encode()
        )
    codec = FrameCodec(max_frames=4)
    frames = codec.feed(bytes(encoded))
    codec.finish()
    assert len(frames) == 4


def test_route_plan_and_l3_packet_enforce_source_and_destination() -> None:
    manifest = {
        "version": 1,
        "split_tunnel": True,
        "route_installation": "client-memory-only",
        "session": {"virtual_ip": "100.64.0.1"},
        "resources": [{"id": "demo-resource", "routes": ["10.60.0.0/16"]}],
        "dns": {"demo.internal": "198.18.0.1"},
    }
    plan = build_route_plan(manifest)
    packet = L3Packet("100.64.0.1", "10.60.1.2", b"hello")
    frame = packet_to_frame(0, packet, plan)
    assert frame_to_packet(frame, plan) == packet
    with pytest.raises(PermissionError):
        packet_to_frame(1, L3Packet("100.64.0.2", "10.60.1.2", b"no"), plan)
    with pytest.raises(PermissionError):
        packet_to_frame(1, L3Packet("100.64.0.1", "192.0.2.1", b"no"), plan)
    assert isinstance(manifest_digest({"a": 1}), str)


def test_route_manifest_rejects_full_tunnel_or_bad_virtual_ip() -> None:
    with pytest.raises(RouteManifestError):
        build_route_plan({"split_tunnel": False})
    with pytest.raises(RouteManifestError):
        build_route_plan(
            {
                "split_tunnel": True,
                "route_installation": "client-memory-only",
                "session": {"virtual_ip": "10.0.0.2"},
                "resources": [{"id": "x", "routes": ["10.0.0.0/8"]}],
                "dns": {},
            }
        )
    with pytest.raises(RouteManifestError, match="not permitted"):
        build_route_plan(
            {
                "version": 1,
                "split_tunnel": True,
                "route_installation": "client-memory-only",
                "session": {"virtual_ip": "100.64.0.2"},
                "resources": [{"id": "x", "routes": ["0.0.0.0/0"]}],
                "dns": {},
            }
        )
    with pytest.raises(RouteManifestError, match="full tunnel"):
        build_route_plan(
            {
                "version": 1,
                "split_tunnel": True,
                "route_installation": "client-memory-only",
                "session": {"virtual_ip": "100.64.0.2"},
                "resources": [
                    {"id": "lower", "routes": ["0.0.0.0/1"]},
                    {"id": "upper", "routes": ["128.0.0.0/1"]},
                ],
                "dns": {},
            }
        )


def test_gateway_only_accepts_the_declared_resource(stack: LabStack) -> None:
    client = make_client(stack)
    client.login(stack.username, stack.password, totp_now(stack.otp_secret))
    client._resource = "another-resource"  # exercise the policy boundary, not a public API
    with pytest.raises(PermissionError):
        client.fetch("/")


def test_servers_are_loopback_and_tls_is_13(stack: LabStack) -> None:
    assert stack.control is not None and stack.gateway is not None
    assert stack.control.address[0] == "127.0.0.1"
    assert stack.gateway.address[0] == "127.0.0.1"
    assert stack.bundle.control_cert != stack.bundle.gateway_cert
    assert stack.bundle.control_key.read_bytes() != stack.bundle.gateway_key.read_bytes()
    raw = socket.create_connection(stack.gateway.address, timeout=5)
    with client_context(stack.bundle.ca_cert).wrap_socket(raw, server_hostname="localhost") as tls:
        assert tls.version() == "TLSv1.3"


def test_non_loopback_endpoints_are_rejected() -> None:
    with pytest.raises(ValueError):
        require_loopback("localhost")
    with pytest.raises(ValueError):
        require_loopback("10.0.0.1")
    with pytest.raises(ValueError):
        require_loopback("::1")


def test_gateway_rejects_malformed_signed_payloads() -> None:
    signer = TokenSigner(key=b"k" * 32)
    token = signer.issue("user", "demo-resource")
    header, payload, signature = token.split(".")
    # A changed header cannot be accepted even when the rest of the bearer
    # token looks structurally valid.
    def enc(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    malformed_header = enc(b'{"alg":"HS256","kid":"lab-signing-1","typ":"ZTNA1"}')
    malformed = f"{malformed_header}.{payload}.{signature}"
    with pytest.raises(TokenError):
        signer.verify(malformed, expected_resource="demo-resource")


def test_gateway_has_verify_only_grant_key(stack: LabStack) -> None:
    assert stack.gateway is not None
    assert not hasattr(stack.gateway.signer, "issue")
    assert not hasattr(stack.manifest_signer.verifier(), "issue")


def test_invalid_device_proof_is_denied_and_gateway_keeps_serving(stack: LabStack) -> None:
    client = make_client(stack)
    client.login(stack.username, stack.password, totp_now(stack.otp_secret))
    original_key = client._device_key
    client._device_key = Ed25519PrivateKey.generate()
    with pytest.raises(PermissionError, match="invalid_proof"):
        client.fetch("/")
    client._device_key = original_key
    status, _body, _line = client.fetch("/")
    assert status == 200


def test_revoked_session_is_rejected_by_gateway(stack: LabStack) -> None:
    client = make_client(stack)
    client.login(stack.username, stack.password, totp_now(stack.otp_secret))
    token = client._token
    session_id = client._session_id
    resource = client._resource
    device_id = client._device_id
    binding = client._binding
    client.logout()
    client._token = token
    client._session_id = session_id
    client._resource = resource
    client._device_id = device_id
    client._binding = binding
    with pytest.raises(PermissionError, match="resource_denied"):
        client.fetch("/")


def test_admin_audit_requires_separate_secret_and_omits_credentials(stack: LabStack) -> None:
    assert stack.control is not None
    client = make_client(stack)
    otp = totp_now(stack.otp_secret)
    client.login(stack.username, stack.password, otp)
    status, _ = client._http_json_request(
        stack.control.address,
        "GET",
        "/v1/audit",
        b"",
        content_type="application/json",
    )
    assert status == 401
    status, body = client._http_json_request(
        stack.control.address,
        "GET",
        "/v1/audit",
        b"",
        content_type="application/json",
        extra_headers={"X-Lab-Admin": stack.control.admin_secret},
    )
    assert status == 200
    serialized = body.decode("utf-8")
    assert stack.password not in serialized
    assert otp not in serialized
    assert (client._token or "not-present") not in serialized


def test_stolen_bearer_cannot_refresh_without_the_device_key(stack: LabStack) -> None:
    assert stack.control is not None
    owner = make_client(stack)
    owner.login(stack.username, stack.password, totp_now(stack.otp_secret))
    attacker = make_client(stack)
    attacker._token = owner._token
    attacker._resource = owner._resource
    attacker._session_id = owner._session_id
    attacker._device_id = owner._device_id
    attacker._binding = owner._binding
    status, body = attacker._http_json_request(
        stack.control.address,
        "POST",
        "/v1/heartbeat",
        b"{}",
        content_type="application/json",
        extra_headers=attacker._control_auth_headers("POST", "/v1/heartbeat"),
    )
    assert status == 401
    assert json.loads(body)["error"] == "invalid_device_proof"
    owner.heartbeat()


def _signed_manifest() -> tuple[ManifestSigner, dict[str, object], ManifestBinding]:
    base: dict[str, object] = {
        "version": 1,
        "split_tunnel": True,
        "route_installation": "client-memory-only",
        "resources": [{"id": "demo-resource", "routes": ["10.60.0.0/16"]}],
        "dns": {"demo.internal": "198.18.0.1"},
    }
    manifest = {
        **base,
        "manifest_hash": manifest_digest(base),
        "session": {
            "id": "session-1",
            "virtual_ip": "100.64.0.1",
            "device_id": "device-1",
            "lease_generation": 1,
        },
    }
    signer = ManifestSigner()
    binding = ManifestBinding("session-1", "100.64.0.1", "device-1", 1, "demo-resource")
    return signer, signer.issue(manifest), binding


def test_signed_manifest_detects_tampering() -> None:
    signer, envelope, binding = _signed_manifest()
    verified = signer.verifier().verify(envelope)
    require_manifest_binding(verified, binding)
    tampered = copy.deepcopy(envelope)
    tampered["manifest"]["dns"]["demo.internal"] = "198.18.0.2"
    with pytest.raises(SignedManifestError):
        signer.verifier().verify(tampered)

    bad_digest = copy.deepcopy(envelope["manifest"])
    bad_digest["manifest_hash"] = "0" * 64
    with pytest.raises(SignedManifestError, match="digest"):
        signer.verifier().verify(signer.issue(bad_digest))


def test_dry_run_network_helper_is_transactional_and_never_mutates_os() -> None:
    signer, envelope, binding = _signed_manifest()
    helper = DryRunNetworkHelper(signer.verifier(), binding)
    assert helper.mutates_os is False
    preview = helper.preview(envelope)
    assert preview.before.generation == 0
    assert preview.after.virtual_ip == "100.64.0.1"
    assert helper.snapshot().generation == 0
    applied = helper.apply(envelope)
    assert applied.after.generation == 1
    assert len(applied.added_routes) == 1
    assert helper.apply(envelope).after.generation == 1
    rolled_back = helper.rollback()
    assert rolled_back.after.virtual_ip is None
    assert len(rolled_back.removed_routes) == 1


def test_signed_manifest_cannot_cross_session_or_device_binding() -> None:
    signer, envelope, binding = _signed_manifest()
    wrong_binding = ManifestBinding(
        "another-session",
        binding.virtual_ip,
        binding.device_id,
        binding.lease_generation,
        binding.resource_id,
    )
    with pytest.raises(SignedManifestError, match="different session"):
        DryRunNetworkHelper(signer.verifier(), wrong_binding).preview(envelope)


def test_virtual_ip_is_reused_only_with_a_new_lease_generation() -> None:
    pool = VirtualIPPool("100.64.0.0/30")
    sessions = SessionStore(pool, ttl_seconds=30, absolute_ttl_seconds=30, idle_seconds=15)
    posture = DevicePosture("device", "windows-lab", True, "ztna-lab/0.2", b"k" * 32)
    first = sessions.create("user", posture)
    second = sessions.create("user", posture)
    with pytest.raises(RuntimeError, match="exhausted"):
        sessions.create("user", posture)
    assert sessions.revoke(first.session_id)
    replacement = sessions.create("user", posture)
    assert replacement.virtual_ip == first.virtual_ip
    assert replacement.lease_generation > second.lease_generation


def test_create_scavenges_unobserved_expired_sessions() -> None:
    pool = VirtualIPPool("100.64.0.0/30")
    sessions = SessionStore(pool, ttl_seconds=30, absolute_ttl_seconds=30, idle_seconds=15)
    posture = DevicePosture("device", "windows-lab", True, "ztna-lab/0.2", b"k" * 32)
    first = sessions.create("user", posture)
    second = sessions.create("user", posture)
    first.expires_at = 0
    second.expires_at = 0
    replacement = sessions.create("user", posture)
    assert replacement.virtual_ip in {first.virtual_ip, second.virtual_ip}
    assert replacement.lease_generation > second.lease_generation


def test_l3_packet_enforces_exact_frame_limit() -> None:
    encoded = L3Packet("100.64.0.1", "10.60.0.1", b"x" * MAX_PACKET).encode()
    assert len(encoded) == 64 * 1024
    with pytest.raises(ProtocolError, match="too large"):
        L3Packet("100.64.0.1", "10.60.0.1", b"x" * (MAX_PACKET + 1)).encode()


def test_certificate_directory_must_be_empty() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = __import__("pathlib").Path(directory)
        (path / "existing").write_text("keep", encoding="utf-8")
        with pytest.raises(ValueError):
            create_ephemeral_bundle(path)
