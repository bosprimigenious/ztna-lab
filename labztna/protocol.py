"""Framing for the independent lab data plane.

This is a small, versioned application protocol carried inside an already
authenticated TLS 1.3 connection. It is deliberately not compatible with
Sangfor/aTrust and does not implement raw packet forwarding by itself.
"""

from __future__ import annotations

import json
import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum


MAGIC = b"ZTL1"
VERSION = 1
# magic, version, type, flags, stream id, sequence, payload length
HEADER = struct.Struct("!4sBBHIQI")
MAX_PAYLOAD = 64 * 1024
MAX_FRAME = HEADER.size + MAX_PAYLOAD
FLAG_FIN = 0x0001
FLAG_RST = 0x0002
ALLOWED_FLAGS = FLAG_FIN | FLAG_RST


class FrameType(IntEnum):
    TCP_OPEN = 1
    TCP_DATA = 2
    L3_DATA = 3
    PING = 4
    PONG = 5
    CLOSE = 6


class ProtocolError(ValueError):
    """Raised for malformed, oversized, or out-of-order frames."""


def connection_proof_message(
    *, token: str, resource: str, mode: str, request_id: str, timestamp: int
) -> bytes:
    """Canonical bytes a device signs for one data-plane connection."""

    if not all(isinstance(value, str) for value in (token, resource, mode, request_id)):
        raise ProtocolError("invalid proof fields")
    if (
        mode not in {"tcp", "l3"}
        or not token
        or not (1 <= len(resource) <= 256)
        or not (1 <= len(request_id) <= 128)
        or not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or not (0 <= timestamp <= 4_294_967_295)
    ):
        raise ProtocolError("invalid proof timestamp or request id")
    return json.dumps(
        {
            "mode": mode,
            "request_id": request_id,
            "resource": resource,
            "timestamp": timestamp,
            "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def control_proof_message(
    *, token: str, method: str, path: str, request_id: str, timestamp: int
) -> bytes:
    """Canonical bytes a device signs for one authenticated control request."""

    if (
        not all(isinstance(value, str) for value in (token, method, path, request_id))
        or not token
        or method not in {"GET", "POST"}
        or not path.startswith("/")
        or "\r" in path
        or "\n" in path
        or not (1 <= len(request_id) <= 128)
        or not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or not (0 <= timestamp <= 4_294_967_295)
    ):
        raise ProtocolError("invalid control proof fields")
    return json.dumps(
        {
            "method": method,
            "path": path,
            "request_id": request_id,
            "timestamp": timestamp,
            "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True)
class Frame:
    frame_type: FrameType
    sequence: int
    payload: bytes
    stream_id: int = 0
    flags: int = 0

    def encode(self) -> bytes:
        if not isinstance(self.frame_type, FrameType):
            raise ProtocolError("unknown frame type")
        if not isinstance(self.payload, bytes) or len(self.payload) > MAX_PAYLOAD:
            raise ProtocolError("payload exceeds frame limit")
        if not (0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF):
            raise ProtocolError("sequence out of range")
        if not (0 <= self.stream_id <= 0xFFFFFFFF):
            raise ProtocolError("stream id out of range")
        if self.flags & ~ALLOWED_FLAGS:
            raise ProtocolError("unsupported frame flags")
        _validate_frame_semantics(self)
        return HEADER.pack(
            MAGIC,
            VERSION,
            int(self.frame_type),
            self.flags,
            self.stream_id,
            self.sequence,
            len(self.payload),
        ) + self.payload

    @classmethod
    def decode(cls, encoded: bytes) -> "Frame":
        if len(encoded) < HEADER.size:
            raise ProtocolError("truncated frame")
        magic, version, frame_type, flags, stream_id, sequence, payload_length = HEADER.unpack(
            encoded[: HEADER.size]
        )
        if magic != MAGIC or version != VERSION:
            raise ProtocolError("unsupported frame")
        if payload_length > MAX_PAYLOAD or len(encoded) != HEADER.size + payload_length:
            raise ProtocolError("invalid frame length")
        try:
            kind = FrameType(frame_type)
        except ValueError as exc:
            raise ProtocolError("unknown frame type") from exc
        frame = cls(kind, sequence, encoded[HEADER.size :], stream_id=stream_id, flags=flags)
        # Reuse encode-time invariant checks without returning another copy.
        frame.encode()
        return frame


class FrameCodec:
    """Incremental decoder with sequence and per-stream state enforcement."""

    def __init__(self, *, max_frames: int = 10_000) -> None:
        self._buffer = bytearray()
        self._next_sequence: dict[int, int] = {}
        self._stream_kind: dict[int, str] = {}
        self._closed_streams: set[int] = set()
        self._connection_closed = False
        self._frames = 0
        if max_frames <= 0:
            raise ValueError("max_frames must be positive")
        self._max_frames = max_frames

    def next_sequence(self, stream_id: int = 0) -> int:
        return self._next_sequence.get(stream_id, 0)

    def finish(self) -> None:
        """Reject an EOF that arrived in the middle of a frame."""

        if self._buffer:
            raise ProtocolError("truncated frame at end of stream")
        if any(
            kind == "tcp" and stream_id not in self._closed_streams
            for stream_id, kind in self._stream_kind.items()
        ):
            raise ProtocolError("TCP stream ended without FIN or RST")

    def feed(self, data: bytes) -> list[Frame]:
        if not isinstance(data, bytes):
            raise ProtocolError("frame input must be bytes")
        self._buffer.extend(data)
        frames: list[Frame] = []
        while len(self._buffer) >= HEADER.size:
            magic, version, _kind, _flags, stream_id, _sequence, payload_length = HEADER.unpack(
                self._buffer[: HEADER.size]
            )
            if magic != MAGIC or version != VERSION:
                raise ProtocolError("unsupported frame")
            if payload_length > MAX_PAYLOAD:
                raise ProtocolError("payload exceeds frame limit")
            total = HEADER.size + payload_length
            if len(self._buffer) < total:
                break
            raw = bytes(self._buffer[:total])
            del self._buffer[:total]
            frame = Frame.decode(raw)
            expected = self._next_sequence.get(stream_id, 0)
            if frame.sequence != expected:
                raise ProtocolError("sequence replay or gap")
            self._advance_stream_state(frame)
            self._next_sequence[stream_id] = expected + 1
            self._frames += 1
            if self._frames > self._max_frames:
                raise ProtocolError("frame count exceeds limit")
            frames.append(frame)
        # A remaining partial frame can never legitimately exceed one maximum
        # frame. Complete frames have already been consumed above.
        if len(self._buffer) > MAX_FRAME:
            raise ProtocolError("decoder buffer exceeds limit")
        return frames

    def _advance_stream_state(self, frame: Frame) -> None:
        if self._connection_closed:
            raise ProtocolError("frame received after connection close")
        if frame.stream_id == 0:
            if frame.frame_type == FrameType.CLOSE:
                self._connection_closed = True
            return
        if frame.stream_id in self._closed_streams:
            raise ProtocolError("frame received for a closed stream")
        kind = self._stream_kind.get(frame.stream_id)
        if frame.frame_type == FrameType.TCP_OPEN:
            if kind is not None or frame.sequence != 0:
                raise ProtocolError("TCP stream is already open")
            self._stream_kind[frame.stream_id] = "tcp"
            return
        if frame.frame_type == FrameType.TCP_DATA:
            if kind != "tcp":
                raise ProtocolError("TCP data requires an open TCP stream")
            if frame.flags & (FLAG_FIN | FLAG_RST):
                self._closed_streams.add(frame.stream_id)
            return
        if frame.frame_type == FrameType.L3_DATA:
            if kind not in {None, "l3"}:
                raise ProtocolError("cannot mix L3 and TCP frames on one stream")
            self._stream_kind[frame.stream_id] = "l3"


def _validate_frame_semantics(frame: Frame) -> None:
    if frame.frame_type in {FrameType.PING, FrameType.PONG, FrameType.CLOSE}:
        if frame.stream_id != 0 or frame.flags:
            raise ProtocolError("control frames must use stream zero without flags")
        return
    if frame.stream_id == 0:
        raise ProtocolError("data frames require a nonzero stream id")
    if frame.frame_type in {FrameType.TCP_OPEN, FrameType.L3_DATA} and frame.flags:
        raise ProtocolError("frame type does not permit flags")
    if frame.frame_type == FrameType.TCP_DATA:
        if frame.flags == ALLOWED_FLAGS:
            raise ProtocolError("TCP FIN and RST cannot be combined")
        if frame.flags & FLAG_RST and frame.payload:
            raise ProtocolError("TCP reset frames cannot carry payload")


def encode_control(
    kind: FrameType,
    sequence: int,
    value: dict[str, object],
    *,
    stream_id: int = 0,
) -> Frame:
    """Encode a bounded JSON control payload (open/ping/close)."""

    if kind not in {FrameType.TCP_OPEN, FrameType.PING, FrameType.PONG, FrameType.CLOSE}:
        raise ProtocolError("invalid control frame type")
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(payload) > 8 * 1024:
        raise ProtocolError("control payload exceeds limit")
    if kind == FrameType.TCP_OPEN and stream_id == 0:
        raise ProtocolError("TCP open requires a nonzero stream id")
    if kind != FrameType.TCP_OPEN and stream_id != 0:
        raise ProtocolError("control frames require stream zero")
    return Frame(kind, sequence, payload, stream_id=stream_id)


def decode_control(frame: Frame) -> dict[str, object]:
    if frame.frame_type not in {FrameType.TCP_OPEN, FrameType.PING, FrameType.PONG, FrameType.CLOSE}:
        raise ProtocolError("not a control frame")
    try:
        value = json.loads(frame.payload.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid control JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("control payload must be an object")
    return value
