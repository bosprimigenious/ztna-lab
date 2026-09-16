"""User-space L3 packet model used for testing route/policy behavior.

No raw sockets or system interfaces are opened. A deployment adapter may map
these frames to a real WireGuard/IPsec interface after an independent review.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .protocol import MAX_PAYLOAD, Frame, FrameType, ProtocolError
from .routeplan import RoutePlan


MAX_PACKET = MAX_PAYLOAD - 12


@dataclass(frozen=True)
class L3Packet:
    source: str
    destination: str
    payload: bytes

    def encode(self) -> bytes:
        if len(self.payload) > MAX_PACKET:
            raise ProtocolError("L3 packet too large")
        try:
            source = ipaddress.ip_address(self.source)
            destination = ipaddress.ip_address(self.destination)
        except ValueError as exc:
            raise ProtocolError("invalid L3 address") from exc
        if source.version != 4 or destination.version != 4:
            raise ProtocolError("lab L3 packets must be IPv4")
        source_bytes = source.packed
        destination_bytes = destination.packed
        return source_bytes + destination_bytes + len(self.payload).to_bytes(4, "big") + self.payload

    @classmethod
    def decode(cls, encoded: bytes) -> "L3Packet":
        if len(encoded) < 12:
            raise ProtocolError("truncated L3 packet")
        source = str(ipaddress.ip_address(encoded[:4]))
        destination = str(ipaddress.ip_address(encoded[4:8]))
        length = int.from_bytes(encoded[8:12], "big")
        if length > MAX_PACKET or length != len(encoded) - 12:
            raise ProtocolError("invalid L3 packet length")
        return cls(source, destination, encoded[12:])


def packet_to_frame(sequence: int, packet: L3Packet, plan: RoutePlan) -> Frame:
    route = plan.lookup(packet.destination)
    if route is None:
        raise PermissionError("destination is outside the authorized route plan")
    if packet.source != plan.virtual_ip:
        raise PermissionError("source is not the allocated virtual IP")
    return Frame(FrameType.L3_DATA, sequence, packet.encode(), stream_id=1)


def frame_to_packet(frame: Frame, plan: RoutePlan) -> L3Packet:
    if frame.frame_type != FrameType.L3_DATA:
        raise ProtocolError("expected L3 data frame")
    packet = L3Packet.decode(frame.payload)
    route = plan.lookup(packet.destination)
    if route is None or packet.source != plan.virtual_ip:
        raise PermissionError("packet violates the route plan")
    return packet
