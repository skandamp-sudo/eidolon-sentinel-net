"""
Packet parsing module for EIDOLON // SENTINEL-NET.

CRITICAL SECURITY REQUIREMENT: This module performs READ-ONLY packet inspection.
It has NO capability to capture live traffic, send packets, or interact with
any network interface.
"""

import logging
import math
import time
from typing import Any

from scapy.all import Ether, raw
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from sentinel_net.models.types import ParsedPacket, RawPacket

logger = logging.getLogger(__name__)

# Protocol number -> name mapping
_PROTO_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte string.

    Args:
        data: The byte string to compute entropy for.

    Returns:
        Shannon entropy in bits (0.0 to 8.0). Returns 0.0 for empty data.
    """
    if not data:
        return 0.0

    length = len(data)
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1

    entropy = 0.0
    for count in counts.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy


def extract_raw_packet(scapy_packet: Any) -> RawPacket:
    """Extract raw bytes and metadata from a scapy packet into a RawPacket.

    Args:
        scapy_packet: A scapy packet object (from PcapReader or constructed).

    Returns:
        RawPacket with raw bytes and capture metadata.
    """
    raw_bytes = raw(scapy_packet)
    timestamp = float(scapy_packet.time) if hasattr(scapy_packet, "time") else time.time()
    wire_len = getattr(scapy_packet, "wirelen", None) or len(raw_bytes)

    return RawPacket(
        timestamp=timestamp,
        raw_bytes=raw_bytes,
        wire_length=wire_len,
        capture_length=len(raw_bytes),
        interface="pcap",
    )


def parse_packet(raw_pkt: RawPacket) -> ParsedPacket | None:
    """Parse a RawPacket into a structured ParsedPacket.

    Reconstructs the scapy packet from raw bytes, extracts IP/transport
    layer fields, and computes payload entropy.

    Args:
        raw_pkt: The raw packet to parse.

    Returns:
        ParsedPacket if the packet contains an IP layer, None otherwise
        (e.g., ARP packets return None).
    """
    try:
        pkt = Ether(raw_pkt.raw_bytes)
    except Exception:
        # Try raw IP if Ether decoding fails
        try:
            pkt = IP(raw_pkt.raw_bytes)
        except Exception:
            return None

    # Extract IP layer
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_protocol = int(ip_layer.proto)
        ip_version = 4
        ttl = int(ip_layer.ttl)
        ip_total_length = int(ip_layer.len) if ip_layer.len else len(raw_pkt.raw_bytes)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_protocol = int(ip_layer.nh)
        ip_version = 6
        ttl = int(ip_layer.hlim)
        ip_total_length = int(ip_layer.plen) + 40  # payload len + IPv6 header
    else:
        return None  # Non-IP packet (ARP, etc.)

    # Determine protocol name
    protocol_name = _PROTO_NAMES.get(ip_protocol, f"PROTO_{ip_protocol}")

    # Extract transport layer fields
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    tcp_window: int | None = None
    tcp_seq: int | None = None
    tcp_ack_num: int | None = None
    payload_bytes = b""

    if TCP in pkt:
        tcp_layer = pkt[TCP]
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = int(tcp_layer.flags)
        tcp_window = int(tcp_layer.window)
        tcp_seq = int(tcp_layer.seq)
        tcp_ack_num = int(tcp_layer.ack)
        protocol_name = "TCP"
        payload_bytes = bytes(tcp_layer.payload)
    elif UDP in pkt:
        udp_layer = pkt[UDP]
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        protocol_name = "UDP"
        payload_bytes = bytes(udp_layer.payload)
    elif ICMP in pkt:
        icmp_layer = pkt[ICMP]
        protocol_name = "ICMP"
        payload_bytes = bytes(icmp_layer.payload)
    else:
        # Unknown transport — extract payload from IP layer
        payload_bytes = bytes(ip_layer.payload)

    return ParsedPacket(
        timestamp=raw_pkt.timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=ip_protocol,
        protocol_name=protocol_name,
        ip_version=ip_version,
        ttl=ttl,
        ip_total_length=ip_total_length,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        tcp_seq=tcp_seq,
        tcp_ack_num=tcp_ack_num,
        payload_size=len(payload_bytes),
        payload_entropy=compute_entropy(payload_bytes),
        raw_packet=raw_pkt,
    )
