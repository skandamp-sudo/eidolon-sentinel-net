"""Tests for packet parser functions."""

from scapy.all import ARP, Ether, IP, TCP, UDP

from sentinel_net.ingestion.parser import compute_entropy, extract_raw_packet, parse_packet
from sentinel_net.models.types import RawPacket


def test_compute_entropy_empty():
    """Entropy of empty bytes should be 0.0."""
    assert compute_entropy(b"") == 0.0


def test_compute_entropy_uniform():
    """Entropy of uniform bytes should be 0.0."""
    assert compute_entropy(b"AAAA") == 0.0


def test_compute_entropy_varied():
    """Entropy of 256 distinct byte values should approach 8.0."""
    assert compute_entropy(bytes(range(256))) > 7.9


def test_compute_entropy_binary():
    """Entropy of two equally distributed values should be 1.0."""
    assert compute_entropy(b"\x00\xff" * 50) == 1.0


def test_extract_raw_packet():
    """extract_raw_packet produces a valid RawPacket."""
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=443)
    raw_pkt = extract_raw_packet(pkt)

    assert isinstance(raw_pkt, RawPacket)
    assert raw_pkt.wire_length > 0
    assert raw_pkt.capture_length > 0
    assert len(raw_pkt.raw_bytes) == raw_pkt.capture_length


def test_parse_tcp_packet():
    """Parse an Ethernet/IP/TCP packet with payload."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=443) / b"payload"
    raw_pkt = extract_raw_packet(pkt)
    parsed = parse_packet(raw_pkt)

    assert parsed is not None
    assert parsed.src_ip == "1.1.1.1"
    assert parsed.dst_ip == "2.2.2.2"
    assert parsed.protocol == 6
    assert parsed.protocol_name == "TCP"
    assert parsed.src_port == 80
    assert parsed.dst_port == 443
    assert parsed.ip_version == 4
    assert parsed.tcp_flags is not None
    assert parsed.tcp_window is not None
    assert parsed.payload_size == len(b"payload")
    assert parsed.payload_entropy > 0.0
    assert parsed.raw_packet is raw_pkt


def test_parse_udp_packet():
    """Parse an Ethernet/IP/UDP packet."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=53) / b"dns"
    raw_pkt = extract_raw_packet(pkt)
    parsed = parse_packet(raw_pkt)

    assert parsed is not None
    assert parsed.protocol == 17
    assert parsed.protocol_name == "UDP"
    assert parsed.src_port == 53
    assert parsed.tcp_flags is None  # UDP has no TCP flags
    assert parsed.tcp_window is None


def test_parse_non_ip_returns_none():
    """Non-IP packets (ARP) should return None."""
    pkt = Ether() / ARP()
    raw_pkt = extract_raw_packet(pkt)
    parsed = parse_packet(raw_pkt)

    assert parsed is None
