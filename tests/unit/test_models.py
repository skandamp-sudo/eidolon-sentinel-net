"""Tests for the data model hierarchy."""

import time
import uuid

from sentinel_net.models.enums import Direction, Protocol, Severity, ThreatType
from sentinel_net.models.types import (
    DetectionEvent,
    FlowKey,
    ObservedFlow,
    ParsedPacket,
    RawPacket,
)


def test_raw_packet_creation():
    """Test RawPacket instantiation."""
    rp = RawPacket(
        timestamp=1.0,
        raw_bytes=b"\x00\x01\x02",
        wire_length=3,
        capture_length=3,
    )
    assert rp.wire_length == 3
    assert rp.capture_length == 3
    assert rp.interface == "pcap"


def test_parsed_packet_creation():
    """Test ParsedPacket instantiation with correct fields."""
    pp = ParsedPacket(
        timestamp=1.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=80,
        dst_port=443,
        protocol=6,
        protocol_name="TCP",
        ip_version=4,
        ttl=64,
        ip_total_length=100,
        tcp_flags=0x02,
        tcp_window=65535,
        tcp_seq=1000,
        tcp_ack_num=0,
        payload_size=50,
        payload_entropy=3.5,
    )
    assert pp.src_ip == "1.1.1.1"
    assert pp.protocol_name == "TCP"
    assert pp.raw_packet is None  # default


def test_flow_key_creation_and_hashing():
    """Test FlowKey is frozen and hashable."""
    k1 = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)
    k2 = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)

    assert hash(k1) == hash(k2)
    assert k1 == k2
    assert k1 in {k2}  # works as dict key / set member


def test_flow_key_direction_key_is_canonical():
    """Test that direction_key is the same regardless of src/dst order."""
    k1 = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)
    k2 = FlowKey(src_ip="B", dst_ip="A", src_port=2, dst_port=1, protocol=6)

    assert k1.direction_key == k2.direction_key


def test_flow_key_unidirectional_key_preserves_direction():
    """Test that unidirectional_key differs for swapped src/dst."""
    k1 = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)
    k2 = FlowKey(src_ip="B", dst_ip="A", src_port=2, dst_port=1, protocol=6)

    assert k1.unidirectional_key != k2.unidirectional_key


def test_observed_flow_creation():
    """Test ObservedFlow creation and unidirectional semantics."""
    k = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)
    f = ObservedFlow(
        flow_key=k,
        direction="forward",
        start_time=1.0,
        end_time=2.0,
        duration_sec=1.0,
        packet_count=10,
        byte_count=1000,
        payload_byte_count=500,
    )
    assert f.direction == "forward"
    assert f.packets == []
    assert f.is_complete is False
    # Verify docstring mentions passive observation
    assert "ACTUALLY OBSERVED" in ObservedFlow.__doc__
    assert "NOT fabricate" in ObservedFlow.__doc__


def test_detection_event_creation():
    """Test DetectionEvent with optional fields defaulting to None."""
    k = FlowKey(src_ip="A", dst_ip="B", src_port=1, dst_port=2, protocol=6)
    flow = ObservedFlow(
        flow_key=k,
        direction="forward",
        start_time=1.0,
        end_time=2.0,
        duration_sec=1.0,
        packet_count=5,
        byte_count=500,
        payload_byte_count=200,
    )
    event = DetectionEvent(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        flow_key=k,
        observed_flow=flow,
        severity="high",
        rationale="Test detection",
    )
    assert event.feature_vector is None
    assert event.anomaly_result is None
    assert event.threat_classification is None
    assert event.metadata == {}


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_threat_type_enum():
    """Test ThreatType enum values."""
    assert ThreatType.DDOS.value == "ddos"
    assert ThreatType.BENIGN.value == "benign"
    assert ThreatType.UNKNOWN.value == "unknown"
