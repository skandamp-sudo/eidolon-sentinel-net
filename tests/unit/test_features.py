"""Tests for feature extraction engine."""

import numpy as np
import pytest

from sentinel_net.features.extractor import FeatureExtractor, _safe_ratio, _stats
from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA
from sentinel_net.models.types import FlowKey, ObservedFlow


def _make_flow(
    fwd_pkts: int = 5,
    rev_pkts: int = 3,
    fwd_bytes: int = 500,
    rev_bytes: int = 300,
    duration: float = 2.0,
    protocol: int = 6,
    packet_sizes: list[int] | None = None,
    fwd_iats: list[float] | None = None,
    rev_iats: list[float] | None = None,
    **kwargs,
) -> ObservedFlow:
    """Helper to create an ObservedFlow with sensible defaults."""
    key = FlowKey(
        src_ip=kwargs.get("src_ip", "192.168.1.100"),
        dst_ip=kwargs.get("dst_ip", "10.0.0.1"),
        src_port=kwargs.get("src_port", 12345),
        dst_port=kwargs.get("dst_port", 80),
        protocol=protocol,
    )
    if packet_sizes is None:
        packet_sizes = [100] * (fwd_pkts + rev_pkts)
    if fwd_iats is None:
        fwd_iats = [0.1] * max(0, fwd_pkts - 1)
    if rev_iats is None:
        rev_iats = [0.2] * max(0, rev_pkts - 1)

    return ObservedFlow(
        flow_key=key,
        direction="bidirectional" if rev_pkts > 0 else "forward",
        start_time=1000.0,
        end_time=1000.0 + duration,
        duration_sec=duration,
        packet_count=fwd_pkts + rev_pkts,
        byte_count=fwd_bytes + rev_bytes,
        payload_byte_count=kwargs.get("payload_bytes", 400),
        forward_packet_count=fwd_pkts,
        reverse_packet_count=rev_pkts,
        forward_bytes=fwd_bytes,
        reverse_bytes=rev_bytes,
        forward_payload_bytes=kwargs.get("fwd_payload", 250),
        reverse_payload_bytes=kwargs.get("rev_payload", 150),
        syn_count=kwargs.get("syn_count", 1),
        syn_ack_count=kwargs.get("syn_ack_count", 1),
        ack_count=kwargs.get("ack_count", 5),
        fin_count=kwargs.get("fin_count", 1),
        rst_count=kwargs.get("rst_count", 0),
        psh_count=kwargs.get("psh_count", 2),
        forward_iats=fwd_iats,
        reverse_iats=rev_iats,
        packet_sizes=packet_sizes,
        initiator_ip=kwargs.get("src_ip", "192.168.1.100"),
        initiator_port=kwargs.get("src_port", 12345),
    )


# ─── Feature extraction basic ────────────────────────────────────────


def test_extract_returns_feature_vector():
    """FeatureExtractor.extract should return a FeatureVector."""
    extractor = FeatureExtractor()
    flow = _make_flow()
    fv = extractor.extract(flow)

    assert fv.flow_key == flow.flow_key
    assert fv.timestamp == flow.start_time
    assert len(fv.feature_names) == FEATURE_COUNT
    assert len(fv.values) == FEATURE_COUNT
    assert len(fv.features) == FEATURE_COUNT


def test_feature_schema_order():
    """Feature names should match the canonical schema order."""
    extractor = FeatureExtractor()
    fv = extractor.extract(_make_flow())

    assert tuple(fv.feature_names) == FEATURE_SCHEMA


def test_feature_vector_validation():
    """FeatureVector.validate() should return True for well-formed vectors."""
    extractor = FeatureExtractor()
    fv = extractor.extract(_make_flow())
    assert fv.validate() is True


def test_feature_vector_to_numpy():
    """FeatureVector.to_numpy_array() should return a float64 array."""
    extractor = FeatureExtractor()
    fv = extractor.extract(_make_flow())

    arr = fv.to_numpy_array()
    assert isinstance(arr, np.ndarray)
    assert arr.dtype == np.float64
    assert len(arr) == FEATURE_COUNT


# ─── Basic features ──────────────────────────────────────────────────


def test_duration_feature():
    """Duration should match the flow's duration_sec."""
    fv = FeatureExtractor().extract(_make_flow(duration=5.0))
    assert fv.features["duration_sec"] == 5.0


def test_total_packets_feature():
    """total_packets should be sum of forward + reverse."""
    fv = FeatureExtractor().extract(_make_flow(fwd_pkts=10, rev_pkts=5))
    assert fv.features["total_packets"] == 15.0


def test_packets_per_sec():
    """packets_per_sec should be total_packets / duration."""
    fv = FeatureExtractor().extract(_make_flow(fwd_pkts=10, rev_pkts=0, duration=2.0))
    assert abs(fv.features["packets_per_sec"] - 5.0) < 0.001


def test_zero_duration_safe():
    """Zero duration should not cause division by zero."""
    fv = FeatureExtractor().extract(_make_flow(duration=0.0))
    assert fv.features["packets_per_sec"] == 0.0
    assert fv.features["bytes_per_sec"] == 0.0


# ─── Directional features ────────────────────────────────────────────


def test_directional_packet_counts():
    """Forward and reverse packet counts should be correct."""
    fv = FeatureExtractor().extract(_make_flow(fwd_pkts=7, rev_pkts=3))
    assert fv.features["forward_packets"] == 7.0
    assert fv.features["reverse_packets"] == 3.0


def test_directional_ratios():
    """Forward/reverse ratio should be computed correctly."""
    fv = FeatureExtractor().extract(_make_flow(
        fwd_pkts=10, rev_pkts=5, fwd_bytes=1000, rev_bytes=500,
    ))
    assert abs(fv.features["fwd_rev_packet_ratio"] - 2.0) < 0.001
    assert abs(fv.features["fwd_rev_byte_ratio"] - 2.0) < 0.001


def test_zero_reverse_ratio():
    """When reverse is zero, ratio should be 0.0 (safe division)."""
    fv = FeatureExtractor().extract(_make_flow(fwd_pkts=5, rev_pkts=0))
    assert fv.features["fwd_rev_packet_ratio"] == 0.0


# ─── Packet size statistics ──────────────────────────────────────────


def test_packet_size_stats():
    """Packet size statistics should be computed correctly."""
    fv = FeatureExtractor().extract(_make_flow(
        packet_sizes=[100, 200, 300, 400, 500],
    ))
    assert fv.features["pkt_size_mean"] == 300.0
    assert fv.features["pkt_size_min"] == 100.0
    assert fv.features["pkt_size_max"] == 500.0
    assert fv.features["pkt_size_median"] == 300.0


def test_packet_size_single():
    """Single packet should have zero std."""
    fv = FeatureExtractor().extract(_make_flow(
        fwd_pkts=1, rev_pkts=0, packet_sizes=[150],
    ))
    assert fv.features["pkt_size_mean"] == 150.0
    assert fv.features["pkt_size_std"] == 0.0


def test_empty_packet_sizes():
    """Empty packet_sizes should return zeros."""
    fv = FeatureExtractor().extract(_make_flow(packet_sizes=[]))
    assert fv.features["pkt_size_mean"] == 0.0
    assert fv.features["pkt_size_std"] == 0.0


# ─── IAT calculations ────────────────────────────────────────────────


def test_iat_features():
    """IAT features should be computed from forward and reverse IATs."""
    fv = FeatureExtractor().extract(_make_flow(
        fwd_iats=[0.1, 0.1, 0.1, 0.1],
        rev_iats=[0.2, 0.2],
    ))
    assert fv.features["fwd_iat_mean"] == pytest.approx(0.1, abs=0.001)
    assert fv.features["rev_iat_mean"] == pytest.approx(0.2, abs=0.001)
    assert fv.features["fwd_iat_std"] == 0.0  # All identical
    assert fv.features["rev_iat_std"] == 0.0


def test_iat_empty():
    """Zero IATs should produce zero features."""
    fv = FeatureExtractor().extract(_make_flow(fwd_iats=[], rev_iats=[]))
    assert fv.features["fwd_iat_mean"] == 0.0
    assert fv.features["iat_mean"] == 0.0


# ─── TCP flag features ───────────────────────────────────────────────


def test_tcp_flag_features():
    """TCP flag counts should be present in features."""
    flow = _make_flow(syn_count=2, ack_count=10, psh_count=3, fin_count=1, rst_count=0)
    fv = FeatureExtractor().extract(flow)

    assert fv.features["syn_count"] == 2.0
    assert fv.features["ack_count"] == 10.0
    assert fv.features["psh_count"] == 3.0
    assert fv.features["fin_count"] == 1.0
    assert fv.features["rst_count"] == 0.0


def test_tcp_flag_ratios():
    """TCP flag ratios should be relative to total packets."""
    flow = _make_flow(fwd_pkts=8, rev_pkts=2, syn_count=2, ack_count=8)
    fv = FeatureExtractor().extract(flow)

    # syn_ratio = 2/10 = 0.2
    assert abs(fv.features["syn_ratio"] - 0.2) < 0.001
    # ack_ratio = 8/10 = 0.8
    assert abs(fv.features["ack_ratio"] - 0.8) < 0.001


# ─── Protocol features ───────────────────────────────────────────────


def test_protocol_features_tcp():
    """TCP flow should have is_tcp=1, is_udp=0, is_icmp=0."""
    fv = FeatureExtractor().extract(_make_flow(protocol=6))
    assert fv.features["is_tcp"] == 1.0
    assert fv.features["is_udp"] == 0.0
    assert fv.features["is_icmp"] == 0.0
    assert fv.features["protocol"] == 6.0


def test_protocol_features_udp():
    """UDP flow should have is_udp=1."""
    fv = FeatureExtractor().extract(_make_flow(protocol=17))
    assert fv.features["is_tcp"] == 0.0
    assert fv.features["is_udp"] == 1.0


def test_protocol_features_icmp():
    """ICMP flow should have is_icmp=1."""
    fv = FeatureExtractor().extract(_make_flow(
        protocol=1, src_port=None, dst_port=None,
    ))
    assert fv.features["is_icmp"] == 1.0


def test_ipv6_detection():
    """IPv6 addresses should set ip_version to 6."""
    fv = FeatureExtractor().extract(_make_flow(src_ip="2001:db8::1"))
    assert fv.features["ip_version"] == 6.0


# ─── Payload features ────────────────────────────────────────────────


def test_payload_features():
    """Payload byte counts should be present."""
    fv = FeatureExtractor().extract(_make_flow(
        payload_bytes=400, fwd_payload=250, rev_payload=150,
        fwd_bytes=500, rev_bytes=300,
    ))
    assert fv.features["payload_bytes_total"] == 400.0
    assert fv.features["forward_payload_bytes"] == 250.0
    assert fv.features["reverse_payload_bytes"] == 150.0
    assert fv.features["payload_ratio"] == pytest.approx(400.0 / 800.0, abs=0.001)


# ─── Batch extraction ────────────────────────────────────────────────


def test_extract_batch():
    """extract_batch should process multiple flows."""
    extractor = FeatureExtractor()
    flows = [_make_flow() for _ in range(5)]
    fvs = extractor.extract_batch(flows)

    assert len(fvs) == 5
    for fv in fvs:
        assert len(fv.values) == FEATURE_COUNT


# ─── Helper functions ─────────────────────────────────────────────────


def test_safe_ratio_zero_denominator():
    """_safe_ratio should return 0.0 for zero denominator."""
    assert _safe_ratio(10.0, 0.0) == 0.0


def test_safe_ratio_normal():
    """_safe_ratio should compute normal ratio."""
    assert _safe_ratio(10.0, 5.0) == 2.0


def test_stats_empty():
    """_stats of empty list should return zeros."""
    s = _stats([])
    assert s["mean"] == 0.0
    assert s["std"] == 0.0


def test_stats_single():
    """_stats of single value should have zero std."""
    s = _stats([42.0])
    assert s["mean"] == 42.0
    assert s["std"] == 0.0
    assert s["min"] == 42.0
    assert s["max"] == 42.0
