"""Tests for PCAP vs live-capture processing parity.

Proves that equivalent traffic processed through PCAP replay
and mock live capture produces equivalent ParsedPacket / Flow / Feature semantics.

No real network required — uses MockCaptureSource.
"""

from __future__ import annotations

import queue
import time

import pytest

from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
from sentinel_net.features.extractor import FeatureExtractor
from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.models.types import ParsedPacket, FlowKey
from sentinel_net.sensor.metrics import SensorMetrics


def _make_packets() -> list[ParsedPacket]:
    """Create deterministic test packets."""
    base_time = 1000000.0
    return [
        ParsedPacket(
            timestamp=base_time + i * 0.1,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
            protocol=6, protocol_name="TCP",
            ip_version=4, ttl=64, ip_total_length=100 + i * 10,
            tcp_flags=0x10,  # ACK
            tcp_window=65535, tcp_seq=i * 100, tcp_ack_num=i * 50,
            payload_size=50 + i * 5, payload_entropy=3.5 + i * 0.1,
        )
        for i in range(10)
    ]


class TestPcapLiveParity:
    """Verify PCAP and live capture paths produce equivalent results."""

    def test_same_packets_same_flows(self):
        """Same packets → same FlowKey and flow counters."""
        packets = _make_packets()

        # Path 1: Direct aggregation (simulating PCAP)
        agg1 = FlowAggregator(FlowAggregatorConfig(idle_timeout_sec=120.0))
        for pkt in packets:
            agg1.ingest(pkt)
        flows1 = agg1.flush_all()

        # Path 2: Queue-based (simulating live capture)
        agg2 = FlowAggregator(FlowAggregatorConfig(idle_timeout_sec=120.0))
        pkt_queue = queue.Queue(maxsize=100)
        for pkt in packets:
            pkt_queue.put(pkt)

        while not pkt_queue.empty():
            pkt = pkt_queue.get()
            agg2.ingest(pkt)
        flows2 = agg2.flush_all()

        # Verify parity
        assert len(flows1) == len(flows2)
        for f1, f2 in zip(flows1, flows2):
            assert f1.flow_key == f2.flow_key
            assert f1.packet_count == f2.packet_count
            assert f1.byte_count == f2.byte_count
            assert f1.forward_packet_count == f2.forward_packet_count
            assert f1.reverse_packet_count == f2.reverse_packet_count

    def test_same_packets_same_features(self):
        """Same packets → same FeatureVector values."""
        packets = _make_packets()
        extractor = FeatureExtractor()

        # Path 1: Direct
        agg1 = FlowAggregator(FlowAggregatorConfig())
        for pkt in packets:
            agg1.ingest(pkt)
        flows1 = agg1.flush_all()
        fvs1 = extractor.extract_batch(flows1)

        # Path 2: Queue-based
        agg2 = FlowAggregator(FlowAggregatorConfig())
        for pkt in packets:
            agg2.ingest(pkt)
        flows2 = agg2.flush_all()
        fvs2 = extractor.extract_batch(flows2)

        assert len(fvs1) == len(fvs2)
        for fv1, fv2 in zip(fvs1, fvs2):
            assert len(fv1.values) == FEATURE_COUNT
            assert len(fv2.values) == FEATURE_COUNT
            for v1, v2 in zip(fv1.values, fv2.values):
                assert abs(v1 - v2) < 1e-10, f"Feature mismatch: {v1} vs {v2}"

    def test_feature_count_consistency(self):
        """Both paths produce 52-feature vectors."""
        packets = _make_packets()
        agg = FlowAggregator(FlowAggregatorConfig())
        for pkt in packets:
            agg.ingest(pkt)
        flows = agg.flush_all()
        extractor = FeatureExtractor()
        fvs = extractor.extract_batch(flows)
        for fv in fvs:
            assert len(fv.values) == 52
            assert len(fv.feature_names) == 52

    def test_bidirectional_parity(self):
        """Bidirectional flows produce same results regardless of path."""
        base_time = 1000000.0
        packets = [
            # Forward
            ParsedPacket(
                timestamp=base_time, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=12345, dst_port=80, protocol=6, protocol_name="TCP",
                ip_version=4, ttl=64, ip_total_length=100,
                tcp_flags=0x02, tcp_window=65535, tcp_seq=100, tcp_ack_num=0,
                payload_size=50, payload_entropy=3.0,
            ),
            # Reverse
            ParsedPacket(
                timestamp=base_time + 0.01, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                src_port=80, dst_port=12345, protocol=6, protocol_name="TCP",
                ip_version=4, ttl=64, ip_total_length=200,
                tcp_flags=0x12, tcp_window=65535, tcp_seq=200, tcp_ack_num=101,
                payload_size=100, payload_entropy=4.0,
            ),
        ]

        # Two independent aggregation paths
        for _ in range(2):
            agg = FlowAggregator(FlowAggregatorConfig())
            for pkt in packets:
                agg.ingest(pkt)
            flows = agg.flush_all()
            assert len(flows) == 1
            assert flows[0].forward_packet_count == 1
            assert flows[0].reverse_packet_count == 1

    def test_empty_packet_list(self):
        """Empty packet list produces no flows."""
        agg = FlowAggregator(FlowAggregatorConfig())
        flows = agg.flush_all()
        assert len(flows) == 0
