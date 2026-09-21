"""Tests for the end-to-end PCAP processing pipeline."""

from pathlib import Path

import numpy as np
import pytest
from scapy.all import ARP, Ether, IP, TCP, UDP, wrpcap

from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.pipeline import PcapPipeline, PipelineConfig, PipelineResult


@pytest.fixture
def simple_pcap(tmp_path: Path) -> Path:
    """Generate a simple PCAP with known traffic patterns."""
    path = tmp_path / "simple.pcap"
    pkts = [
        # TCP handshake: client → server
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S"),
        # TCP handshake: server → client
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA"),
        # TCP data: client → server
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="PA") / b"GET / HTTP/1.1",
        # TCP data: server → client
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="PA") / (b"A" * 500),
        # TCP FIN: client → server
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="FA"),
    ]
    # Set deterministic timestamps
    for i, pkt in enumerate(pkts):
        pkt.time = 1000.0 + i * 0.1
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def multi_flow_pcap(tmp_path: Path) -> Path:
    """PCAP with multiple distinct flows."""
    path = tmp_path / "multi.pcap"
    pkts = []
    base_time = 1000.0

    # Flow 1: TCP 10.0.0.1:1000 → 10.0.0.2:80
    for i in range(3):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="PA") / b"data"
        pkt.time = base_time + i * 0.1
        pkts.append(pkt)

    # Flow 2: UDP 10.0.0.1:5000 → 8.8.8.8:53
    for i in range(2):
        pkt = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=53) / b"dns"
        pkt.time = base_time + 1.0 + i * 0.1
        pkts.append(pkt)

    # Non-IP packet (should be skipped)
    arp = Ether() / ARP()
    arp.time = base_time + 2.0
    pkts.append(arp)

    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def empty_pcap(tmp_path: Path) -> Path:
    """PCAP with only non-IP packets."""
    path = tmp_path / "empty.pcap"
    arp = Ether() / ARP()
    arp.time = 1000.0
    wrpcap(str(path), [arp])
    return path


# ─── Basic pipeline ──────────────────────────────────────────────────


def test_pipeline_produces_results(simple_pcap: Path):
    """Pipeline should produce flows and feature vectors."""
    pipeline = PcapPipeline()
    result = pipeline.process(simple_pcap)

    assert isinstance(result, PipelineResult)
    assert result.total_flows >= 1
    assert len(result.flows) == result.total_flows
    assert len(result.feature_vectors) == result.total_flows
    assert result.processing_time_sec > 0.0


def test_pipeline_packet_counts(simple_pcap: Path):
    """Pipeline should report correct packet counts."""
    result = PcapPipeline().process(simple_pcap)

    assert result.total_packets == 5
    assert result.parsed_packets == 5  # All IP
    assert result.skipped_packets == 0


def test_pipeline_bidirectional_flow(simple_pcap: Path):
    """TCP handshake PCAP should produce a bidirectional flow."""
    result = PcapPipeline().process(simple_pcap)

    assert result.total_flows == 1
    f = result.flows[0]
    assert f.forward_packet_count == 3  # SYN, PA, FA
    assert f.reverse_packet_count == 2  # SA, PA
    assert f.direction == "bidirectional"
    assert f.syn_count == 1
    assert f.syn_ack_count == 1
    assert f.fin_count == 1
    assert f.is_complete is True


# ─── Multi-flow pipeline ─────────────────────────────────────────────


def test_pipeline_multiple_flows(multi_flow_pcap: Path):
    """Pipeline should separate distinct flows."""
    result = PcapPipeline().process(multi_flow_pcap)

    assert result.total_flows == 2  # TCP + UDP
    assert result.parsed_packets == 5  # 3 TCP + 2 UDP
    assert result.skipped_packets == 1  # 1 ARP


# ─── Feature vector properties ───────────────────────────────────────


def test_pipeline_feature_vector_shape(simple_pcap: Path):
    """Feature vectors should have the correct number of features."""
    result = PcapPipeline().process(simple_pcap)

    for fv in result.feature_vectors:
        assert len(fv.values) == FEATURE_COUNT
        assert len(fv.feature_names) == FEATURE_COUNT
        assert fv.validate() is True


def test_pipeline_numpy_conversion(simple_pcap: Path):
    """Feature vectors should convert to numpy arrays."""
    result = PcapPipeline().process(simple_pcap)

    for fv in result.feature_vectors:
        arr = fv.to_numpy_array()
        assert arr.dtype == np.float64
        assert len(arr) == FEATURE_COUNT
        # No NaN values
        assert not np.any(np.isnan(arr))


# ─── Empty PCAP ──────────────────────────────────────────────────────


def test_pipeline_empty_pcap(empty_pcap: Path):
    """PCAP with only non-IP packets should produce no flows."""
    result = PcapPipeline().process(empty_pcap)

    assert result.total_flows == 0
    assert result.flows == []
    assert result.feature_vectors == []
    assert result.parsed_packets == 0
    assert result.skipped_packets == 1


# ─── Repeated replay ─────────────────────────────────────────────────


def test_pipeline_repeated_replay(simple_pcap: Path):
    """Running the pipeline twice on the same PCAP should give identical results."""
    pipeline = PcapPipeline()

    r1 = pipeline.process(simple_pcap)
    r2 = pipeline.process(simple_pcap)

    assert r1.total_flows == r2.total_flows
    assert r1.parsed_packets == r2.parsed_packets
    assert r1.skipped_packets == r2.skipped_packets

    for fv1, fv2 in zip(r1.feature_vectors, r2.feature_vectors):
        assert fv1.values == fv2.values


# ─── Pipeline with test fixture ──────────────────────────────────────


def test_pipeline_with_test_fixture():
    """Pipeline should process the Phase 1 test fixture PCAP."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "test_traffic.pcap"
    if not fixture_path.exists():
        pytest.skip("Test fixture not generated yet")

    result = PcapPipeline().process(fixture_path)

    # 22 total packets: 5 SYN + 3 SA + 10 data + 2 UDP + 1 ICMP + 1 ARP
    assert result.total_packets == 22
    assert result.skipped_packets == 1  # ARP
    assert result.parsed_packets == 21
    assert result.total_flows >= 2  # TCP + UDP + ICMP flows
    assert len(result.feature_vectors) == result.total_flows

    # Verify no NaN in any feature vector
    for fv in result.feature_vectors:
        arr = fv.to_numpy_array()
        assert not np.any(np.isnan(arr))


# ─── Pipeline config ─────────────────────────────────────────────────


def test_pipeline_config_store_packets(simple_pcap: Path):
    """store_packets config should be passed through."""
    config = PipelineConfig(store_packets=True)
    result = PcapPipeline(config).process(simple_pcap)

    for f in result.flows:
        assert len(f.packets) > 0


def test_pipeline_config_default_no_packets(simple_pcap: Path):
    """Default config should not store packets."""
    result = PcapPipeline().process(simple_pcap)

    for f in result.flows:
        assert f.packets == []
