"""Tests for flow aggregation engine."""

import pytest

from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
from sentinel_net.models.types import FlowKey, ParsedPacket


def _make_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int | None = 12345,
    dst_port: int | None = 80,
    protocol: int = 6,
    timestamp: float = 1000.0,
    ip_total_length: int = 100,
    payload_size: int = 50,
    tcp_flags: int | None = 0x10,  # ACK
    **kwargs,
) -> ParsedPacket:
    """Helper to create a ParsedPacket with sensible defaults."""
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        protocol_name="TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP",
        ip_version=kwargs.get("ip_version", 4),
        ttl=kwargs.get("ttl", 64),
        ip_total_length=ip_total_length,
        tcp_flags=tcp_flags,
        tcp_window=kwargs.get("tcp_window", 65535),
        tcp_seq=kwargs.get("tcp_seq"),
        tcp_ack_num=kwargs.get("tcp_ack_num"),
        payload_size=payload_size,
        payload_entropy=kwargs.get("payload_entropy", 3.5),
    )


# ─── Single packet flow ───────────────────────────────────────────────


def test_single_packet_flow():
    """A single packet should create a flow with 1 forward packet."""
    agg = FlowAggregator()
    pkt = _make_packet(timestamp=1000.0)
    agg.ingest(pkt)

    flows = agg.flush_all()
    assert len(flows) == 1

    f = flows[0]
    assert f.forward_packet_count == 1
    assert f.reverse_packet_count == 0
    assert f.packet_count == 1
    assert f.direction == "forward"
    assert f.start_time == 1000.0
    assert f.end_time == 1000.0
    assert f.duration_sec == 0.0


# ─── Multi-packet flow ────────────────────────────────────────────────


def test_multi_packet_forward_only():
    """Multiple packets in same direction should accumulate."""
    agg = FlowAggregator()
    for i in range(5):
        agg.ingest(_make_packet(timestamp=1000.0 + i * 0.1, ip_total_length=100))

    flows = agg.flush_all()
    assert len(flows) == 1

    f = flows[0]
    assert f.forward_packet_count == 5
    assert f.reverse_packet_count == 0
    assert f.packet_count == 5
    assert f.byte_count == 500
    assert f.direction == "forward"
    assert abs(f.duration_sec - 0.4) < 0.001


# ─── Forward + reverse traffic ────────────────────────────────────────


def test_bidirectional_flow():
    """Forward and reverse packets should group into one flow."""
    agg = FlowAggregator()

    # Forward: client → server
    agg.ingest(_make_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.1",
        src_port=12345, dst_port=80,
        timestamp=1000.0, ip_total_length=60, tcp_flags=0x02,  # SYN
    ))
    # Reverse: server → client
    agg.ingest(_make_packet(
        src_ip="10.0.0.1", dst_ip="192.168.1.100",
        src_port=80, dst_port=12345,
        timestamp=1000.1, ip_total_length=60, tcp_flags=0x12,  # SYN+ACK
    ))
    # Forward: client → server
    agg.ingest(_make_packet(
        src_ip="192.168.1.100", dst_ip="10.0.0.1",
        src_port=12345, dst_port=80,
        timestamp=1000.2, ip_total_length=200, tcp_flags=0x18,  # PSH+ACK
    ))

    flows = agg.flush_all()
    assert len(flows) == 1

    f = flows[0]
    assert f.forward_packet_count == 2
    assert f.reverse_packet_count == 1
    assert f.packet_count == 3
    assert f.direction == "bidirectional"
    assert f.forward_bytes == 260  # 60 + 200
    assert f.reverse_bytes == 60
    assert f.initiator_ip == "192.168.1.100"


# ─── Multiple simultaneous flows ─────────────────────────────────────


def test_multiple_simultaneous_flows():
    """Packets for different conversations should create separate flows."""
    agg = FlowAggregator()

    # Flow 1: client → server A
    agg.ingest(_make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, timestamp=1000.0))
    agg.ingest(_make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, timestamp=1000.1))

    # Flow 2: client → server B
    agg.ingest(_make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.3", dst_port=443, timestamp=1000.0))

    # Flow 3: different protocol
    agg.ingest(_make_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80,
        protocol=17, tcp_flags=None, timestamp=1000.0,
    ))

    flows = agg.flush_all()
    assert len(flows) == 3


# ─── IPv6 support ─────────────────────────────────────────────────────


def test_ipv6_flow():
    """IPv6 addresses should be supported."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(
        src_ip="2001:db8::1", dst_ip="2001:db8::2",
        src_port=12345, dst_port=80,
        ip_version=6, timestamp=1000.0,
    ))

    flows = agg.flush_all()
    assert len(flows) == 1
    assert flows[0].flow_key.src_ip == "2001:db8::1"
    assert flows[0].initiator_ip == "2001:db8::1"


# ─── TCP flag counting ────────────────────────────────────────────────


def test_tcp_flag_counting():
    """TCP flags should be counted from bitmask."""
    agg = FlowAggregator()

    # SYN
    agg.ingest(_make_packet(tcp_flags=0x02, timestamp=1000.0))
    # SYN+ACK (reverse)
    agg.ingest(_make_packet(
        src_ip="10.0.0.1", dst_ip="192.168.1.100",
        src_port=80, dst_port=12345,
        tcp_flags=0x12, timestamp=1000.1,
    ))
    # ACK
    agg.ingest(_make_packet(tcp_flags=0x10, timestamp=1000.2))
    # PSH+ACK
    agg.ingest(_make_packet(tcp_flags=0x18, timestamp=1000.3))
    # FIN+ACK
    agg.ingest(_make_packet(tcp_flags=0x11, timestamp=1000.4))
    # RST
    agg.ingest(_make_packet(tcp_flags=0x04, timestamp=1000.5))

    flows = agg.flush_all()
    assert len(flows) == 1

    f = flows[0]
    assert f.syn_count == 1
    assert f.syn_ack_count == 1
    assert f.ack_count == 4  # SYN+ACK, ACK, PSH+ACK, FIN+ACK all have ACK bit
    assert f.psh_count == 1
    assert f.fin_count == 1
    assert f.rst_count == 1
    assert f.is_complete is True  # FIN/RST seen
    assert f.tcp_flag_counts["SYN"] == 1
    assert f.tcp_flag_counts["RST"] == 1


# ─── UDP flow ─────────────────────────────────────────────────────────


def test_udp_flow():
    """UDP packets should aggregate without TCP flag counting."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(
        protocol=17, tcp_flags=None,
        src_port=54321, dst_port=53,
        timestamp=1000.0,
    ))
    agg.ingest(_make_packet(
        protocol=17, tcp_flags=None,
        src_ip="10.0.0.1", dst_ip="192.168.1.100",
        src_port=53, dst_port=54321,
        timestamp=1000.1,
    ))

    flows = agg.flush_all()
    assert len(flows) == 1

    f = flows[0]
    assert f.forward_packet_count == 1
    assert f.reverse_packet_count == 1
    assert f.syn_count == 0
    assert f.is_complete is False


# ─── ICMP flow ────────────────────────────────────────────────────────


def test_icmp_flow():
    """ICMP packets (no ports) should aggregate correctly."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(
        protocol=1, tcp_flags=None,
        src_port=None, dst_port=None,
        timestamp=1000.0,
    ))
    agg.ingest(_make_packet(
        protocol=1, tcp_flags=None,
        src_port=None, dst_port=None,
        timestamp=1000.5,
    ))

    flows = agg.flush_all()
    assert len(flows) == 1
    assert flows[0].flow_key.src_port is None
    assert flows[0].flow_key.dst_port is None
    assert flows[0].packet_count == 2


# ─── Byte and packet counts ──────────────────────────────────────────


def test_byte_packet_counts():
    """Byte and packet counts should match exactly."""
    agg = FlowAggregator()

    sizes = [100, 200, 300]
    payloads = [50, 100, 150]
    for i, (sz, pl) in enumerate(zip(sizes, payloads)):
        agg.ingest(_make_packet(
            ip_total_length=sz, payload_size=pl, timestamp=1000.0 + i,
        ))

    flows = agg.flush_all()
    f = flows[0]
    assert f.packet_count == 3
    assert f.byte_count == 600
    assert f.payload_byte_count == 300
    assert f.forward_bytes == 600
    assert f.forward_payload_bytes == 300


# ─── Flow duration ────────────────────────────────────────────────────


def test_flow_duration():
    """Duration should be last_seen - first_seen."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(timestamp=1000.0))
    agg.ingest(_make_packet(timestamp=1005.5))

    flows = agg.flush_all()
    assert abs(flows[0].duration_sec - 5.5) < 0.001


# ─── Idle timeout ─────────────────────────────────────────────────────


def test_idle_timeout_expires_flow():
    """Flows idle beyond timeout should be expired."""
    config = FlowAggregatorConfig(idle_timeout_sec=10.0)
    agg = FlowAggregator(config)

    agg.ingest(_make_packet(timestamp=1000.0))
    assert agg.active_flow_count == 1

    # Expire with time far in the future
    expired = agg.expire_idle(current_time=1020.0)
    assert expired == 1
    assert agg.active_flow_count == 0
    assert agg.completed_flow_count == 1


def test_idle_timeout_does_not_expire_active():
    """Flows within timeout should NOT be expired."""
    config = FlowAggregatorConfig(idle_timeout_sec=10.0)
    agg = FlowAggregator(config)

    agg.ingest(_make_packet(timestamp=1000.0))
    expired = agg.expire_idle(current_time=1005.0)  # Within timeout
    assert expired == 0
    assert agg.active_flow_count == 1


# ─── Flow expiration and deterministic ordering ──────────────────────


def test_deterministic_ordering():
    """Flushed flows should be sorted by start_time."""
    agg = FlowAggregator()

    # Create flows in reverse timestamp order
    agg.ingest(_make_packet(
        src_ip="10.0.0.3", dst_ip="10.0.0.4", dst_port=443,
        timestamp=3000.0,
    ))
    agg.ingest(_make_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80,
        timestamp=1000.0,
    ))
    agg.ingest(_make_packet(
        src_ip="10.0.0.5", dst_ip="10.0.0.6", dst_port=8080,
        timestamp=2000.0,
    ))

    flows = agg.flush_all()
    assert len(flows) == 3
    assert flows[0].start_time == 1000.0
    assert flows[1].start_time == 2000.0
    assert flows[2].start_time == 3000.0


# ─── Max active flows (bounded memory) ───────────────────────────────


def test_max_active_flows_eviction():
    """When max_active_flows is reached, the oldest flow should be evicted."""
    config = FlowAggregatorConfig(max_active_flows=3)
    agg = FlowAggregator(config)

    # Create 4 distinct flows
    for i in range(4):
        agg.ingest(_make_packet(
            src_ip=f"10.0.0.{i}", dst_ip="10.0.0.100",
            dst_port=80 + i, timestamp=1000.0 + i,
        ))

    # Should have evicted 1 flow
    assert agg.active_flow_count == 3
    assert agg.completed_flow_count == 1


# ─── Store packets config ────────────────────────────────────────────


def test_store_packets_disabled():
    """When store_packets is False, packets should not be retained."""
    config = FlowAggregatorConfig(store_packets=False)
    agg = FlowAggregator(config)

    agg.ingest(_make_packet())
    flows = agg.flush_all()
    assert flows[0].packets == []


def test_store_packets_enabled():
    """When store_packets is True, packets should be retained."""
    config = FlowAggregatorConfig(store_packets=True)
    agg = FlowAggregator(config)

    agg.ingest(_make_packet())
    agg.ingest(_make_packet(timestamp=1000.1))
    flows = agg.flush_all()
    assert len(flows[0].packets) == 2


# ─── Forward IAT tracking ────────────────────────────────────────────


def test_forward_iats():
    """Forward inter-arrival times should be computed."""
    agg = FlowAggregator()

    for i in range(4):
        agg.ingest(_make_packet(timestamp=1000.0 + i * 0.5))

    flows = agg.flush_all()
    f = flows[0]
    assert len(f.forward_iats) == 3
    for iat in f.forward_iats:
        assert abs(iat - 0.5) < 0.001


# ─── Packet sizes tracking ───────────────────────────────────────────


def test_packet_sizes_tracked():
    """Packet sizes should be recorded for statistics."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(ip_total_length=100, timestamp=1000.0))
    agg.ingest(_make_packet(ip_total_length=200, timestamp=1000.1))
    agg.ingest(_make_packet(ip_total_length=300, timestamp=1000.2))

    flows = agg.flush_all()
    assert flows[0].packet_sizes == [100, 200, 300]


# ─── Properties ───────────────────────────────────────────────────────


def test_aggregator_properties():
    """Verify counter properties."""
    agg = FlowAggregator()

    assert agg.total_packets_processed == 0
    assert agg.total_flows_created == 0
    assert agg.total_flows_expired == 0

    agg.ingest(_make_packet())
    assert agg.total_packets_processed == 1
    assert agg.total_flows_created == 1

    agg.flush_all()
    assert agg.total_flows_expired == 1


# ─── ObservedFlow total_packets/total_bytes properties ────────────────


def test_observed_flow_properties():
    """Test the total_packets and total_bytes computed properties."""
    agg = FlowAggregator()

    agg.ingest(_make_packet(
        ip_total_length=100, timestamp=1000.0,
    ))
    agg.ingest(_make_packet(
        src_ip="10.0.0.1", dst_ip="192.168.1.100",
        src_port=80, dst_port=12345,
        ip_total_length=200, timestamp=1000.1,
    ))

    flows = agg.flush_all()
    f = flows[0]
    assert f.total_packets == 2
    assert f.total_bytes == 300
