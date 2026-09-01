"""Tests for PCAP replay functionality."""

from pathlib import Path

import pytest
from scapy.all import ARP, Ether, IP, TCP, wrpcap

from sentinel_net.ingestion.replay import PcapReplay, PcapReplayConfig


@pytest.fixture
def pcap_path(tmp_path: Path) -> Path:
    """Generate a small deterministic PCAP file for testing."""
    path = tmp_path / "test.pcap"
    pkts = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=443) / b"data",
        Ether() / ARP(),  # Non-IP — should be skipped
        Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=443, dport=80) / b"reply",
    ]
    wrpcap(str(path), pkts)
    return path


def test_replay_sync(pcap_path: Path):
    """Synchronous replay returns only IP packets."""
    config = PcapReplayConfig(pcap_path=pcap_path)
    replay = PcapReplay(config)

    packets = replay.replay_sync()
    assert len(packets) == 2  # ARP is skipped
    assert replay.skipped_count == 1
    assert replay.parsed_count == 2
    assert replay.packet_count == 3


@pytest.mark.asyncio
async def test_replay_async(pcap_path: Path):
    """Async replay yields only IP packets."""
    config = PcapReplayConfig(pcap_path=pcap_path)
    replay = PcapReplay(config)

    count = 0
    async for pkt in replay.replay():
        count += 1
        assert pkt.src_ip in ("1.1.1.1", "2.2.2.2")

    assert count == 2
    assert replay.skipped_count == 1


def test_replay_file_not_found():
    """FileNotFoundError for nonexistent PCAP."""
    config = PcapReplayConfig(pcap_path=Path("nonexistent.pcap"))
    with pytest.raises(FileNotFoundError):
        PcapReplay(config)


def test_replay_properties(pcap_path: Path):
    """Verify counter properties after sync replay."""
    config = PcapReplayConfig(pcap_path=pcap_path)
    replay = PcapReplay(config)

    assert replay.file_size_bytes > 0
    assert replay.packet_count == 0  # Before replay

    replay.replay_sync()

    assert replay.packet_count == 3
    assert replay.parsed_count == 2
    assert replay.skipped_count == 1
