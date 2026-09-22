"""Shared frozen runtime parity, canonical contract and durable streaming evidence."""

import asyncio
import queue

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from sentinel_net.config import SentinelConfig
from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.intelligence.config import IntelligenceConfig
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.sources import LiveCaptureSource, PcapReplaySource
from sentinel_net.storage.database import Database
from tests.unit.test_passive_sources import canonical_event
from tests.unit.test_passive_sources import real_detector as detector_fixture
from tests.unit.test_sensor_runtime_model import load, save_pipeline


@pytest.fixture
def detector():
    return detector_fixture.__wrapped__()


def packets(case):
    result = []
    for i in range(8):
        source = f"192.0.2.{i + 10}" if case == "entropy" else "192.0.2.1"
        dest = f"198.51.100.{i + 10}" if case == "hosts" else "198.51.100.1"
        port = 100 + i if case == "ports" else 443
        for flags, offset in [("S", 0), ("R", 0.01)]:
            layer = (
                UDP(sport=10000 + i, dport=port)
                if case == "udp"
                else TCP(sport=10000 + i, dport=port, flags=flags)
            )
            p = (
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src=source, dst=dest)
                / layer
                / Raw(b"x" * (1100 if case == "asymmetry" else 20))
            )
            p.time = 1000 + i * (6 if case == "periodic" else 0.1) + offset
            result.append(p)
    return result


async def run(config, source, metrics, detector, path):
    db = Database(path)
    await db.initialize()
    bus = EventBus()
    delivery = bus.subscribe("test")
    pipeline = PacketProcessingPipeline(
        config, source, bus, metrics, detector, db=db, event_loop=asyncio.get_running_loop()
    )
    try:
        pipeline.start()
        if isinstance(source, LiveCaptureSource):
            await pipeline.astop()
        else:
            await pipeline.wait()
        result = []
        while not delivery.empty():
            event = delivery.get_nowait()
            assert event == await db.get_event_by_id(event["id"])
            result.append(event)
        assert len({e["id"] for e in result}) == len(result)
        assert metrics.intelligence_keys == 0
        return result, pipeline
    finally:
        if pipeline.alive:
            await pipeline.astop()
        await db.close()


@pytest.mark.parametrize(
    "case,expected",
    [
        ("syn", "SYN_RATE"),
        ("udp", "UDP_RATE"),
        ("entropy", "SOURCE_DISTRIBUTION_ENTROPY"),
        ("periodic", "C2_PERIODICITY_EVIDENCE"),
        ("ports", "PORT_FANOUT"),
        ("hosts", "HOST_FANOUT"),
        ("asymmetry", "DIRECTIONAL_ASYMMETRY"),
    ],
)
async def test_live_replay_behavioral_evidence_matches(tmp_path, detector, case, expected):
    model = save_pipeline(tmp_path / "registry", detector)
    config = SentinelConfig(
        intelligence=IntelligenceConfig(
            syn_rate=0.01,
            udp_rate=0.01,
            flow_rate=0.01,
            packet_rate=0.01,
            unique_sources=4,
            entropy_bits=1,
            min_entropy_observations=4,
            port_fanout=4,
            host_fanout=4,
            directional_bytes=1000,
        )
    )
    pkts = packets(case)
    pcap = tmp_path / "input.pcap"
    wrpcap(str(pcap), pkts)
    live_metrics, replay_metrics = SensorMetrics(), SensorMetrics()
    q = queue.Queue(maxsize=100)
    for pkt in pkts:
        q.put_nowait(extract_raw_packet(pkt))
    live = LiveCaptureSource(q, live_metrics, clock=lambda: 1000)
    replay = PcapReplaySource(pcap, replay_metrics)
    a, _ = await run(config, live, live_metrics, load(model), tmp_path / "live.db")
    b, _ = await run(config, replay, replay_metrics, load(model), tmp_path / "replay.db")
    assert [canonical_event(e) for e in a] == [canonical_event(e) for e in b]
    assert any(s["signal_type"] == expected for e in a for s in e["behavioral_evidence"])
    for key in (
        "intelligence_evidence_generated",
        "intelligence_evictions",
        "intelligence_keys_peak",
    ):
        assert getattr(live_metrics, key) == getattr(replay_metrics, key)
    # A second identical replay is deterministic despite different UUIDs/runtime clocks.
    c, _ = await run(
        config,
        PcapReplaySource(pcap, SensorMetrics()),
        SensorMetrics(),
        load(model),
        tmp_path / "again.db",
    )
    assert [canonical_event(e) for e in b] == [canonical_event(e) for e in c]


async def test_engine_failure_preserves_ml_durability_and_is_visible(tmp_path, detector):
    metrics = SensorMetrics()
    pcap = tmp_path / "p.pcap"
    wrpcap(str(pcap), packets("syn"))
    db = Database(tmp_path / "d.db")
    await db.initialize()
    pipeline = PacketProcessingPipeline(
        SentinelConfig(),
        PcapReplaySource(pcap, metrics),
        EventBus(),
        metrics,
        detector,
        db=db,
        event_loop=asyncio.get_running_loop(),
    )

    def fail(*_):
        raise RuntimeError("injected operational failure")

    pipeline.intelligence.observe_packet = fail
    try:
        pipeline.start()
        await pipeline.wait()
        events = await db.get_events()
        assert len(events) == 8 and metrics.intelligence_processing_errors == 1
        assert all(
            e["behavioral_evidence_status"] == "unavailable_processing_error" for e in events
        )
        assert all(
            e["classification_score"] is not None and not e["behavioral_evidence"] for e in events
        )
        assert not pipeline.intelligence.window.keys
    finally:
        await db.close()


async def test_enabled_engine_does_not_change_ml_contract(tmp_path, detector):
    path = tmp_path / "input.pcap"
    wrpcap(str(path), packets("ports"))
    model = save_pipeline(tmp_path / "registry", detector)
    outputs = []
    for enabled in (False, True):
        config = SentinelConfig(intelligence=IntelligenceConfig(enabled=enabled, port_fanout=4))
        metrics = SensorMetrics()
        events, _ = await run(
            config,
            PcapReplaySource(path, metrics),
            metrics,
            load(model),
            tmp_path / f"{enabled}.db",
        )
        outputs.append(events)
    for a, b in zip(*outputs):
        for key in (
            "severity",
            "classification_score",
            "anomaly_score",
            "threat_type",
            "model_manifest_sha256",
            "feature_schema_version",
            "evidence",
            "rationale",
        ):
            if key == "evidence":
                assert canonical_event({"evidence": a[key], "metadata": {}}) == canonical_event(
                    {"evidence": b[key], "metadata": {}}
                )
            else:
                assert a[key] == b[key]
