"""Frozen inference plus persisted encrypted metadata across live/replay sources."""

import asyncio
import queue

import pytest
from scapy.all import Ether, wrpcap

from scripts.f5_fixtures import client_hello, quic_initial, server_hello
from sentinel_net.config import SentinelConfig
from sentinel_net.encrypted.config import EncryptedConfig
from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.sources import LiveCaptureSource, PcapReplaySource
from sentinel_net.storage.database import Database
from tests.unit.test_encrypted_metadata import packet
from tests.unit.test_passive_sources import canonical_event, real_detector
from tests.unit.test_sensor_runtime_model import load, save_pipeline
from tests.unit.test_stream_intelligence_parity import run


@pytest.fixture
def detector():
    return real_detector.__wrapped__()


def sequence(case):
    data = client_hello()
    packets = []
    if case in ("client", "both"):
        packets.append(packet(data))
    if case in ("server", "both"):
        packets.append(packet(server_hello(), reverse=True, timestamp=1000.1))
    if case in ("split", "out_of_order", "retransmission"):
        pieces = [
            packet(data[:40], seq=1000, timestamp=1000),
            packet(data[40:], seq=1040, timestamp=1000.1),
        ]
        packets = (
            [pieces[1], pieces[0]]
            if case == "out_of_order"
            else [pieces[0], pieces[0], pieces[1]]
            if case == "retransmission"
            else pieces
        )
    if case == "ciphertext":
        packets = [packet(b"\x17\x03\x03\x00\x04xxxx")]
    if case == "malformed":
        packets = [packet(b"\x16\x03\x03\xff\xff")]
    if case.startswith("quic"):
        packets = [
            packet(
                quic_initial(
                    version=0 if case == "quic_vn" else 99 if case == "quic_unknown" else 1
                ),
                udp=True,
            )
        ]
        if case == "quic_both":
            packets.append(packet(quic_initial(), udp=True, reverse=True, timestamp=1000.1))
    result = []
    for p in packets:
        raw = Ether(p.raw_packet.raw_bytes)
        raw.time = p.timestamp
        result.append(raw)
    return result


@pytest.mark.parametrize(
    "case",
    [
        "client",
        "server",
        "both",
        "split",
        "out_of_order",
        "retransmission",
        "ciphertext",
        "malformed",
        "quic",
        "quic_vn",
        "quic_unknown",
        "quic_both",
    ],
)
async def test_metadata_live_replay_parity(tmp_path, detector, case):
    model = save_pipeline(tmp_path / "registry", detector)
    packets = sequence(case)
    path = tmp_path / "input.pcap"
    wrpcap(str(path), packets)
    q = queue.Queue(maxsize=100)
    for p in packets:
        q.put_nowait(extract_raw_packet(p))
    lm, rm = SensorMetrics(), SensorMetrics()
    config = SentinelConfig()
    a, ap = await run(
        config, LiveCaptureSource(q, lm, clock=lambda: 1000), lm, load(model), tmp_path / "live.db"
    )
    b, bp = await run(config, PcapReplaySource(path, rm), rm, load(model), tmp_path / "replay.db")
    assert a and [canonical_event(e) for e in a] == [canonical_event(e) for e in b]
    cm = SensorMetrics()
    c, _ = await run(config, PcapReplaySource(path, cm), cm, load(model), tmp_path / "again.db")
    assert [canonical_event(e) for e in b] == [canonical_event(e) for e in c]
    for p in (ap, bp):
        assert not p.encrypted.connections
    record = a[-1]
    if case in ("client", "server", "both", "split", "out_of_order", "retransmission"):
        assert record["tls_status"] == "COMPLETE"
    if case.startswith("quic"):
        assert record["quic_status"] == ("UNSUPPORTED" if case == "quic_unknown" else "COMPLETE")
    if case == "malformed":
        assert record["tls_status"] == "MALFORMED" and record["tls_evidence"] == []
    assert lm.encrypted_metadata_processing_errors == rm.encrypted_metadata_processing_errors == 0


async def test_f5_does_not_change_ml_f3_or_f4(tmp_path, detector):
    model = save_pipeline(tmp_path / "registry", detector)
    path = tmp_path / "input.pcap"
    wrpcap(str(path), sequence("both"))
    outputs = []
    for enabled in (False, True):
        m = SensorMetrics()
        events, _ = await run(
            SentinelConfig(encrypted=EncryptedConfig(enabled=enabled)),
            PcapReplaySource(path, m),
            m,
            load(model),
            tmp_path / f"{enabled}.db",
        )
        outputs.append(events)
    assert len(outputs[0]) == len(outputs[1])
    for a, b in zip(*outputs):
        for key in (
            "severity",
            "classification_score",
            "anomaly_score",
            "threat_type",
            "feature_schema_version",
            "model_manifest_sha256",
            "behavioral_evidence",
            "behavioral_policy",
            "dns_status",
            "dns_evidence",
            "dns_observation",
            "dns_attack_context",
        ):
            assert a[key] == b[key]
        assert canonical_event({"evidence": a["evidence"], "metadata": {}}) == canonical_event(
            {"evidence": b["evidence"], "metadata": {}}
        )
        assert a["tls_status"] == "disabled"


async def test_f5_error_isolation(tmp_path, detector):
    path = tmp_path / "input.pcap"
    wrpcap(str(path), sequence("both"))
    db = Database(tmp_path / "events.db")
    await db.initialize()
    m = SensorMetrics()
    p = PacketProcessingPipeline(
        SentinelConfig(),
        PcapReplaySource(path, m),
        EventBus(),
        m,
        detector,
        db=db,
        event_loop=asyncio.get_running_loop(),
    )

    def fail(*args):
        raise RuntimeError("injected metadata failure")

    p.encrypted.observe_packet = fail
    try:
        p.start()
        await p.wait()
        events = await db.get_events()
        assert events and m.encrypted_metadata_processing_errors == 1 and m.processing_errors == 0
        assert all(
            e["tls_status"] == "unavailable_processing_error"
            and e["quic_status"] == "unavailable_processing_error"
            and e["behavioral_evidence_status"] == "available"
            for e in events
        )
    finally:
        await db.close()
