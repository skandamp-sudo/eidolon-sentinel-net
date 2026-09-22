"""DNS through the shared frozen runtime and durable event contract."""

import asyncio
import queue

import pytest
from scapy.all import Ether, wrpcap

from sentinel_net.config import SentinelConfig
from sentinel_net.dns.config import DNSConfig
from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.sources import LiveCaptureSource, PcapReplaySource
from sentinel_net.storage.database import Database
from tests.unit.test_dns_intelligence import packet, random_label, wire
from tests.unit.test_passive_sources import canonical_event, real_detector
from tests.unit.test_sensor_runtime_model import load, save_pipeline
from tests.unit.test_stream_intelligence_parity import run


@pytest.fixture
def detector():
    return real_detector.__wrapped__()



def sequence(case):
    result = []
    count = 24 if case in ("dga", "tunnel") else 1
    for i in range(count):
        domain = (
            f"{random_label(i)}.{('d' + str(i)) if case == 'dga' else 'service'}.test"
            if count > 1
            else "example.test"
        )
        query = wire(domain, 16 if case == "txt" else 1, txid=i)
        response = wire(domain, response=True, rcode=3, txid=i)
        if case == "malformed":
            query = b"\x00"
        if case == "tcp":
            query = len(query).to_bytes(2, "big") + query
        for reverse in [False, True] if case == "paired" else [case == "response"]:
            p = packet(
                response if reverse else query,
                response=reverse,
                tcp=case == "tcp",
                timestamp=1000 + i * 0.1 + (0.01 if reverse else 0),
            )
            raw = Ether(p.raw_packet.raw_bytes)
            raw.time = p.timestamp
            result.append(raw)
    return result


@pytest.mark.parametrize(
    "case", ["query", "response", "paired", "txt", "tcp", "malformed", "dga", "tunnel"]
)
async def test_dns_live_replay_parity(tmp_path, detector, case):
    model = save_pipeline(tmp_path / "registry", detector)
    config = SentinelConfig()
    packets = sequence(case)
    path = tmp_path / "input.pcap"
    wrpcap(str(path), packets)
    lm, rm = SensorMetrics(), SensorMetrics()
    q = queue.Queue(maxsize=100)
    for p in packets:
        q.put_nowait(extract_raw_packet(p))
    a, ap = await run(
        config, LiveCaptureSource(q, lm, clock=lambda: 1000), lm, load(model), tmp_path / "live.db"
    )
    b, bp = await run(config, PcapReplaySource(path, rm), rm, load(model), tmp_path / "replay.db")
    assert a and [canonical_event(e) for e in a] == [canonical_event(e) for e in b]
    cm = SensorMetrics()
    c, _ = await run(config, PcapReplaySource(path, cm), cm, load(model), tmp_path / "repeat.db")
    assert [canonical_event(e) for e in b] == [canonical_event(e) for e in c]
    for pipeline in (ap, bp):
        assert (
            not pipeline.dns.window.keys
            and not pipeline.dns.transactions
            and not pipeline.dns.observations
        )
    for metric in (
        "dns_messages_parsed",
        "dns_evidence_generated",
        "dns_evictions",
        "dns_keys_peak",
    ):
        assert getattr(lm, metric) == getattr(rm, metric)
    record = a[-1]
    if case == "malformed":
        assert record["dns_status"] == "TRUNCATED" and not record["dns_evidence"]
    else:
        assert record["dns_status"] == "PARSED"
    if case == "paired":
        assert record["dns_observation"]["visibility"] == "PAIRED"
    if case in ("query", "txt", "tcp"):
        assert record["dns_observation"]["visibility"] == "QUERY_ONLY"
    if case == "response":
        assert record["dns_observation"]["visibility"] == "RESPONSE_ONLY"
    if case in ("dga", "tunnel"):
        expected = "DGA_LIKE_BEHAVIOR" if case == "dga" else "DNS_TUNNELLING_LIKE_BEHAVIOR"
        assert expected in {s["signal_type"] for s in record["dns_evidence"]}
        assert "dns_intelligence" in record["detection_source"]


async def test_dns_enabled_disabled_preserves_ml_and_f3(tmp_path, detector):
    model = save_pipeline(tmp_path / "registry", detector)
    path = tmp_path / "input.pcap"
    wrpcap(str(path), sequence("tunnel"))
    outputs = []
    for enabled in (False, True):
        metrics = SensorMetrics()
        events, _ = await run(
            SentinelConfig(dns=DNSConfig(enabled=enabled)),
            PcapReplaySource(path, metrics),
            metrics,
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
            "model_manifest_sha256",
            "feature_schema_version",
            "rationale",
            "behavioral_evidence",
            "behavioral_policy",
            "behavioral_attack_context",
        ):
            assert a[key] == b[key]
        assert canonical_event({"evidence": a["evidence"], "metadata": {}}) == canonical_event(
            {"evidence": b["evidence"], "metadata": {}}
        )
        assert a["dns_status"] == "disabled" and b["dns_status"] == "PARSED"


async def test_dns_processing_error_isolated_and_visible(tmp_path, detector):
    path = tmp_path / "input.pcap"
    wrpcap(str(path), sequence("tunnel"))
    metrics = SensorMetrics()
    db = Database(tmp_path / "d.db")
    await db.initialize()
    pipeline = PacketProcessingPipeline(
        SentinelConfig(),
        PcapReplaySource(path, metrics),
        EventBus(),
        metrics,
        detector,
        db=db,
        event_loop=asyncio.get_running_loop(),
    )

    def fail(*args):
        raise RuntimeError("injected DNS error")

    pipeline.dns.observe_packet = fail
    try:
        pipeline.start()
        await pipeline.wait()
        events = await db.get_events()
        assert events and metrics.dns_processing_errors == 1 and metrics.processing_errors == 0
        assert all(
            e["dns_status"] == "unavailable_processing_error"
            and e["classification_score"] is not None
            and e["behavioral_evidence_status"] == "available"
            for e in events
        )
    finally:
        await db.close()
