"""Operational resource and durability contracts; no scientific policy changes."""

import asyncio
import sqlite3
import time
from types import SimpleNamespace

import pytest

from sentinel_net.config import SentinelConfig
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.event_output import persist_and_publish
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.retention import RetentionWorker
from sentinel_net.storage.database import Database
from tests.unit.test_retention import _make_event
from tests.unit.test_rw1_correctness import detector as detector_fixture


@pytest.fixture
def detector():
    return detector_fixture.__wrapped__()


@pytest.fixture
async def storage(tmp_path):
    db = Database(tmp_path / "ops.db")
    await db.initialize()
    try:
        yield db
    finally:
        await db.close()


async def test_retention_bounds_references_and_in_progress(storage):
    old = time.time() - 7200
    events = [_make_event(str(i), old + i) for i in range(9)]
    for event in events:
        await storage.store_event(event)
    # Shared flow still referenced by a retained event, including old flow timestamp.
    retained = _make_event("retained", time.time())
    retained.observed_flow = events[0].observed_flow
    retained.flow_id = events[0].observed_flow.id
    await storage.store_event(retained)
    in_progress = _make_event("pending", old).observed_flow
    await storage.store_flow(in_progress)
    config = SentinelConfig(
        max_events=1, retention_hours=1, cleanup_batch_rows=2, cleanup_cycle_rows=3
    )
    metrics = SensorMetrics()
    worker = RetentionWorker(storage, config, metrics)
    await worker.cycle()
    assert metrics.retention_events_removed + metrics.retention_flows_removed == 3
    for _ in range(8):
        await worker.cycle()
    assert await storage.get_event_count() == 1
    assert await storage.get_flow_by_id(retained.observed_flow.id)
    assert await storage.get_flow_by_id(in_progress.id)
    assert await storage.get_flow_count() == 2
    assert metrics.retention_events_removed == 9
    assert metrics.retention_flows_removed == 8
    assert metrics.retention_last_success and metrics.retention_duration_sec >= 0
    assert storage.storage_sizes()["database_bytes"] > 0


async def test_retention_cancellation_rolls_back_before_close(storage):
    await storage.store_event(_make_event("old", 0))
    original = storage._conn.commit
    entered = asyncio.Event()

    async def slow_commit():
        entered.set()
        await asyncio.sleep(10)
        await original()

    storage._conn.commit = slow_commit
    worker = RetentionWorker(storage, SentinelConfig(max_events=0), SensorMetrics())
    worker.start()
    await asyncio.wait_for(entered.wait(), 1)
    await asyncio.wait_for(worker.stop(), 1)
    assert worker.task.done()
    assert await storage.get_event_count() == 1
    storage._conn.commit = original
    await storage.store_event(_make_event("after", time.time()))


async def test_retention_failure_observed_without_spin(storage):
    metrics = SensorMetrics()
    worker = RetentionWorker(storage, SentinelConfig(cleanup_interval_sec=300), metrics)
    await storage.close()
    worker.start()
    await asyncio.sleep(0.05)
    await worker.stop()
    assert metrics.retention_failures == 1
    assert metrics.retention_last_success is None
    assert metrics.last_error_kind == "RETENTION_ERROR"


@pytest.mark.parametrize("mode", ["normal", "slow", "locked", "failed", "unavailable"])
async def test_persistence_commit_before_publish(storage, mode):
    bus, metrics = EventBus(), SensorMetrics()
    out = bus.subscribe("reader")
    event = _make_event("one", time.time())
    blocker = None
    if mode == "slow":
        original = storage.store_event

        async def slow(e):
            await asyncio.sleep(0.05)
            assert out.empty()
            return await original(e)

        storage.store_event = slow
    if mode == "locked":
        await storage._conn.execute("PRAGMA busy_timeout=30")
        blocker = sqlite3.connect(storage.db_path)
        blocker.execute("BEGIN IMMEDIATE")
    if mode == "failed":
        await storage._conn.execute(
            "CREATE TRIGGER fail_write BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    if mode == "unavailable":
        await storage.close()
    try:
        if mode in ("locked", "failed", "unavailable"):
            with pytest.raises((sqlite3.DatabaseError, RuntimeError)):
                await asyncio.wait_for(persist_and_publish(event, storage, bus, metrics), 1)
            assert out.empty() and metrics.events_persisted == 0
            assert metrics.persistence_errors == 1
            if mode != "unavailable":
                assert await storage.get_event_count() == await storage.get_flow_count() == 0
        else:
            task = asyncio.create_task(persist_and_publish(event, storage, bus, metrics))
            # Concurrent API reads while writer is in progress.
            while not task.done():
                await storage.get_events()
                await asyncio.sleep(0.001)
            await task
            assert out.get_nowait()["id"] == event.id
            assert await storage.get_event_by_id(event.id)
            assert metrics.events_persisted == 1
    finally:
        if blocker:
            blocker.rollback()
            blocker.close()


def test_subscriber_capacity_and_copy_drops():
    bus = EventBus(max_queue_size=2, max_subscribers=2)
    bus.subscribe("slow")
    fast = bus.subscribe("fast")
    with pytest.raises(RuntimeError, match="capacity"):
        bus.subscribe("third")
    for _ in range(10):
        bus.publish_result({"event": 1})
        fast.get_nowait()
    assert bus.subscriber_count == bus.subscriber_peak == 2
    assert bus.queue_peak == 2 and bus.dropped_events == 8
    assert bus.rejected_subscribers == 1
    assert bus.shutdown() == 2
    assert EventBus().publish_result({}).dropped == 0


def test_bounded_monotonic_latency_and_unknown_kernel_drops():
    metrics = SensorMetrics()
    for i in range(10000):
        metrics.observe_latency("packet_processing", i / 1000)
    result = metrics.latency_snapshot()["packet_processing"]
    assert result["samples"] == 4096 and result["total_observations"] == 10000
    assert result["p50"] > 5000
    assert metrics.snapshot()["kernel_capture_drops"] is None


async def test_slow_websocket_timeout_accounts_inflight(monkeypatch):
    from sentinel_net.api.routes import websocket as route

    config = SentinelConfig(ws_send_timeout_sec=0.02)
    monkeypatch.setattr(route, "get_config", lambda: config)
    bus, metrics = EventBus(2, 1), SensorMetrics()

    class SlowSocket:
        query_params = None
        app = SimpleNamespace(state=SimpleNamespace(event_bus=bus, sensor_metrics=metrics))

        async def accept(self):
            pass

        async def receive_text(self):
            return '{"type":"auth","api_key":"changeme-dev"}'

        async def send_json(self, payload):
            if payload["type"] == "auth_ok":
                bus.publish({"id": "first"})
                bus.publish({"id": "second"})
            else:
                await asyncio.sleep(10)

        async def close(self, code):
            pass

    await asyncio.wait_for(route.websocket_events(SlowSocket()), 1)
    assert metrics.events_dropped == 2
    assert metrics.output_errors == 1 and bus.subscriber_count == 0


async def test_shutdown_drains_slow_persistence(tmp_path, detector):
    from scapy.all import IP, TCP, Ether

    from sentinel_net.ingestion.parser import extract_raw_packet
    from sentinel_net.sensor.service import SensorService
    from tests.unit.test_sensor_service import FakeCapture

    entered, release = asyncio.Event(), asyncio.Event()

    class SlowDatabase(Database):
        async def store_event(self, event):
            entered.set()
            await release.wait()
            return await super().store_event(event)

    service = SensorService(
        SentinelConfig(database_path=tmp_path / "shutdown.db", capture_interface="test0"),
        model_loader=lambda _: detector,
        interface_validator=lambda _: None,
        capture_factory=FakeCapture,
        database_factory=SlowDatabase,
    )
    await service.start()
    try:
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(flags="R")
        )
        service.capture.emit(extract_raw_packet(packet))
        await asyncio.wait_for(entered.wait(), 2)
        closing = asyncio.create_task(service.stop())
        await asyncio.sleep(0.03)
        assert not closing.done() and service.db.is_connected
        release.set()
        await asyncio.wait_for(closing, 3)
        assert service.metrics.events_persisted == 1 and not service.db.is_connected
        assert service.retention.task.done() and not service.pipeline.alive
    finally:
        release.set()
        await service.stop()


@pytest.mark.parametrize("value", [None, 0, 7])
def test_kernel_drops_only_from_actual_backend_read(value):
    import queue

    from sentinel_net.sensor.capture import CaptureConfig, PassiveCaptureSource

    class BpfSocket:
        __module__ = "scapy.arch.bpf.supersocket"

        def get_stats(self):
            return (100, value)

    metrics = SensorMetrics()
    capture = PassiveCaptureSource(CaptureConfig("test0"), queue.Queue(2), metrics)
    capture._socket = BpfSocket()
    capture.refresh_statistics()
    assert metrics.kernel_capture_drops == value
    capture._socket = object()
    capture.refresh_statistics()
    assert metrics.kernel_capture_drops is None


async def test_retention_failure_degrades_health_without_anomaly_change(tmp_path, detector):
    from tests.unit.test_sensor_service import service

    s = service(tmp_path, detector)
    await s.start()
    try:
        s.metrics.increment("retention_failures")
        assert s.health()["state"] == "degraded"
        assert s.health()["reasons"] == ["retention_failures"]
        assert s.metrics.detections_generated == 0
    finally:
        await s.stop()


def test_timing_adapter_preserves_frozen_event_and_exact_features(detector):
    from scapy.all import IP, TCP, Ether

    from sentinel_net.features.extractor import FeatureExtractor
    from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
    from sentinel_net.ingestion.parser import extract_raw_packet, parse_packet
    from sentinel_net.sensor.telemetry import TimedFlowAggregator, timed_detector
    from tests.unit.test_passive_sources import canonical_event

    metrics = SensorMetrics()
    original = FlowAggregator()
    timed = TimedFlowAggregator(FlowAggregatorConfig(), metrics)
    for i in range(8):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(flags="A")
        )
        packet.time = 1000 + i * 0.1
        original.ingest(parse_packet(extract_raw_packet(packet)))
        timed.ingest(parse_packet(extract_raw_packet(packet)))
    before, after = original.flush_all(), timed.flush_all()
    extractor = FeatureExtractor()
    a, b = extractor.extract_batch(before), extractor.extract_batch(after)
    assert a[0].values == b[0].values
    expected = detector.detect_batch(a, before)[0].to_dict()
    actual = timed_detector(detector, metrics).detect_batch(b, after)[0].to_dict()
    assert canonical_event(expected) == canonical_event(actual)
    assert "_enrich" not in vars(detector)
    assert metrics.exact_history_samples_peak == 8
    assert metrics.latency_snapshot()["evidence_enrichment"]["samples"] == 1
