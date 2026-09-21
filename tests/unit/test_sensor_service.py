"""RW-2 deterministic service tests. No privileged or real-interface capture."""
import asyncio
import json
import queue
import threading
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import pytest
from fastapi.testclient import TestClient

from sentinel_net.api.main import create_app
from sentinel_net.config import SentinelConfig, get_config
from sentinel_net.sensor.service import SensorService
from sentinel_net.sensor.lifecycle import SensorState
from sentinel_net.sensor.capture import PassiveCaptureSource, CaptureConfig
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.storage.database import Database
from tests.unit.test_rw1_correctness import detector, parsed, packet


class FakeCapture:
    def __init__(self, config, packets, metrics):
        self.packets, self.metrics = packets, metrics
        self.started = False
        self.stopped = False
        self.failed = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def emit(self, packet):
        assert self.started and not self.stopped
        self.metrics.increment('packets_observed')
        try:
            self.packets.put_nowait(packet)
        except queue.Full:
            self.metrics.increment('packets_dropped')


def service(tmp_path, detector, **kwargs):
    config = SentinelConfig(database_path=tmp_path/'sensor.db', capture_interface='test0',
                            flow_idle_timeout_sec=60)
    return SensorService(config, interface_validator=lambda _: None,
                         model_loader=lambda _: detector, capture_factory=FakeCapture, **kwargs)


async def until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(.01)


async def test_start_stop_idle_and_no_subscribers(tmp_path, detector):
    s = service(tmp_path, detector)
    assert s.lifecycle.state == SensorState.STOPPED
    await s.start()
    assert s.health() == {'state': 'running', 'mode': 'live_passive_sensor', 'reasons': []}
    assert s.db.is_connected and s.event_bus.subscriber_count == 0
    await asyncio.wait_for(s.stop(), 2)
    assert s.lifecycle.state == SensorState.STOPPED
    assert s.capture.stopped and not s.pipeline.alive and not s.db.is_connected
    assert s.metrics.detections_generated == s.metrics.events_dropped == 0
    uptime = s.metrics.uptime_sec
    await asyncio.sleep(.01)
    assert s.metrics.uptime_sec == uptime
    await s.stop()  # idempotent
    with pytest.raises(RuntimeError, match='one-shot'):
        await s.start()


async def test_invalid_interface_before_database(tmp_path, detector):
    s = service(tmp_path, detector)
    s._interface_validator = Mock(side_effect=ValueError('invalid interface'))
    s._database_factory = Mock()
    with pytest.raises(RuntimeError, match='configuration'):
        await s.start()
    s._database_factory.assert_not_called()
    assert s.lifecycle.state == SensorState.FAILED


@pytest.mark.parametrize('setting,value', [('capture_queue_size',0), ('event_queue_size',-1),
                                          ('flow_idle_timeout_sec',float('nan')), ('api_port',0)])
async def test_invalid_config_rejected(tmp_path, detector, setting, value):
    s = service(tmp_path, detector)
    setattr(s.config, setting, value)
    with pytest.raises(RuntimeError, match='configuration'):
        await s.start()
    assert s.db is None


async def test_capture_init_failure_closes_pipeline_and_database(tmp_path, detector):
    s = service(tmp_path, detector)
    class BadCapture(FakeCapture):
        def start(self):
            raise PermissionError('not permitted')
    s._capture_factory = BadCapture
    with pytest.raises(RuntimeError, match='capture initialization'):
        await s.start()
    assert s.capture.stopped and not s.pipeline.alive and not s.db.is_connected
    assert s.lifecycle.state == SensorState.FAILED
    await s.stop()


async def test_partial_database_initialization_failure_is_closed(tmp_path, detector):
    class BadDatabase(Database):
        async def initialize(self):
            await super().initialize()
            raise OSError('disk failure')
    s = service(tmp_path, detector, database_factory=BadDatabase)
    with pytest.raises(RuntimeError, match='database initialization'):
        await s.start()
    assert not s.db.is_connected
    assert s.lifecycle.state == SensorState.FAILED


async def test_model_failure_closes_database_without_capture(tmp_path, detector):
    s = service(tmp_path, detector)
    s._model_loader = Mock(side_effect=ValueError('invalid model'))
    with pytest.raises(RuntimeError, match='model loading'):
        await s.start()
    assert s.capture is None and s.db is None
    assert s.lifecycle.state == SensorState.FAILED


async def test_active_flows_and_queued_packets_drained_once(tmp_path, detector):
    s = service(tmp_path, detector)
    await s.start()
    for i in range(20):
        s.capture.emit(parsed(time.time(), sport=1000+i))
    await s.quiesce()
    assert s.capture.stopped and s.pipeline._capture_queue.unfinished_tasks == 0
    assert s.metrics.packets_processed == s.metrics.flows_created == 20
    assert s.metrics.flows_active == 0
    assert s.metrics.flows_completed == s.metrics.events_persisted == 20
    assert await s.db.get_event_count() == 20
    await s.quiesce()
    assert await s.db.get_event_count() == 20
    await s.stop()


async def test_persistence_failure_never_publishes_and_degrades(tmp_path, detector):
    s = service(tmp_path, detector)
    await s.start()
    q = s.event_bus.subscribe('observer')
    await s.db._conn.execute("CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL, 'disk failure'); END")
    s.capture.emit(parsed(time.time(), 'R'))
    await until(lambda: s.metrics.persistence_errors == 1)
    assert s.health()['state'] == 'degraded'
    assert 'persistence_errors' in s.health()['reasons']
    assert q.empty() and await s.db.get_event_count() == 0
    assert s.metrics.detections_generated == 1 and s.metrics.events_enqueued == 0
    await s.stop()
    assert s.lifecycle.state == SensorState.FAILED


async def test_malformed_packet_and_processing_exception_observable(tmp_path, detector, monkeypatch):
    from sentinel_net.sensor import pipeline
    from sentinel_net.models.types import RawPacket
    s = service(tmp_path, detector)
    await s.start()
    s.capture.emit(RawPacket(timestamp=time.time(), raw_bytes=b'', wire_length=0, capture_length=0))
    await until(lambda: s.metrics.packets_malformed == 1)
    monkeypatch.setattr(pipeline, 'parse_packet', Mock(side_effect=ValueError('parser failure')))
    s.capture.emit(object())
    await until(lambda: s.metrics.packet_processing_errors == 1)
    assert s.health()['state'] == 'degraded'
    assert s.metrics.snapshot()['packet_errors'] == 2
    assert s.metrics.detections_generated == 0
    await s.stop()
    assert not s.db.is_connected


async def test_processing_exception_does_not_kill_other_flows(tmp_path, detector, monkeypatch):
    s = service(tmp_path, detector)
    await s.start()
    original = detector.detect_batch
    calls = 0
    def detect(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError('inference failed')
        return original(*args)
    monkeypatch.setattr(detector, 'detect_batch', detect)
    s.capture.emit(parsed(time.time(), 'R', sport=1000))
    s.capture.emit(parsed(time.time(), 'R', sport=1001))
    await until(lambda: s.metrics.events_persisted == 1)
    assert s.health()['state'] == 'degraded'
    assert s.metrics.processing_errors == 1
    await s.stop()


async def test_persist_before_publish_with_slow_subscriber_overflow(tmp_path, detector):
    s = service(tmp_path, detector)
    s.config.event_queue_size = 1
    await s.start()
    slow = s.event_bus.subscribe('slow')
    fast = s.event_bus.subscribe('fast')
    original = s.event_bus.publish_result
    order = []
    def publish(event):
        assert s.metrics.events_persisted == len(order)+1
        order.append(event['id'])
        return original(event)
    s.event_bus.publish_result = publish
    s.capture.emit(parsed(time.time(), 'R', sport=1000))
    await until(lambda: s.metrics.events_enqueued == 2)
    first = fast.get_nowait()
    assert await s.db.get_event_by_id(first['id']) == first
    s.capture.emit(parsed(time.time(), 'R', sport=1001))
    await until(lambda: s.metrics.events_persisted == 2)
    assert len(set(order)) == 2 and slow.qsize() == fast.qsize() == 1
    assert s.metrics.events_enqueued == 3 and s.metrics.events_dropped == 1
    assert s.metrics.events_delivered == 0
    assert s.health()['state'] == 'degraded'
    await s.stop()
    assert s.metrics.events_dropped == 3  # overflow + two undelivered queue copies


async def test_shutdown_during_inference_waits_for_persistence(tmp_path, detector, monkeypatch):
    s = service(tmp_path, detector)
    entered, release = threading.Event(), threading.Event()
    original = detector.detect_batch
    def paused(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(detector, 'detect_batch', paused)
    await s.start()
    s.capture.emit(parsed(time.time(), 'R'))
    await until(entered.is_set)
    stopping = asyncio.create_task(s.stop())
    await asyncio.sleep(.05)
    assert not stopping.done() and s.db.is_connected and s.capture.stopped
    release.set()
    await asyncio.wait_for(stopping, 5)
    assert s.metrics.events_persisted == 1 and s.lifecycle.state == SensorState.STOPPED


async def test_capture_worker_failure_requests_exit(tmp_path, detector):
    s = service(tmp_path, detector)
    await s.start()
    s.capture.failed = True
    await until(lambda: s.lifecycle.shutdown_requested)
    assert s.health()['state'] == 'failed'
    await s.stop()
    assert s.lifecycle.state == SensorState.FAILED and not s.db.is_connected


def test_passive_socket_start_failure_and_no_transmit(monkeypatch):
    from sentinel_net.sensor import capture
    iface = SimpleNamespace(is_valid=lambda: True, l2listen=lambda: Mock(side_effect=PermissionError()))
    monkeypatch.setattr(capture, 'resolve_iface', lambda _: iface)
    m = SensorMetrics()
    source = PassiveCaptureSource(CaptureConfig('test0'), queue.Queue(2), m)
    with pytest.raises(RuntimeError, match='initialization'):
        source.start()
    assert m.capture_errors == 1 and not source._running.is_set()


def test_receive_only_socket_idle_stop_and_callback(monkeypatch):
    from sentinel_net.sensor import capture
    sock = Mock()
    opened = Mock(return_value=sock)
    monkeypatch.setattr(capture, 'resolve_iface', lambda _: SimpleNamespace(is_valid=lambda: True,l2listen=lambda:opened))
    class Sniffer:
        def __init__(self, **kwargs):
            assert kwargs['opened_socket'] is sock and kwargs['store'] is False
            self.kwargs = kwargs
            self.running = False
            self.thread = Mock(is_alive=lambda:False)
            self.stop_cb = lambda:None
        def start(self):
            self.running = True
            self.kwargs['started_callback']()
        def stop(self, join):
            self.running = False
    monkeypatch.setattr(capture, 'AsyncSniffer', Sniffer)
    m, q = SensorMetrics(), queue.Queue(1)
    source = PassiveCaptureSource(CaptureConfig('test0'), q, m)
    source.start()
    source._on_packet(packet())
    source._on_packet(packet())
    assert m.packets_observed == 2 and m.packets_dropped == 1
    assert q.get_nowait().interface == 'test0'
    source.stop()
    sock.close.assert_called_once()
    sock.send.assert_not_called()
    assert not source.failed


def test_interface_validation_rejects_unknown_and_bad_names(monkeypatch):
    from sentinel_net.sensor import capture
    for name in ['', ' x', 'x\n']:
        with pytest.raises(ValueError):
            PassiveCaptureSource.validate_interface(name)
    monkeypatch.setattr(capture, 'resolve_iface', Mock(side_effect=ValueError('unknown')))
    with pytest.raises(ValueError):
        PassiveCaptureSource.validate_interface('missing0')


def test_api_health_and_status_observe_service_without_remote_controls(tmp_path, detector, monkeypatch):
    s = service(tmp_path, detector)
    monkeypatch.setenv('SENTINEL_API_KEY', 'rw2-test-key')
    get_config.cache_clear()
    try:
        with TestClient(create_app(sensor_service=s)) as client:
            headers = {'X-API-Key':'rw2-test-key'}
            assert client.get('/health').json()['sensor']['state'] == 'running'
            assert client.get('/readiness').status_code == 200
            s.metrics.increment('packets_dropped')
            assert client.get('/health').json()['status'] == 'degraded'
            assert client.get('/readiness').status_code == 503
            result = client.get('/api/v1/status', headers=headers).json()
            assert result['sensor_state'] == 'degraded'
            assert result['sensor_mode'] == 'live_passive_sensor'
            assert result['metrics']['subscriber_count'] == 0
            assert result['feature_count'] == 52
            assert client.post('/api/v1/sensor/start', headers=headers).status_code == 404
    finally:
        get_config.cache_clear()


def test_real_scapy_idle_control_wakeup_without_network(monkeypatch):
    """Exercise Scapy's actual blocking select/control pipe, not a fake sniffer."""
    from scapy.automaton import ObjectPipe
    from sentinel_net.sensor import capture
    pipe = ObjectPipe('rw2-test-input')
    monkeypatch.setattr(capture, 'resolve_iface', lambda _: SimpleNamespace(
        is_valid=lambda: True, l2listen=lambda: lambda **_: pipe))
    source = PassiveCaptureSource(CaptureConfig('test0'), queue.Queue(2), SensorMetrics())
    source.start()
    started = time.monotonic()
    source.stop()
    assert time.monotonic()-started < 2
    assert not source._sniffer.thread.is_alive()


async def test_capture_queue_pressure_and_overflow_are_visible(tmp_path, detector):
    s = service(tmp_path, detector)
    s.config.capture_queue_size = 1
    await s.start()
    # Hold inference so the next accepted packet stays queued.
    entered, release = threading.Event(), threading.Event()
    original = detector.detect_batch
    def delayed(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    detector.detect_batch = delayed
    try:
        s.capture.emit(parsed(time.time(), 'R', sport=1000))
        await until(entered.is_set)
        s.capture.emit(parsed(time.time(), 'R', sport=1001))
        s.capture.emit(parsed(time.time(), 'R', sport=1002))
        s.metrics.set_gauge('capture_queue_depth', 1)
        assert 'capture_queue_pressure' in s.health()['reasons']
        assert s.metrics.packets_observed == 3 and s.metrics.packets_dropped == 1
    finally:
        release.set()
        await s.stop()
    assert s.metrics.packets_processed == s.metrics.events_persisted == 2


async def test_lifecycle_transitions_and_single_owner_order(tmp_path, detector):
    s = service(tmp_path, detector)
    order = []
    original = s.lifecycle.transition
    def transition(state, error=''):
        order.append(state)
        original(state, error)
    s.lifecycle.transition = transition
    await s.start()
    s.metrics.increment('events_dropped')
    s.health()
    await s.stop()
    assert order == [SensorState.STARTING, SensorState.RUNNING, SensorState.DEGRADED,
                     SensorState.STOPPING, SensorState.STOPPED]
    assert s.capture.stopped and not s.pipeline.alive and not s.db.is_connected


def test_cli_server_quiesces_before_api_shutdown(monkeypatch):
    import uvicorn
    from sentinel_net.cli import SensorServer
    order = []
    async def quiesce(): order.append('sensor drained')
    async def shutdown(self, sockets=None): order.append('api stopped')
    monkeypatch.setattr(uvicorn.Server, 'shutdown', shutdown)
    server = SensorServer(uvicorn.Config('sentinel_net.api.main:app'),SimpleNamespace(quiesce=quiesce))
    asyncio.run(server.shutdown())
    assert order == ['sensor drained', 'api stopped']
