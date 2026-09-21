"""Regressions for the runtime defects found by the SIH audit."""
import asyncio
import queue
import time

import numpy as np
import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from sentinel_net.config import SentinelConfig
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import RandomForestBaseline
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.features.extractor import FeatureExtractor
from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.flow.aggregator import FlowAggregator, FlowAggregatorConfig
from sentinel_net.ingestion.parser import extract_raw_packet, parse_packet
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics


def packet(ts=1000.0, flags='A', sport=1234):
    pkt = Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=443, flags=flags)/Raw(b'x'*20)
    pkt.time = ts
    return pkt


def parsed(ts=1000.0, flags='A', sport=1234):
    return parse_packet(extract_raw_packet(packet(ts, flags, sport)))


@pytest.fixture
def detector():
    rng = np.random.RandomState(42)
    X = rng.normal(size=(40, FEATURE_COUNT))
    y = np.array(['benign']*20 + ['ddos']*20)
    pp = FeaturePreprocessor()
    transformed = pp.fit_transform(X)
    return DetectionPipeline(pp, AnomalyDetector(n_estimators=5).train(transformed[:20]),
                             RandomForestBaseline(n_estimators=5).train(transformed, y))


def detected(detector):
    agg = FlowAggregator()
    agg.ingest(parsed())
    flow = agg.flush_all()[0]
    return detector.detect_single(FeatureExtractor().extract(flow), flow)


def test_rst_finalizes_without_eof():
    agg = FlowAggregator()
    agg.ingest(parsed(flags='S'))
    agg.ingest(parsed(1000.1, 'R'))
    flows = agg.flush_completed()
    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert agg.active_flow_count == 0
    assert agg.flush_all() == []


def test_fin_grace_retains_tail_then_finalizes():
    agg = FlowAggregator()
    agg.ingest(parsed(flags='FA'))
    agg.ingest(parsed(1000.1, 'A'))
    assert agg.flush_completed() == []
    agg.expire_idle(1001.0)
    flows = agg.flush_completed()
    assert len(flows) == 1
    assert flows[0].packet_count == 2


def test_idle_tuple_reuse_is_separate_flow():
    agg = FlowAggregator(FlowAggregatorConfig(idle_timeout_sec=1))
    agg.ingest(parsed())
    agg.ingest(parsed(1002))
    assert [f.packet_count for f in agg.flush_all()] == [1, 1]


@pytest.mark.asyncio
async def test_event_record_survives_storage_without_field_loss(db, detector):
    event = detected(detector)
    expected = event.to_dict()
    assert expected['classification_score'] == event.threat_classification.confidence
    assert expected['anomaly_score'] == event.anomaly_result.anomaly_score
    assert expected['event_id'] == event.id
    assert expected['flow_id']
    assert expected['evidence']['unavailable_reason'] or expected['evidence']['explanation_available']
    await db.store_event(event)
    assert await db.get_event_by_id(event.id) == expected
    assert (await db.get_events())[0] == expected


@pytest.mark.asyncio
async def test_persisted_with_zero_clients_is_not_dropped(db, detector):
    from sentinel_net.demo_replay import _persist_and_publish
    metrics = SensorMetrics()
    await _persist_and_publish(detected(detector), db, EventBus(), metrics)
    assert metrics.events_persisted == 1
    assert metrics.events_dropped == 0
    assert await db.get_event_count() == 1


@pytest.mark.asyncio
async def test_replay_eof_counts_real_inference(tmp_path, db, detector, monkeypatch):
    from sentinel_net import demo_replay
    from sentinel_net.sensor.lifecycle import SensorLifecycle
    pcap = tmp_path/'eof.pcap'
    wrpcap(str(pcap), [packet(), packet(1000.1)])
    async def trained(_):
        return detector
    monkeypatch.setattr(demo_replay, 'load_detection_pipeline', trained)
    metrics = SensorMetrics()
    bus = EventBus()
    subscriber = bus.subscribe('audit')
    result = await demo_replay.run_replay(
        demo_replay.DemoReplayConfig(pcap, tmp_path, realtime=False), db, bus, SensorLifecycle(), metrics)
    assert result['total_flows'] == 1
    assert metrics.features_generated == 1
    assert metrics.flows_active == 0
    assert metrics.events_persisted == metrics.detections_generated == 1
    assert subscriber.get_nowait() == (await db.get_events())[0]


@pytest.mark.asyncio
async def test_live_shutdown_drains_packets_and_persists(db, detector):
    from sentinel_net.sensor.pipeline import LiveSensorPipeline
    packets = queue.Queue(maxsize=10)
    packets.put(extract_raw_packet(packet(time.time())))
    metrics = SensorMetrics()
    live = LiveSensorPipeline(SentinelConfig(), packets, EventBus(), metrics, detector,
                              db=db, event_loop=asyncio.get_running_loop())
    live.start()
    await asyncio.to_thread(live.stop)
    assert packets.unfinished_tasks == 0
    assert metrics.flows_completed == metrics.events_persisted == 1
    assert metrics.events_dropped == 0
    assert await db.get_event_count() == 1


@pytest.mark.asyncio
async def test_slow_and_fast_subscribers_have_separate_accounting(db, detector):
    from sentinel_net.sensor.event_output import persist_and_publish
    bus = EventBus(max_queue_size=1)
    slow = bus.subscribe('slow')
    fast = bus.subscribe('fast')
    metrics = SensorMetrics()
    await persist_and_publish(detected(detector), db, bus, metrics)
    first = fast.get_nowait()
    await persist_and_publish(detected(detector), db, bus, metrics)
    assert slow.qsize() == fast.qsize() == 1
    assert metrics.events_persisted == 2
    assert metrics.events_enqueued == 3
    assert metrics.events_dropped == bus.dropped_events == 1
    assert metrics.events_delivered == 0  # queue insertion is not socket delivery
    assert first['classification_score'] is not None


@pytest.mark.asyncio
async def test_db_failure_is_observable_and_never_broadcast(db, detector):
    from sentinel_net.sensor.event_output import persist_and_publish
    await db._conn.execute("CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL, 'test disk failure'); END")
    bus = EventBus()
    sub = bus.subscribe('test')
    metrics = SensorMetrics()
    with pytest.raises(Exception, match='test disk failure'):
        await persist_and_publish(detected(detector), db, bus, metrics)
    assert metrics.persistence_errors == metrics.processing_errors == 1
    assert metrics.detections_generated == 1
    assert metrics.events_persisted == metrics.events_enqueued == 0
    assert sub.empty()
    assert await db.get_flow_count() == await db.get_event_count() == 0


@pytest.mark.asyncio
async def test_live_persistence_failure_surfaces_at_shutdown(db, detector):
    from sentinel_net.sensor.pipeline import LiveSensorPipeline
    await db._conn.execute("CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(FAIL, 'failed'); END")
    packets = queue.Queue(maxsize=10)
    packets.put(extract_raw_packet(packet(time.time(), 'R')))
    metrics = SensorMetrics()
    live = LiveSensorPipeline(SentinelConfig(), packets, EventBus(), metrics, detector,
                              db=db, event_loop=asyncio.get_running_loop())
    live.start()
    with pytest.raises(RuntimeError, match='Live processing failed'):
        await live.astop()
    assert metrics.persistence_errors == 1
    assert packets.unfinished_tasks == 0


@pytest.mark.asyncio
async def test_live_idle_expiry_without_more_packets(db, detector):
    from sentinel_net.sensor.pipeline import LiveSensorPipeline
    packets = queue.Queue(maxsize=10)
    packets.put(extract_raw_packet(packet(time.time())))
    metrics = SensorMetrics()
    live = LiveSensorPipeline(SentinelConfig(flow_idle_timeout_sec=0.05), packets,
                              EventBus(), metrics, detector, db=db,
                              event_loop=asyncio.get_running_loop())
    live.start()
    try:
        async with asyncio.timeout(5):
            while metrics.events_persisted == 0:
                await asyncio.sleep(0.01)
        assert live._running.is_set()
        assert metrics.flows_completed == 1
        assert metrics.flows_evicted == 0  # expiry is not capacity eviction
    finally:
        await live.astop()
    assert await db.get_event_count() == 1


def test_out_of_order_packet_does_not_move_last_seen_backwards():
    agg = FlowAggregator(FlowAggregatorConfig(idle_timeout_sec=10))
    agg.ingest(parsed(1005))
    agg.ingest(parsed(1000))
    agg.expire_idle(1010)
    assert agg.active_flow_count == 1
    flow = agg.flush_all()[0]
    assert flow.start_time == 1000
    assert flow.end_time == 1005


@pytest.mark.parametrize('field,value', [('idle_timeout_sec', 0), ('max_active_flows', 0), ('fin_grace_sec', -1)])
def test_invalid_flow_policy_is_rejected(field, value):
    with pytest.raises(ValueError):
        FlowAggregatorConfig(**{field: value})


def test_enrichment_does_not_change_model_outputs(detector):
    event = detected(detector)
    X = np.array([event.feature_vector.values])
    transformed = detector.preprocessor.transform(X)
    label = str(detector.classifier.predict(transformed)[0])
    assert event.anomaly_result.anomaly_score == float(detector.anomaly_detector.score(transformed)[0])
    assert event.threat_classification.confidence == float(detector.classifier.predict_scores(transformed)[label][0])
    assert event.severity == detector.thresholds.get_severity(event.anomaly_result.anomaly_score)
    assert event.metadata['classification_score_class'] == label


def test_statistical_evidence_attached_with_correct_names(detector):
    from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
    detector._anomaly_explainer = AnomalyExplainer(
        feature_names=detector.preprocessor.output_feature_names).fit(np.zeros((2, FEATURE_COUNT)))
    event = detected(detector)
    evidence = event.to_dict()['evidence']
    assert evidence['explanation_available']
    statistical = [item for item in evidence['items'] if item['evidence_type'] == 'statistical']
    assert statistical
    transformed = detector.preprocessor.transform(np.array([event.feature_vector.values]))[0]
    for item in statistical:
        idx = detector.preprocessor.output_feature_names.index(item['feature_name'])
        assert item['observed_value'] == transformed[idx]
        assert item['source'] == 'training_distribution'


def test_dropped_training_columns_do_not_mislabel_evidence():
    X = np.ones((4, FEATURE_COUNT))
    X[:, 3] = np.nan
    pp = FeaturePreprocessor()
    transformed = pp.fit_transform(X)
    assert len(pp.output_feature_names) == transformed.shape[1] == FEATURE_COUNT - 1
    assert 'packets_per_sec' not in pp.output_feature_names


@pytest.mark.asyncio
async def test_legacy_event_migrates_without_invented_confidence(tmp_path):
    import sqlite3
    from sentinel_net.storage.database import Database
    path = tmp_path/'legacy.db'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE events (id TEXT PRIMARY KEY, timestamp REAL, flow_id TEXT, severity TEXT, threat_type TEXT, anomaly_score REAL, model_version TEXT, feature_schema_version TEXT, explanation_version TEXT, rationale TEXT, metadata TEXT, created_at REAL)')
        conn.execute("INSERT INTO events VALUES ('old', 1, NULL, 'low', 'benign', 0.2, '1', '2.0.0', NULL, '', '{}', 1)")
    db = Database(path)
    await db.initialize()
    try:
        record = await db.get_event_by_id('old')
        assert record['event_id'] == 'old'
        assert record['event_schema_version'] == '1.0.0'
        assert record['classification_score'] is None
        assert record['classification_score_type'] is None
        assert record['evidence']['explanation_available'] is False
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_replay_idle_event_is_persisted_before_eof(tmp_path, db, detector, monkeypatch):
    from sentinel_net import demo_replay
    from sentinel_net.sensor.sources import PcapReplaySource, ReadKind
    from sentinel_net.sensor.lifecycle import SensorLifecycle
    pcap = tmp_path/'idle.pcap'
    wrpcap(str(pcap), [packet(1000), packet(1002, sport=5555), packet(1002.1, sport=5555)])
    async def trained(_):
        return detector
    monkeypatch.setattr(demo_replay, 'load_detection_pipeline', trained)
    original = PcapReplaySource.read
    checked_before_eof = []
    loop = asyncio.get_running_loop()
    read_count = 0
    def observe(self, timeout=.1):
        nonlocal read_count
        # The shared worker has completed output before asking for packet 3.
        if read_count == 2:
            checked_before_eof.append(asyncio.run_coroutine_threadsafe(
                db.get_event_count(), loop).result())
        result = original(self, timeout)
        if result.kind == ReadKind.PACKET:
            read_count += 1
        return result
    monkeypatch.setattr(PcapReplaySource, 'read', observe)
    metrics = SensorMetrics()
    await demo_replay.run_replay(demo_replay.DemoReplayConfig(pcap, tmp_path, realtime=False,
                                  flow_idle_timeout=1), db, EventBus(), SensorLifecycle(), metrics)
    assert checked_before_eof == [1]
    assert metrics.flows_completed == metrics.events_persisted == 2
    assert metrics.flows_evicted == 0


@pytest.mark.asyncio
async def test_replay_failure_sets_error_lifecycle(tmp_path, db, detector, monkeypatch):
    from sentinel_net import demo_replay
    from sentinel_net.sensor.lifecycle import SensorLifecycle, SensorState
    pcap = tmp_path/'failed.pcap'
    wrpcap(str(pcap), [packet()])
    async def trained(_):
        return detector
    monkeypatch.setattr(demo_replay, 'load_detection_pipeline', trained)
    async def unavailable(_):
        raise RuntimeError('Database not initialized')
    monkeypatch.setattr(db, 'store_event', unavailable)
    metrics = SensorMetrics()
    lifecycle = SensorLifecycle()
    with pytest.raises(RuntimeError, match='Database not initialized'):
        await demo_replay.run_replay(demo_replay.DemoReplayConfig(pcap, tmp_path, realtime=False),
                                     db, EventBus(), lifecycle, metrics)
    assert lifecycle.state == SensorState.ERROR
    assert metrics.persistence_errors == metrics.processing_errors == 1
    assert metrics.events_persisted == 0


@pytest.mark.asyncio
async def test_empty_replay_produces_no_fake_events(tmp_path, db, detector, monkeypatch):
    from scapy.utils import PcapWriter
    from sentinel_net import demo_replay
    from sentinel_net.sensor.lifecycle import SensorLifecycle
    pcap = tmp_path/'empty.pcap'
    with PcapWriter(str(pcap), linktype=1) as writer:
        writer.write_header(None)
    async def trained(_):
        return detector
    monkeypatch.setattr(demo_replay, 'load_detection_pipeline', trained)
    metrics = SensorMetrics()
    result = await demo_replay.run_replay(demo_replay.DemoReplayConfig(pcap, tmp_path, realtime=False),
                                         db, EventBus(), SensorLifecycle(), metrics)
    assert result['total_packets'] == result['total_flows'] == result['total_detections'] == 0
    assert metrics.events_dropped == await db.get_event_count() == 0


def test_explanation_failure_does_not_suppress_detection(detector, monkeypatch):
    first = detected(detector)
    def fail(*args):
        raise RuntimeError('explanation failed')
    monkeypatch.setattr(detector._enricher.classifier_explainer, 'explain', fail)
    second = detected(detector)
    assert second.threat_classification.confidence == first.threat_classification.confidence
    evidence = second.to_dict()['evidence']
    assert not evidence['explanation_available']
    assert 'Classifier explanation failed' in evidence['unavailable_reason']


@pytest.mark.asyncio
async def test_duplicate_event_rollback_preserves_previous_record(db, detector):
    event = detected(detector)
    await db.store_event(event)
    before = await db.get_event_by_id(event.id)
    with pytest.raises(Exception, match='UNIQUE constraint'):
        await db.store_event(event)
    assert await db.get_event_by_id(event.id) == before
    assert await db.get_flow_count() == await db.get_event_count() == 1


def test_batch_and_single_inference_preserve_scores_and_semantics(detector):
    event = detected(detector)
    batch = detector.detect_batch([event.feature_vector], [event.observed_flow])[0]
    keys = ['flow_id', 'threat_class', 'classification_score', 'classification_score_type',
            'classification_score_class', 'anomaly_score', 'anomaly_score_type',
            'severity', 'model_version', 'anomaly_model_version', 'feature_schema_version']
    assert {k: event.to_dict()[k] for k in keys} == {k: batch.to_dict()[k] for k in keys}


@pytest.mark.asyncio
async def test_multiple_events_can_reference_one_flow(db, detector):
    event = detected(detector)
    second = detector.detect_single(event.feature_vector, event.observed_flow)
    await db.store_event(event)
    await db.store_event(second)
    assert await db.get_flow_count() == 1
    assert await db.get_event_count() == 2
    assert event.flow_id == second.flow_id


@pytest.mark.asyncio
async def test_legacy_enriched_metadata_keeps_its_evidence(db, detector):
    event = detected(detector)
    record = event.to_dict()
    legacy = dict(record)
    legacy.pop('evidence')
    legacy.pop('event_schema_version')
    item = {'feature_name': 'total_packets', 'observed_value': 10, 'reference_value': 1,
            'contribution': 9, 'direction': 'increase', 'evidence_type': 'statistical',
            'source': 'training_distribution', 'model_name': 'isolation_forest',
            'model_version': '1.0.0', 'feature_schema_version': '2.0.0'}
    legacy['metadata'] = {'anomaly_evidence': {'items': [item], 'explanation_available': True}}
    assert db._event_record(legacy)['evidence']['items'] == [item]


def test_epoch_zero_is_a_valid_flow_start():
    agg = FlowAggregator()
    agg.ingest(parsed(0))
    agg.ingest(parsed(0.5))
    flow = agg.flush_all()[0]
    assert flow.start_time == 0
    assert flow.duration_sec == 0.5
