"""RW-3 source, clock, cancellation, parity and failure contracts."""
import asyncio
import copy
from dataclasses import asdict
import json
import queue
import threading
import time
from types import SimpleNamespace

import numpy as np
import pytest
from scapy.all import Ether, ARP, wrpcap
from scapy.utils import PcapWriter, PcapReader

from sentinel_net.config import SentinelConfig
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.ingestion.parser import extract_raw_packet
from sentinel_net.sensor.sources import (PassivePacketSource, LiveCaptureSource,
    PcapReplaySource, SourceError, SourceMode, SourceRead, ReadKind)
from sentinel_net.sensor.pipeline import PacketProcessingPipeline
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.lifecycle import SensorLifecycle, SensorState
from sentinel_net.storage.database import Database
from tests.unit.test_rw1_correctness import packet, detector
from tests.unit.test_sensor_service import FakeCapture, until


@pytest.fixture
def real_detector():
    rng = np.random.RandomState(42)
    x = rng.normal(size=(40, FEATURE_COUNT))
    labels = np.array(['benign']*20+['ddos']*20)
    pp = FeaturePreprocessor()
    transformed = pp.fit_transform(x)
    return DetectionPipeline(pp, AnomalyDetector(n_estimators=5).train(transformed[:20]),
        XGBoostClassifier(n_estimators=5, max_depth=2).train(transformed, labels),
        anomaly_explainer=AnomalyExplainer(feature_names=pp.output_feature_names).fit(transformed[:20]))


class RecordingDetection:
    def __init__(self, detection):
        self.detection, self.vectors, self.flows = detection, [], []
        self.deployment_identity = getattr(detection, "deployment_identity", None)

    def detect_batch(self, vectors, flows):
        self.vectors.extend(vectors)
        self.flows.extend(flows)
        return self.detection.detect_batch(vectors, flows)


def canonical_event(event):
    event = copy.deepcopy(event)
    event['metadata'].pop('source', None)
    # UUID identities and runtime creation times are intentionally per run.
    ignored = {'id','event_id','flow_id','timestamp','created_at',
               'source_mode','capture_interface','replay_file_identifier',
               'detection_event_id','explanation_id','generation_timestamp'}
    def clean(value):
        if isinstance(value, dict):
            return {k:clean(v) for k,v in value.items() if k not in ignored}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    return clean(event)


async def run_source(source, metrics, path, detection, *, limit=100):
    db = Database(path)
    await db.initialize()
    recording = RecordingDetection(detection)
    pipeline = PacketProcessingPipeline(SentinelConfig(flow_idle_timeout_sec=1,
        max_active_flows=limit), source, EventBus(), metrics, recording,
        db=db, event_loop=asyncio.get_running_loop())
    try:
        pipeline.start()
        if source.mode == SourceMode.LIVE:
            await pipeline.astop()
        else:
            await pipeline.wait()
        events = await db.get_events(limit=200)
        await pipeline.astop()  # repeated completion cannot finalize twice
        assert await db.get_event_count() == len(events)
        return recording, events, pipeline
    finally:
        if pipeline.alive:
            await pipeline.astop()
        await db.close()


CASES = {
 'fin': [packet(1000,'S'),packet(1000.1,'FA'),packet(1000.2),packet(1002,sport=2000)],
 'rst': [packet(1000,'S'),packet(1000.1,'R'),packet(1000.2)],
 'idle': [packet(1000),packet(1002,sport=2000)],
 'tuple_reuse': [packet(1000),packet(1002)],
 'eof_shutdown': [packet(1000),packet(1000.1)],
 'capacity': [packet(1000,sport=1000),packet(1000.1,sport=1001),packet(1000.2,sport=1002)],
 'out_of_order': [packet(1000.2),packet(1000.1),packet(1000.3)],
}


@pytest.mark.parametrize('case', list(CASES))
async def test_live_replay_features_scores_flows_and_events_are_equivalent(tmp_path, real_detector, case):
    from tests.unit.test_sensor_runtime_model import save_pipeline, load
    path = save_pipeline(tmp_path/'registry', real_detector)
    real_detector = load(path)
    packets = CASES[case]
    pcap = tmp_path/'private-name.pcap'
    wrpcap(str(pcap), packets)
    lm, rm = SensorMetrics(), SensorMetrics()
    q = queue.Queue(20)
    for p in packets:
        q.put(extract_raw_packet(p))
        lm.increment('packets_observed')
    live = LiveCaptureSource(q, lm, interface='test0', clock=lambda:1000)
    replay = PcapReplaySource(pcap, rm)
    assert isinstance(live, PassivePacketSource) and isinstance(replay, PassivePacketSource)
    limit = 1 if case == 'capacity' else 100
    l, le, lp = await run_source(live, lm, tmp_path/'live.db', real_detector, limit=limit)
    r, re, rp = await run_source(replay, rm, tmp_path/'replay.db', real_detector, limit=limit)
    assert lp.completion == 'cancelled' and rp.completion == 'eof'
    assert len(le) == len(re) > 0
    assert len({e['id'] for e in le+re}) == len(le)+len(re)
    assert q.unfinished_tasks == 0
    assert [asdict(v) for v in l.vectors] == [asdict(v) for v in r.vectors]
    for a,b in zip(l.flows,r.flows):
        fa,fb = asdict(a),asdict(b)
        fa.pop('id');fb.pop('id')
        assert fa == fb
    # Database listing order is newest-first; compare by deterministic flow key and timestamp-independent record.
    lrecords = sorted((canonical_event(e) for e in le),key=lambda e:json.dumps(e,sort_keys=True))
    rrecords = sorted((canonical_event(e) for e in re),key=lambda e:json.dumps(e,sort_keys=True))
    assert lrecords == rrecords
    assert all(e['model_name']=='runtime' and e['deployment_model_version']=='1.0.0' for e in le+re)
    assert all(e['source_mode']=='LIVE' and e['capture_interface']=='test0' for e in le)
    assert all(e['source_mode']=='REPLAY' and e['replay_file_identifier'] for e in re)
    assert str(pcap) not in json.dumps(re) and pcap.name not in json.dumps(re)
    assert lm.flows_active == rm.flows_active == 0
    assert lm.flows_evicted == rm.flows_evicted == (2 if case=='capacity' else 0)
    assert 0 <= rm.processing_time_sec < 10  # recorded epoch 1000 must not imply decades of latency


def test_replay_timestamp_order_and_eof_are_preserved(tmp_path):
    pcap = tmp_path/'ordered.pcap'
    wrpcap(str(pcap), [packet(1000.2),packet(1000.1),packet(1000.3)])
    source = PcapReplaySource(pcap, SensorMetrics())
    source.start()
    assert [source.read().packet.timestamp for _ in range(3)] == [1000.2,1000.1,1000.3]
    assert source.read().kind == source.read().kind == ReadKind.EOF
    assert source._reader is None
    source.stop()
    assert source.read().kind == ReadKind.EOF


def test_replay_pacing_has_no_wall_clock_expiry_and_stop_drains_accepted_packet(tmp_path):
    pcap = tmp_path/'paced.pcap'
    wrpcap(str(pcap), [packet(1000),packet(99999),packet(100000)])
    source = PcapReplaySource(pcap, SensorMetrics(), realtime=True)
    source.start()
    first = source.read()
    assert first.packet.timestamp == 1000
    idle = source.read(timeout=.001)
    assert idle.kind == ReadKind.IDLE and idle.idle_watermark is None
    before = time.monotonic()
    source.stop()
    assert source.read().packet.timestamp == 99999  # already read, accepted before stop
    assert source.read().kind == ReadKind.CANCELLED
    assert time.monotonic()-before < .5
    assert source.metrics.packets_observed == 2


async def test_paced_replay_cancellation_preserves_active_flow(tmp_path, detector):
    pcap = tmp_path/'paced.pcap'
    wrpcap(str(pcap), [packet(1000),packet(1000.1),packet(1000.2)])
    metrics = SensorMetrics()
    source = PcapReplaySource(pcap, metrics, realtime=True, speed=.000001)
    db = Database(tmp_path/'paced.db');await db.initialize()
    pipeline = PacketProcessingPipeline(SentinelConfig(), source, EventBus(), metrics, detector,
        db=db, event_loop=asyncio.get_running_loop())
    pipeline.start()
    try:
        await until(lambda:metrics.packets_observed==2)
        assert metrics.events_persisted == 0 and metrics.flows_active == 1
        await asyncio.wait_for(pipeline.astop(),2)
        assert metrics.packets_processed == 2 and metrics.events_persisted == 1
        assert pipeline.completion == 'cancelled'
    finally:
        await db.close()


async def test_empty_replay_and_idle_live_terminate_without_events(tmp_path, detector):
    pcap = tmp_path/'empty.pcap'
    with PcapWriter(str(pcap),linktype=1) as writer: writer.write_header(None)
    for mode in ('live','replay'):
        metrics = SensorMetrics()
        source = LiveCaptureSource(queue.Queue(2),metrics) if mode=='live' else PcapReplaySource(pcap,metrics)
        _,events,pipeline = await asyncio.wait_for(run_source(source,metrics,tmp_path/(mode+'.db'),detector),2)
        assert events == [] and metrics.packets_observed == 0
        assert not pipeline.alive


@pytest.mark.parametrize('mode',['live','replay'])
async def test_source_error_is_distinct_and_flushes_accepted_flows(tmp_path, detector, mode):
    metrics = SensorMetrics()
    if mode=='replay':
        pcap=tmp_path/'bad.pcap';wrpcap(str(pcap),[packet()])
        class Reader:
            def __init__(self,_): self.count=0;self.closed=False
            def read_packet(self):
                self.count+=1
                if self.count==1:return packet()
                raise OSError('private-path-secret')
            def close(self):self.closed=True
        source=PcapReplaySource(pcap,metrics,reader_factory=Reader)
    else:
        q=queue.Queue(2);q.put(extract_raw_packet(packet()))
        source=LiveCaptureSource(q,metrics,capture=SimpleNamespace(start=lambda:None,stop=lambda:None,failed=True))
    db=Database(tmp_path/'failure.db');await db.initialize()
    pipeline=PacketProcessingPipeline(SentinelConfig(),source,EventBus(),metrics,detector,
                                      db=db,event_loop=asyncio.get_running_loop())
    pipeline.start()
    try:
        with pytest.raises(SourceError): await pipeline.wait()
        assert pipeline.failed and pipeline.completion=='source_error'
        assert metrics.source_errors == 1 and metrics.last_error_kind=='SOURCE_ERROR'
        assert metrics.events_persisted == 1 and metrics.flows_active==0
    finally: await db.close()


async def test_malformed_packet_is_skipped_not_detected(tmp_path, detector):
    pcap=tmp_path/'arp.pcap';wrpcap(str(pcap),[Ether()/ARP()])
    metrics=SensorMetrics()
    _,events,_=await run_source(PcapReplaySource(pcap,metrics),metrics,tmp_path/'arp.db',detector)
    assert events==[] and metrics.packets_malformed==1 and metrics.packets_processed==0


async def test_replay_parser_exception_is_processing_error_and_stops(tmp_path, detector, monkeypatch):
    from sentinel_net.sensor import pipeline as module
    pcap=tmp_path/'parser.pcap';wrpcap(str(pcap),[packet(),packet(1001)])
    def fail(_): raise ValueError('parser failed')
    monkeypatch.setattr(module,'parse_packet',fail)
    metrics=SensorMetrics();source=PcapReplaySource(pcap,metrics)
    db=Database(tmp_path/'parser.db');await db.initialize()
    pipeline=PacketProcessingPipeline(SentinelConfig(),source,EventBus(),metrics,detector,
                                      db=db,event_loop=asyncio.get_running_loop())
    pipeline.start()
    try:
        with pytest.raises(ValueError,match='parser failed'):await pipeline.wait()
        assert metrics.last_error_kind=='PROCESSING_ERROR' and metrics.source_errors==0
        assert metrics.packets_observed==1 and metrics.detections_generated==0
        assert source._reader is None
    finally:await db.close()


@pytest.mark.parametrize('failure',['persist','publish'])
async def test_persistence_and_output_errors_are_distinct(tmp_path, detector, monkeypatch, failure):
    pcap=tmp_path/'output.pcap';wrpcap(str(pcap),[packet()])
    metrics=SensorMetrics();source=PcapReplaySource(pcap,metrics)
    db=Database(tmp_path/'output.db');await db.initialize();bus=EventBus()
    if failure=='persist':
        async def broken(_):raise OSError('write failed')
        monkeypatch.setattr(db,'store_event',broken)
    else:
        def broken(_):raise OSError('output failed')
        monkeypatch.setattr(bus,'publish_result',broken)
    pipeline=PacketProcessingPipeline(SentinelConfig(),source,bus,metrics,detector,
        db=db,event_loop=asyncio.get_running_loop());pipeline.start()
    try:
        with pytest.raises(OSError):await pipeline.wait()
        assert metrics.last_error_kind==('PERSISTENCE_ERROR' if failure=='persist' else 'OUTPUT_ERROR')
        assert metrics.persistence_errors==(1 if failure=='persist' else 0)
        assert metrics.output_errors==(1 if failure=='publish' else 0)
        assert await db.get_event_count()==(0 if failure=='persist' else 1)
        assert metrics.events_enqueued==0
    finally:await db.close()


async def test_pull_replay_does_not_read_ahead_of_slow_inference(tmp_path, detector, monkeypatch):
    pcap=tmp_path/'slow.pcap';wrpcap(str(pcap),[packet(1000+i,'R',sport=1000+i) for i in range(50)])
    entered,release=threading.Event(),threading.Event();original=detector.detect_batch
    def delayed(*args):
        entered.set();assert release.wait(5);return original(*args)
    monkeypatch.setattr(detector,'detect_batch',delayed)
    metrics=SensorMetrics();source=PcapReplaySource(pcap,metrics)
    db=Database(tmp_path/'slow.db');await db.initialize()
    pipeline=PacketProcessingPipeline(SentinelConfig(),source,EventBus(),metrics,detector,
        db=db,event_loop=asyncio.get_running_loop());pipeline.start()
    try:
        await until(entered.is_set)
        assert metrics.packets_observed==1 and source._pending is None
        source.stop();release.set();await pipeline.wait()
        assert metrics.packets_processed==metrics.events_persisted==1
    finally:release.set();await db.close()


async def test_replay_task_cancellation_drains_before_return(tmp_path, detector, monkeypatch):
    from sentinel_net import demo_replay
    pcap=tmp_path/'cancel.pcap';wrpcap(str(pcap),[packet(1000),packet(1000.1),packet(1000.2)])
    async def loaded(_):return detector
    monkeypatch.setattr(demo_replay,'load_detection_pipeline',loaded)
    metrics=SensorMetrics();lifecycle=SensorLifecycle();db=Database(tmp_path/'cancel.db');await db.initialize()
    task=asyncio.create_task(demo_replay.run_replay(demo_replay.DemoReplayConfig(
        pcap,tmp_path,realtime=True,speed=.000001),db,EventBus(),lifecycle,metrics))
    try:
        await until(lambda:metrics.packets_observed==2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await asyncio.wait_for(task,2)
        assert lifecycle.state==SensorState.STOPPED
        assert metrics.packets_processed==2 and await db.get_event_count()==1
    finally:await db.close()


async def test_replay_rejects_unready_database_before_reading(tmp_path, detector, monkeypatch):
    from sentinel_net import demo_replay
    pcap=tmp_path/'db.pcap';wrpcap(str(pcap),[packet()])
    async def loaded(_):return detector
    monkeypatch.setattr(demo_replay,'load_detection_pipeline',loaded)
    lifecycle=SensorLifecycle();metrics=SensorMetrics();db=Database(tmp_path/'db.db')
    with pytest.raises(ValueError,match='must be ready'):
        await demo_replay.run_replay(demo_replay.DemoReplayConfig(pcap,tmp_path),db,EventBus(),lifecycle,metrics)
    assert lifecycle.state==SensorState.ERROR and metrics.packets_observed==0


@pytest.mark.parametrize('speed',[0,-1,float('inf'),float('nan')])
def test_invalid_replay_speed_is_source_error(tmp_path,speed):
    pcap=tmp_path/'speed.pcap';wrpcap(str(pcap),[packet()])
    metrics=SensorMetrics();source=PcapReplaySource(pcap,metrics,speed=speed)
    with pytest.raises(SourceError):source.start()
    assert metrics.source_errors==1


def test_replay_open_failure_is_source_error_without_path_exposure(tmp_path):
    metrics=SensorMetrics();source=PcapReplaySource(tmp_path/'private.pcap',metrics)
    with pytest.raises(SourceError) as error:source.start()
    assert str(tmp_path) not in str(error.value) and metrics.source_errors==1
