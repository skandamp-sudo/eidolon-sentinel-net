"""Real PCAP -> real ML -> SQLite -> authenticated REST/WS contract coverage."""
import json
import os
from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient
from scapy.all import wrpcap

from sentinel_net.api.main import create_app
from sentinel_net.config import get_config
from sentinel_net.demo_replay import DemoReplayConfig, run_replay
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.features.schema import FEATURE_COUNT
from sentinel_net.sensor.lifecycle import SensorLifecycle, SensorState
from tests.unit.test_rw1_correctness import packet


def test_real_replay_rest_and_authenticated_websocket(tmp_path, monkeypatch):
    from sentinel_net import demo_replay
    rng = np.random.RandomState(42)
    X = rng.normal(size=(50, FEATURE_COUNT))
    y = np.array(['benign']*25 + ['ddos']*25)
    pp = FeaturePreprocessor()
    transformed = pp.fit_transform(X)
    pipeline = DetectionPipeline(
        pp, AnomalyDetector(n_estimators=5).train(transformed[:25]),
        XGBoostClassifier(n_estimators=5, max_depth=2).train(transformed, y),
        anomaly_explainer=AnomalyExplainer(feature_names=pp.output_feature_names).fit(transformed[:25]))
    from tests.unit.test_sensor_runtime_model import save_pipeline
    save_pipeline(tmp_path/'registry', pipeline)
    monkeypatch.setattr(type(pipeline.classifier), 'train', lambda *_: (_ for _ in ()).throw(AssertionError('runtime training')))
    pcap = tmp_path/'real.pcap'
    wrpcap(str(pcap), [packet(1000, 'S'), packet(1000.1), packet(1000.2, 'R'),
                      packet(1000.3, sport=1235), packet(1003, sport=1236),
                      packet(1003.1, 'FA', sport=1236)])
    monkeypatch.setenv('SENTINEL_DATABASE_PATH', str(tmp_path/'real.db'))
    monkeypatch.setenv('SENTINEL_API_KEY', 'rw1-local-key')
    get_config.cache_clear()
    app = create_app()
    try:
        with TestClient(app) as client:
            with client.websocket_connect('/api/v1/ws/events') as ws:
                ws.send_json({'type': 'auth', 'api_key': 'rw1-local-key'})
                assert ws.receive_json() == {'type': 'auth_ok'}
                lifecycle = SensorLifecycle()
                result = client.portal.call(
                    run_replay, DemoReplayConfig(pcap, "runtime/1.0.0", model_registry=tmp_path/"registry", realtime=False, flow_idle_timeout=1),
                    app.state.db, app.state.event_bus, lifecycle, app.state.sensor_metrics)
                assert lifecycle.state == SensorState.REPLAY_COMPLETE
                assert result['total_flows'] == result['events_persisted'] == 3
                messages = []
                while len(messages) < 3:
                    message = ws.receive_json()
                    if message['type'] == 'event':
                        messages.append(message['data'])
                headers = {'X-API-Key': 'rw1-local-key'}
                listed = client.get('/api/v1/events', headers=headers).json()['events']
                assert {e['id'] for e in messages} == {e['id'] for e in listed}
                for record in messages:
                    detail = client.get('/api/v1/events/'+record['id'], headers=headers).json()
                    assert detail == record == next(e for e in listed if e['id'] == record['id'])
                    assert record['model_name'] == 'runtime'
                    assert record['deployment_model_version'] == '1.0.0'
                    assert str(tmp_path) not in json.dumps(record)
                    assert record['source_mode'] == 'REPLAY'
                    assert record['replay_file_identifier']
                    assert str(pcap) not in json.dumps(record)
                    assert record['event_id'] == record['id']
                    assert record['threat_class'] == record['threat_type']
                    assert record['classification_score_type'] == 'uncalibrated_classifier_score'
                    assert record['anomaly_score_type'] == 'normalized_anomaly_score'
                    assert record['evidence']['items']
                    flow = client.get('/api/v1/flows/'+record['flow_id'], headers=headers).json()
                    assert flow['id'] == record['flow_id']
                assert app.state.sensor_metrics.events_delivered == 3
                assert app.state.sensor_metrics.events_dropped == 0
                assert app.state.sensor_metrics.flows_active == 0
                # Optional export for the frontend consumer/rendering contract test.
                export = os.environ.get('SENTINEL_RW1_EVENT_FIXTURE')
                if export:
                    Path(export).parent.mkdir(parents=True, exist_ok=True)
                    Path(export).write_text(json.dumps(messages[0], indent=2)+'\n')
    finally:
        get_config.cache_clear()
