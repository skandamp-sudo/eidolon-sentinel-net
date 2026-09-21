"""Real inference and storage behind fake passive input; no privileged capture."""
import time
import numpy as np
from fastapi.testclient import TestClient

from sentinel_net.api.main import create_app
from sentinel_net.config import get_config
from sentinel_net.detection.anomaly import AnomalyDetector
from sentinel_net.detection.classifier import XGBoostClassifier
from sentinel_net.detection.inference import DetectionPipeline
from sentinel_net.detection.preprocessing import FeaturePreprocessor
from sentinel_net.explainability.anomaly_explainer import AnomalyExplainer
from sentinel_net.features.schema import FEATURE_COUNT
from tests.unit.test_sensor_service import service
from tests.unit.test_rw1_correctness import packet
from sentinel_net.ingestion.parser import extract_raw_packet


def test_live_service_real_inference_rest_and_websocket(tmp_path, monkeypatch):
    rng = np.random.RandomState(42)
    data = rng.normal(size=(50, FEATURE_COUNT))
    labels = np.array(['benign']*25 + ['ddos']*25)
    pp = FeaturePreprocessor()
    x = pp.fit_transform(data)
    detector = DetectionPipeline(pp, AnomalyDetector(n_estimators=5).train(x[:25]),
        XGBoostClassifier(n_estimators=5, max_depth=2).train(x, labels),
        anomaly_explainer=AnomalyExplainer(feature_names=pp.output_feature_names).fit(x[:25]))
    from tests.unit.test_sensor_runtime_model import save_pipeline
    from sentinel_net.sensor.service import SensorService
    from sentinel_net.config import SentinelConfig
    from tests.unit.test_sensor_service import FakeCapture
    save_pipeline(tmp_path/'registry', detector)
    monkeypatch.setattr(type(detector.classifier), 'train', lambda *_: (_ for _ in ()).throw(AssertionError('runtime training')))
    s = SensorService(SentinelConfig(database_path=tmp_path/'live.db', capture_interface='test0',
        sensor_model='runtime/1.0.0', model_registry=tmp_path/'registry'),
        capture_factory=FakeCapture, interface_validator=lambda _:None)
    monkeypatch.setenv('SENTINEL_API_KEY', 'rw2-local-key')
    get_config.cache_clear()
    try:
        with TestClient(create_app(sensor_service=s)) as client:
            with client.websocket_connect('/api/v1/ws/events') as ws:
                ws.send_json({'type':'auth','api_key':'rw2-local-key'})
                assert ws.receive_json() == {'type':'auth_ok'}
                s.capture.emit(extract_raw_packet(packet(time.time(), 'R')))
                while True:
                    message = ws.receive_json()
                    if message['type'] == 'event':
                        break
                record = message['data']
                headers = {'X-API-Key':'rw2-local-key'}
                assert client.get('/api/v1/events/'+record['id'], headers=headers).json() == record
                assert record['model_name'] == 'runtime'
                assert record['deployment_model_version'] == '1.0.0'
                assert record['source_mode'] == 'LIVE'
                assert record['capture_interface'] == 'test0'
                assert record['replay_file_identifier'] is None
                assert record['evidence']['items']
                assert record['model_version'] and record['feature_schema_version'] == '2.0.0'
                assert s.metrics.events_persisted == s.metrics.events_delivered == 1
                assert client.get('/api/v1/status', headers=headers).json()['sensor_mode'] == 'live_passive_sensor'
                # A tail event is finalized and delivered while WS is still alive.
                s.capture.emit(extract_raw_packet(packet(time.time(), sport=2000)))
                client.portal.call(s.quiesce)
                while True:
                    tail = ws.receive_json()
                    if tail['type'] == 'event':
                        break
                assert tail['data']['id'] != record['id']
                assert s.metrics.events_persisted == 2
        assert not s.db.is_connected
    finally:
        get_config.cache_clear()
