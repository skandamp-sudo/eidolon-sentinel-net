"""Actual TLS/QUIC PCAP -> frozen inference -> SQLite -> authenticated REST/WS."""

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import wrpcap

from sentinel_net.api.main import create_app
from sentinel_net.config import get_config
from sentinel_net.demo_replay import DemoReplayConfig, run_replay
from sentinel_net.sensor.lifecycle import SensorLifecycle
from tests.unit.test_encrypted_parity import sequence
from tests.unit.test_passive_sources import real_detector
from tests.unit.test_sensor_runtime_model import save_pipeline


@pytest.mark.parametrize("case", ["both", "quic"])
def test_encrypted_sqlite_rest_websocket_and_frontend_fixture(tmp_path, monkeypatch, case):
    registry = os.environ.get("SENTINEL_F5_QA_REGISTRY")
    if not registry:
        registry = tmp_path / "registry"
        detector = real_detector.__wrapped__()
        save_pipeline(registry, detector)
        monkeypatch.setattr(
            type(detector.classifier),
            "train",
            lambda *_: (_ for _ in ()).throw(AssertionError("runtime training")),
        )
    pcap = tmp_path / "encrypted.pcap"
    wrpcap(str(pcap), sequence(case))
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(tmp_path / "encrypted.db"))
    monkeypatch.setenv("SENTINEL_API_KEY", "f5-local-test-key")
    get_config.cache_clear()
    app = create_app()
    try:
        with TestClient(app) as client, client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_json({"type": "auth", "api_key": "f5-local-test-key"})
            assert ws.receive_json() == {"type": "auth_ok"}
            result = client.portal.call(
                run_replay,
                DemoReplayConfig(
                    pcap, "runtime/1.0.0", model_registry=Path(registry), realtime=False
                ),
                app.state.db,
                app.state.event_bus,
                SensorLifecycle(),
                app.state.sensor_metrics,
            )
            assert result["events_persisted"] == 1
            message = ws.receive_json()
            while message["type"] != "event":
                message = ws.receive_json()
            record = message["data"]
            headers = {"X-API-Key": "f5-local-test-key"}
            assert client.get("/api/v1/events/" + record["id"], headers=headers).json() == record
            assert client.get("/api/v1/events", headers=headers).json()["events"] == [record]
            assert client.portal.call(app.state.db.get_event_by_id, record["id"]) == record
            family = "tls" if case == "both" else "quic"
            assert record[family + "_status"] == "COMPLETE"
            assert record[family + "_evidence"]
            assert family + "_metadata" in record["detection_source"]
            assert record[family + "_observation"]["visibility"] == (
                "BOTH" if case == "both" else "ONE_DIRECTION_OBSERVED"
            )
            assert record["feature_schema_version"] == "2.0.0"
            export = os.environ.get("SENTINEL_F5_FIXTURE_DIR")
            if export:
                (Path(export) / ("f5-" + family + "-event.json")).write_text(
                    json.dumps(record, indent=2) + "\n"
                )
    finally:
        get_config.cache_clear()
