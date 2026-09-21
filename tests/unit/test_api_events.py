"""Tests for API events, flows, stats, and status endpoints."""

from __future__ import annotations

import time

import pytest
from httpx import AsyncClient, ASGITransport

from sentinel_net.api.main import create_app
from sentinel_net.models.types import (
    DetectionEvent,
    FlowKey,
    ObservedFlow,
    AnomalyResult,
    ThreatClassification,
)
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.storage.database import Database


TEST_API_KEY = "test-key-events-12345"


@pytest.fixture
async def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SENTINEL_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(db_path))
    from sentinel_net.config import get_config
    get_config.cache_clear()

    app = create_app()
    db = Database(db_path)
    await db.initialize()
    app.state.db = db
    app.state.event_bus = EventBus(max_queue_size=10)
    app.state.sensor_metrics = SensorMetrics()
    app.state.sensor_lifecycle = None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    await db.close()
    app.state.event_bus.shutdown()
    get_config.cache_clear()


@pytest.fixture
async def db_with_events(tmp_path, monkeypatch):
    """Return (client, db) with pre-stored events."""
    db_path = tmp_path / "test_events.db"
    monkeypatch.setenv("SENTINEL_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(db_path))
    from sentinel_net.config import get_config
    get_config.cache_clear()

    app = create_app()
    db = Database(db_path)
    await db.initialize()
    app.state.db = db
    app.state.event_bus = EventBus(max_queue_size=10)
    app.state.sensor_metrics = SensorMetrics()
    app.state.sensor_lifecycle = None

    # Store some test events
    fk = FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    flow = ObservedFlow(
        flow_key=fk, direction="forward", start_time=time.time(),
        end_time=time.time() + 1, duration_sec=1.0, packet_count=5,
        byte_count=500, payload_byte_count=200,
    )
    for i in range(3):
        evt = DetectionEvent(
            id=f"evt-{i}", timestamp=time.time() + i, flow_key=fk,
            observed_flow=flow, severity="high" if i == 0 else "info",
            rationale="test",
            threat_classification=ThreatClassification(
                flow_key=fk, timestamp=time.time(), threat_type="ddos" if i == 0 else "benign",
                confidence=0.9, model_name="xgb", model_version="1.0",
            ),
            anomaly_result=AnomalyResult(
                flow_key=fk, timestamp=time.time(), anomaly_score=0.8 if i == 0 else 0.1,
                is_anomalous=i == 0, model_name="iforest", model_version="1.0",
            ),
            metadata={"feature_schema_version": "2.0.0"},
        )
        await db.store_event(evt)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, db

    await db.close()
    app.state.event_bus.shutdown()
    get_config.cache_clear()


class TestEventsAPI:
    @pytest.mark.asyncio
    async def test_list_events_empty(self, client):
        r = await client.get("/api/v1/events", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["events"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_events_requires_auth(self, client):
        r = await client.get("/api/v1/events")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_pagination_limits(self, client):
        r = await client.get("/api/v1/events?limit=0", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 422

        r = await client.get("/api/v1/events?limit=999", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_event_not_found(self, client):
        r = await client.get("/api/v1/events/nonexistent-id", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_list_with_data(self, db_with_events):
        client, db = db_with_events
        r = await client.get("/api/v1/events", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3
        assert len(data["events"]) == 3

    @pytest.mark.asyncio
    async def test_filter_by_threat_type(self, db_with_events):
        client, db = db_with_events
        r = await client.get("/api/v1/events?threat_type=ddos", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, db_with_events):
        client, db = db_with_events
        r = await client.get("/api/v1/events?severity=high", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_get_event_by_id(self, db_with_events):
        client, db = db_with_events
        r = await client.get("/api/v1/events/evt-0", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == "evt-0"


class TestFlowsAPI:
    @pytest.mark.asyncio
    async def test_list_flows_empty(self, client):
        r = await client.get("/api/v1/flows", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["flows"] == []

    @pytest.mark.asyncio
    async def test_list_flows_requires_auth(self, client):
        r = await client.get("/api/v1/flows")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_flow_not_found(self, client):
        r = await client.get("/api/v1/flows/nonexistent-id", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_pagination_validation(self, client):
        r = await client.get("/api/v1/flows?limit=-1", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_list_flows_with_data(self, db_with_events):
        """Events store associated flows."""
        client, db = db_with_events
        r = await client.get("/api/v1/flows", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert len(data["flows"]) >= 1


class TestStatsAPI:
    @pytest.mark.asyncio
    async def test_stats_empty(self, client):
        r = await client.get("/api/v1/stats", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 0

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self, client):
        r = await client.get("/api/v1/stats")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_stats_with_data(self, db_with_events):
        client, db = db_with_events
        r = await client.get("/api/v1/stats", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["total_events"] == 3


class TestStatusAPI:
    @pytest.mark.asyncio
    async def test_status(self, client):
        r = await client.get("/api/v1/status", headers={"X-API-Key": TEST_API_KEY})
        assert r.status_code == 200
        data = r.json()
        assert "sensor_state" in data
        assert data["feature_count"] == 52
        assert data["feature_schema_version"] == "2.0.0"

    @pytest.mark.asyncio
    async def test_status_requires_auth(self, client):
        r = await client.get("/api/v1/status")
        assert r.status_code == 401


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_no_stack_trace_in_errors(self, client):
        r = await client.get("/api/v1/events/bad-id", headers={"X-API-Key": TEST_API_KEY})
        body = r.text
        assert "Traceback" not in body
        assert "File " not in body

    @pytest.mark.asyncio
    async def test_no_secret_in_errors(self, client):
        r = await client.get("/api/v1/events", headers={"X-API-Key": "wrong"})
        assert TEST_API_KEY not in r.text
