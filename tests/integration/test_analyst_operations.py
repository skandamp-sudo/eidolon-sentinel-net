"""Authenticated export, adversarial identifiers, retention and admission bounds."""

import asyncio
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from sentinel_net.api.main import create_app
from sentinel_net.api.routes.operations import BoundedResponse
from sentinel_net.config import get_config
from tests.unit.test_investigation import event


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SENTINEL_API_KEY", "local-test-key")
    get_config.cache_clear()
    with TestClient(create_app()) as c:
        c.portal.call(c.app.state.retention.stop)
        yield c
    get_config.cache_clear()


HEADERS = {"X-API-Key": "local-test-key"}


def store(client, record=None, encoded=None):
    r = record or event()

    async def insert():
        c = client.app.state.db._conn
        await c.execute(
            "INSERT INTO events (id,timestamp,flow_id,severity,created_at,event_json) VALUES (?,?,?,?,?,?)",
            (
                r["id"],
                r["timestamp"],
                r["flow_id"],
                r["severity"],
                r["created_at"],
                encoded if encoded is not None else json.dumps(r),
            ),
        )
        await c.commit()

    client.portal.call(insert)


def test_export_auth_identity_hash_and_retention(client):
    store(client)
    url = "/api/v1/events/event-1/export"
    assert client.get(url).status_code == 401
    assert client.get(url, headers={"X-API-Key": "wrong"}).status_code == 401
    a = client.get(url, headers=HEADERS)
    assert a.status_code == 200
    assert a.headers["x-content-sha256"] == hashlib.sha256(a.content).hexdigest()
    assert a.headers["cache-control"] == "no-store"
    assert "sentinel-investigation-" in a.headers["content-disposition"]
    assert a.content == client.get(url, headers=HEADERS).content
    assert a.json() == client.get("/api/v1/events/event-1/investigation", headers=HEADERS).json()
    client.portal.call(client.app.state.db.cleanup_old_events, 0, None)
    assert client.get(url, headers=HEADERS).status_code == 404


@pytest.mark.parametrize(
    "identifier", ["missing", "..%2F..%2Fetc%2Fpasswd", "%2e%2e", "x%27%20OR%201=1", "x" * 129]
)
def test_identifier_manipulation(client, identifier):
    store(client)
    r = client.get("/api/v1/events/" + identifier + "/export", headers=HEADERS)
    assert r.status_code in (404, 422)
    assert "traceback" not in r.text.lower()


@pytest.mark.parametrize(
    "encoded",
    [
        "{broken",
        "[]",
        '{"metadata":[]}',
        "x" * 131073,
        json.dumps(event(dns_observation={"directions": 3})),
    ],
)
def test_malformed_or_oversized_storage_rejected(client, encoded):
    store(client, encoded=encoded)
    r = client.get("/api/v1/events/event-1/export", headers=HEADERS)
    assert r.status_code == 422
    assert "traceback" not in r.text.lower()
    assert client.app.state.investigation_gate._value == 4


def test_query_bounds_pressure_and_stale_references(client):
    store(client)
    for i in range(40):
        store(client, event(id=f"related-{i}", timestamp=1001 + i))
    r = client.get("/api/v1/events/event-1/investigation", headers=HEADERS)
    assert len(r.json()["events"]) == 32
    assert any("32-event limit" in s for s in r.json()["limitations"])
    gate = client.app.state.investigation_gate
    for _ in range(4):
        client.portal.call(gate.acquire)
    assert client.get("/api/v1/events/event-1/export", headers=HEADERS).status_code == 429
    for _ in range(4):
        client.portal.call(gate.release)
    assert client.get("/api/v1/events/event-1/export", headers=HEADERS).status_code == 200


def test_readiness_unavailable_and_no_paths(client):
    r = client.get("/api/v1/assurance", headers=HEADERS)
    assert r.status_code == 200
    d = r.json()
    rows = {i["property"]: i["status"] for i in d["rows"]}
    assert rows["Model integrity"] == "UNAVAILABLE" and d["model_identity"] is None
    assert rows["Physical data-diode validation"] == "NOT VERIFIED"
    assert rows["Native real-interface capture"] == "NOT VERIFIED"
    assert d["science"]["c2_recall"] == 0
    assert "registry_path" not in r.text and "local-test-key" not in r.text
    assert client.get("/api/v1/assurance").status_code == 401


async def test_response_cancellation_releases_slow_client_slot():
    gate = asyncio.Semaphore(4)
    await gate.acquire()
    response = BoundedResponse(b"{}", gate=gate, headers={})

    async def send(message):
        await asyncio.sleep(60)

    async def receive():
        return {"type": "http.disconnect"}

    task = asyncio.create_task(response({"type": "http"}, receive, send))
    await asyncio.sleep(0)
    assert gate._value == 3
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert gate._value == 4


async def test_slow_send_timeout_releases_admission(monkeypatch):
    from sentinel_net.api.routes import operations

    monkeypatch.setattr(operations, "SEND_TIMEOUT_SECONDS", 0.01)
    gate = asyncio.Semaphore(4)
    await gate.acquire()
    response = BoundedResponse(b"{}", gate=gate, headers={})

    async def send(message):
        await asyncio.sleep(60)

    async def receive():
        return {"type": "http.disconnect"}

    with pytest.raises(TimeoutError):
        await response({"type": "http"}, receive, send)
    assert gate._value == 4
