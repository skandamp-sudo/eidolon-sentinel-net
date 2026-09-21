"""Tests for WebSocket event stream authentication.

Uses Starlette TestClient for synchronous WebSocket testing.
Focus on auth flow — streaming tested separately.
"""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from sentinel_net.api.main import create_app


TEST_API_KEY = "test-ws-key-12345"


@pytest.fixture
def ws_client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SENTINEL_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(db_path))
    monkeypatch.setenv("SENTINEL_WS_AUTH_TIMEOUT_SEC", "2")
    monkeypatch.setenv("SENTINEL_WS_HEARTBEAT_INTERVAL_SEC", "60")
    from sentinel_net.config import get_config
    get_config.cache_clear()

    app = create_app()
    with TestClient(app) as client:
        yield client

    get_config.cache_clear()


class TestWebSocketAuth:
    def test_auth_message_invalid(self, ws_client):
        """Invalid auth → auth_failed, connection closed."""
        with ws_client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_json({"type": "auth", "api_key": "wrong-key"})
            resp = ws.receive_json()
            assert resp["type"] == "auth_failed"

    def test_auth_missing_key(self, ws_client):
        """Auth message without api_key → failed."""
        with ws_client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_json({"type": "auth"})
            resp = ws.receive_json()
            assert resp["type"] == "auth_failed"

    def test_auth_bad_format(self, ws_client):
        """Non-JSON auth message → failed."""
        with ws_client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_text("not json")
            resp = ws.receive_json()
            assert resp["type"] == "auth_failed"

    def test_no_key_in_response(self, ws_client):
        """API key must never appear in responses."""
        with ws_client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_json({"type": "auth", "api_key": "wrong-key"})
            resp = ws.receive_json()
            resp_str = json.dumps(resp)
            assert "wrong-key" not in resp_str
            assert TEST_API_KEY not in resp_str

    def test_hmac_in_websocket_code(self):
        """WebSocket must use hmac.compare_digest."""
        from pathlib import Path
        ws_path = Path(__file__).resolve().parents[2] / "src" / "sentinel_net" / "api" / "routes" / "websocket.py"
        source = ws_path.read_text()
        assert "hmac.compare_digest" in source

    def test_valid_auth_gets_ok(self, ws_client):
        """Valid auth → auth_ok, then client can disconnect cleanly."""
        with ws_client.websocket_connect("/api/v1/ws/events") as ws:
            ws.send_json({"type": "auth", "api_key": TEST_API_KEY})
            resp = ws.receive_json()
            assert resp["type"] == "auth_ok"
            # Close immediately — don't enter streaming loop
