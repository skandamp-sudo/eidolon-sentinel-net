"""Tests for API key authentication — regression tests for auth bypass fix.

These tests verify:
- Correct key → 200
- Incorrect key → 401
- Missing key → 401
- Empty key → 401
- Health endpoint remains public
- Timing-safe comparison used
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from sentinel_net.api.main import create_app
from sentinel_net.config import SentinelConfig
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.storage.database import Database


TEST_API_KEY = "test-secret-key-12345"


@pytest.fixture
async def client(tmp_path, monkeypatch):
    """Create app with known API key and initialized DB."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SENTINEL_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(db_path))
    from sentinel_net.config import get_config
    get_config.cache_clear()

    app = create_app()
    # Manually init app state (lifespan doesn't run with ASGITransport)
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


class TestAuthentication:
    @pytest.mark.parametrize('endpoint', ['/api/v1/status', '/api/v1/events', '/api/v1/flows', '/api/v1/stats'])
    async def test_http_upgrade_cannot_bypass_auth(self, client, endpoint):
        response = await client.get(endpoint, headers={'Upgrade': 'websocket'})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_health_public(self, client):
        """Health endpoint requires no authentication."""
        r = await client.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_readiness_public(self, client):
        """Readiness endpoint requires no authentication."""
        r = await client.get("/readiness")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_correct_key_authorized(self, client):
        """Correct API key grants access."""
        r = await client.get(
            "/api/v1/events",
            headers={"X-API-Key": TEST_API_KEY},
        )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_incorrect_key_rejected(self, client):
        """Wrong API key is rejected."""
        r = await client.get(
            "/api/v1/events",
            headers={"X-API-Key": "wrong-key"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_key_rejected(self, client):
        """Missing API key is rejected."""
        r = await client.get("/api/v1/events")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_key_rejected(self, client):
        """Empty API key is rejected."""
        r = await client.get(
            "/api/v1/events",
            headers={"X-API-Key": ""},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_key_not_in_error_response(self, client):
        """Error response must not contain the API key."""
        r = await client.get(
            "/api/v1/events",
            headers={"X-API-Key": "wrong-key-value-12345"},
        )
        assert "wrong-key-value-12345" not in r.text

    @pytest.mark.asyncio
    async def test_correct_key_various_endpoints(self, client):
        """Auth works across all protected endpoints."""
        endpoints = ["/api/v1/events", "/api/v1/flows", "/api/v1/stats", "/api/v1/status"]
        for ep in endpoints:
            r = await client.get(ep, headers={"X-API-Key": TEST_API_KEY})
            assert r.status_code != 401, f"Auth failed on {ep}"

    @pytest.mark.asyncio
    async def test_wrong_key_all_endpoints(self, client):
        """Wrong key rejected on all protected endpoints."""
        endpoints = ["/api/v1/events", "/api/v1/flows", "/api/v1/stats", "/api/v1/status"]
        for ep in endpoints:
            r = await client.get(ep, headers={"X-API-Key": "nope"})
            assert r.status_code == 401, f"Auth not enforced on {ep}"


class TestTimingSafety:
    def test_hmac_compare_used(self):
        """Verify auth.py uses hmac.compare_digest (static check)."""
        import ast
        from pathlib import Path

        auth_path = Path(__file__).resolve().parents[2] / "src" / "sentinel_net" / "api" / "auth.py"
        source = auth_path.read_text()
        tree = ast.parse(source)

        found_hmac_import = False
        found_compare_digest = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "hmac":
                        found_hmac_import = True
            if isinstance(node, ast.ImportFrom) and node.module == "hmac":
                found_hmac_import = True
            if isinstance(node, ast.Attribute) and node.attr == "compare_digest":
                found_compare_digest = True

        assert found_hmac_import, "auth.py must import hmac"
        assert found_compare_digest, "auth.py must use hmac.compare_digest()"

    def test_no_credential_logging(self):
        """Verify auth.py never logs the key value."""
        from pathlib import Path

        auth_path = Path(__file__).resolve().parents[2] / "src" / "sentinel_net" / "api" / "auth.py"
        source = auth_path.read_text()
        assert "provided_key}" not in source
        assert "expected_key}" not in source


@pytest.fixture
async def cors_client(tmp_path, monkeypatch):
    """Create app with CORS origins configured for cross-origin testing."""
    db_path = tmp_path / "test_cors.db"
    monkeypatch.setenv("SENTINEL_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("SENTINEL_DATABASE_PATH", str(db_path))
    monkeypatch.setenv("SENTINEL_CORS_ORIGINS", "http://localhost:5173")
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


class TestCORSPreflight:
    """Regression tests for CORS preflight / auth middleware interaction.

    Root cause: OPTIONS preflight requests do not carry X-API-Key (per Fetch
    spec). If the auth middleware doesn't skip OPTIONS, the browser receives
    401 before the CORS middleware can respond, breaking all cross-origin
    requests.
    """

    @pytest.mark.asyncio
    async def test_options_preflight_not_401(self, cors_client):
        """OPTIONS preflight to a protected route must NOT return 401."""
        r = await cors_client.request(
            "OPTIONS",
            "/api/v1/status",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-API-Key",
            },
        )
        assert r.status_code != 401, (
            f"Preflight got 401 — auth middleware is blocking OPTIONS"
        )
        # CORSMiddleware returns 200 for valid preflight
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_preflight_returns_cors_headers(self, cors_client):
        """Preflight response must include Access-Control-Allow-* headers."""
        r = await cors_client.request(
            "OPTIONS",
            "/api/v1/events",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-API-Key",
            },
        )
        assert r.status_code == 200
        assert "access-control-allow-origin" in r.headers
        assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
        assert "access-control-allow-headers" in r.headers

    @pytest.mark.asyncio
    async def test_preflight_allows_x_api_key_header(self, cors_client):
        """Preflight must confirm X-API-Key is an allowed request header."""
        r = await cors_client.request(
            "OPTIONS",
            "/api/v1/stats",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-API-Key",
            },
        )
        allowed = r.headers.get("access-control-allow-headers", "").lower()
        assert "x-api-key" in allowed

    @pytest.mark.asyncio
    async def test_unauthenticated_get_still_rejected(self, cors_client):
        """Actual GET without API key must still be rejected (401)."""
        r = await cors_client.get(
            "/api/v1/status",
            headers={"Origin": "http://localhost:5173"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_authenticated_get_still_works(self, cors_client):
        """Actual GET with valid API key must still succeed."""
        r = await cors_client.get(
            "/api/v1/status",
            headers={
                "Origin": "http://localhost:5173",
                "X-API-Key": TEST_API_KEY,
            },
        )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_preflight_multiple_protected_routes(self, cors_client):
        """OPTIONS preflight works on all protected API routes."""
        routes = ["/api/v1/events", "/api/v1/flows", "/api/v1/stats", "/api/v1/status"]
        for route in routes:
            r = await cors_client.request(
                "OPTIONS",
                route,
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "X-API-Key",
                },
            )
            assert r.status_code == 200, f"Preflight failed on {route}: {r.status_code}"

    @pytest.mark.asyncio
    async def test_wrong_origin_rejected(self, cors_client):
        """Preflight from a non-allowed origin gets no CORS headers."""
        r = await cors_client.request(
            "OPTIONS",
            "/api/v1/status",
            headers={
                "Origin": "http://evil.example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-API-Key",
            },
        )
        # CORSMiddleware returns 400 for disallowed origins
        assert "access-control-allow-origin" not in r.headers
