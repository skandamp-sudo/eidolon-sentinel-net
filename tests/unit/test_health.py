"""Tests for health endpoints."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from sentinel_net.api.routes import health


@pytest.fixture
def health_app() -> FastAPI:
    """Create a minimal FastAPI app with only health routes (no lifespan/DB)."""
    app = FastAPI()
    app.include_router(health.router)
    return app


@pytest.fixture
async def health_client(health_app: FastAPI):
    """Async HTTP client for the health-only app."""
    async with AsyncClient(
        transport=ASGITransport(app=health_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_health_returns_200(health_client: AsyncClient):
    """GET /health returns 200 with status='healthy'."""
    response = await health_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_health_has_version(health_client: AsyncClient):
    """Health response includes version field."""
    response = await health_client.get("/health")
    data = response.json()
    assert "version" in data
    assert data["version"] == "0.6.0"


@pytest.mark.asyncio
async def test_health_has_timestamp(health_client: AsyncClient):
    """Health response includes a timestamp."""
    response = await health_client.get("/health")
    assert "timestamp" in response.json()
