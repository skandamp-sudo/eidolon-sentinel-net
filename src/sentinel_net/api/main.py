"""FastAPI application factory for EIDOLON // SENTINEL-NET.

SECURITY:
- APIKeyMiddleware enforces authentication on all protected endpoints
- Exception handler never exposes stack traces or secrets
- CORS origins are configuration-driven
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel_net.api.auth import APIKeyMiddleware
from sentinel_net.api.routes import events, flows, health, stats, status, websocket
from sentinel_net.config import get_config, setup_logging
from sentinel_net.sensor.event_bus import EventBus
from sentinel_net.sensor.metrics import SensorMetrics
from sentinel_net.storage.database import Database

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the lifecycle of the FastAPI application."""
    config = get_config()
    setup_logging(config.log_level)

    service = getattr(app.state, 'sensor_service', None)
    if service is not None:
        try:
            await service.start()
            app.state.db = service.db
            app.state.event_bus = service.event_bus
            app.state.sensor_metrics = service.metrics
            app.state.sensor_lifecycle = service.lifecycle
            yield
        finally:
            await service.stop()
        return

    db = Database(config.database_path)
    await db.initialize()
    app.state.db = db

    # Initialize sensor components
    app.state.event_bus = EventBus(max_queue_size=config.event_queue_size)
    app.state.sensor_metrics = SensorMetrics()
    app.state.sensor_lifecycle = None  # Set when sensor starts

    logger.info("Application initialized.")
    yield

    # Shutdown
    dropped = app.state.event_bus.shutdown()
    app.state.sensor_metrics.increment("events_dropped", dropped)
    await db.close()
    logger.info("Application shutdown complete.")


def create_app(*, sensor_service=None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="EIDOLON // SENTINEL-NET API",
        version="0.5.0",
        lifespan=lifespan,
    )

    config = get_config()
    app.state.sensor_service = sensor_service

    # CORS — configurable origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    # API key authentication
    app.add_middleware(APIKeyMiddleware)

    # Routes
    app.include_router(health.router)
    app.include_router(events.router)
    app.include_router(flows.router)
    app.include_router(status.router)
    app.include_router(stats.router)
    app.include_router(websocket.router)

    # Global exception handler — never leak internals
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()
