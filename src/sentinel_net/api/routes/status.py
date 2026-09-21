"""Status API route — sensor state, metrics, operational info.

Distinct from /health (which answers "is the service functioning?").
Status answers "what is the sensor doing?"
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from sentinel_net.features.schema import FEATURE_COUNT, FEATURE_SCHEMA_VERSION

router = APIRouter(tags=["Status"])


from sentinel_net.api.schemas import StatusResponse

@router.get("/api/v1/status", response_model=StatusResponse)
async def get_status(request: Request):
    """Sensor status, processing counters, and operational info."""
    metrics = getattr(request.app.state, "sensor_metrics", None)
    lifecycle = getattr(request.app.state, "sensor_lifecycle", None)
    event_bus = getattr(request.app.state, "event_bus", None)
    service = getattr(request.app.state, 'sensor_service', None)
    health = service.health() if service else {}
    snapshot = metrics.snapshot() if metrics else {}
    snapshot['subscriber_count'] = event_bus.subscriber_count if event_bus else 0

    return {
        'model_identity': service.model_identity if service else getattr(request.app.state, 'model_identity', None),
        'capture_interface': service.config.capture_interface if service else None,
        "sensor_state": lifecycle.state.value if lifecycle else "stopped",
        "metrics": snapshot,
        "sensor_mode": 'live_passive_sensor' if service else ('recorded_traffic_replay' if lifecycle else 'standby'),
        "operational_health": health,
        "uptime_sec": metrics.uptime_sec if metrics else 0.0,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "websocket_subscribers": event_bus.subscriber_count if event_bus else 0,
    }
