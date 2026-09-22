"""Health check endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException

router = APIRouter(tags=["Health"])

from sentinel_net.api.schemas import HealthResponse
from sentinel_net.sensor.operational_health import resource_reasons

@router.get("/health", response_model=HealthResponse)
async def get_health(request: Request):
    """Return basic health status."""
    service = getattr(request.app.state, 'sensor_service', None)
    reasons = resource_reasons(getattr(request.app.state, 'sensor_metrics', None), getattr(request.app.state, 'event_bus', None))
    sensor = service.health() if service else ({'state': 'degraded', 'reasons': reasons} if reasons else None)
    return {
        "status": ('healthy' if sensor['state'] == 'running' else sensor['state']) if sensor else 'healthy',
        "sensor": sensor,
        "version": "0.6.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/readiness")
async def get_readiness(request: Request):
    """Check readiness including database connection."""
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
        
    is_healthy = await db.health_check()
    if not is_healthy:
        raise HTTPException(status_code=503, detail="Database unhealthy")

    service = getattr(request.app.state, 'sensor_service', None)
    if service:
        health = service.health()
        if health['state'] != 'running':
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=503, content={'status': 'not_ready', 'sensor': health})
        return {'status': 'ready', 'sensor': health}
        
    reasons = resource_reasons(getattr(request.app.state, 'sensor_metrics', None), getattr(request.app.state, 'event_bus', None))
    if reasons:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={'status': 'not_ready', 'reasons': reasons})
    return {"status": "ready"}
