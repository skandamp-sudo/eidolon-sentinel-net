"""Health check endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException

router = APIRouter(tags=["Health"])

@router.get("/health")
async def get_health():
    """Return basic health status."""
    return {
        "status": "healthy",
        "version": "0.1.0",
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
        
    return {"status": "ready"}
