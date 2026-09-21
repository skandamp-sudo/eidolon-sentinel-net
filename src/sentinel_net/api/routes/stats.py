"""Stats API routes."""

from fastapi import APIRouter, Request

router = APIRouter(tags=["Stats"])

from sentinel_net.api.schemas import StatsResponse

@router.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats(request: Request):
    """Get aggregate statistics."""
    db = request.app.state.db
    stats = await db.get_stats()
    return stats
