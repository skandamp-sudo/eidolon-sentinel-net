"""Events API routes."""

from fastapi import APIRouter, Request, Query, HTTPException

router = APIRouter(prefix="/api/v1", tags=["Events"])

from sentinel_net.api.schemas import EventListResponse, EventResponse

@router.get("/events", response_model=EventListResponse)
async def list_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    threat_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    since: float | None = Query(default=None),
    flow_id: str | None = Query(default=None),
):
    """List and filter detection events."""
    db = request.app.state.db
    
    events = await db.get_events(
        limit=limit,
        offset=offset,
        since=since,
        threat_type=threat_type,
        severity=severity,
        flow_id=flow_id
    )
    
    count = await db.get_event_count(
        threat_type=threat_type,
        severity=severity,
        since=since,
        flow_id=flow_id
    )
    
    return {
        "events": events,
        "total": count,
        "limit": limit,
        "offset": offset
    }

@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(request: Request, event_id: str):
    """Get a specific detection event by ID."""
    db = request.app.state.db
    event = await db.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
