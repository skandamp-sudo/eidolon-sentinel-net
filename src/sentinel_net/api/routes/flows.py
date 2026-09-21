"""Flows API routes."""

from fastapi import APIRouter, Request, Query, HTTPException

router = APIRouter(prefix="/api/v1", tags=["Flows"])

from sentinel_net.api.schemas import FlowListResponse, FlowResponse

@router.get("/flows", response_model=FlowListResponse)
async def list_flows(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    since: float | None = Query(default=None),
):
    """List network flows."""
    db = request.app.state.db
    
    flows = await db.get_flows(
        limit=limit,
        offset=offset,
        since=since
    )
    
    total = await db.get_flow_count(since=since)
    
    return {
        "flows": flows,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.get("/flows/{flow_id}", response_model=FlowResponse)
async def get_flow(request: Request, flow_id: str):
    """Get a specific flow by ID."""
    db = request.app.state.db
    flow = await db.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow
