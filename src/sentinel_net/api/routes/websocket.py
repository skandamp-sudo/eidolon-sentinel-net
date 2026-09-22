"""WebSocket event stream endpoint.

Authentication flow:
1. Client connects to WS /api/v1/ws/events
2. Server waits for auth message: {"type": "auth", "api_key": "..."}
3. Server validates with hmac.compare_digest()
4. On success: sends {"type": "auth_ok"}
5. On failure: sends {"type": "auth_failed"}, closes connection
6. After auth: streams events from EventBus

SECURITY:
- API key is NEVER logged, persisted, or included in event payloads
- Uses hmac.compare_digest() for constant-time comparison
- Bounded per-client queue via EventBus
- Detection continues with zero connected clients
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from sentinel_net.config import get_config

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSocket"])


@router.websocket("/api/v1/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    """Authenticated WebSocket event stream."""
    await websocket.accept()

    config = get_config()
    authenticated = False

    # Optional query-param fallback (disabled by default)
    if config.ws_query_param_auth:
        api_key_param = websocket.query_params.get("api_key", "")
        if api_key_param and hmac.compare_digest(api_key_param, config.api_key):
            authenticated = True

    # Primary: auth message flow
    if not authenticated:
        try:
            raw = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=config.ws_auth_timeout_sec,
            )
            msg = json.loads(raw)

            if msg.get("type") == "auth":
                provided = msg.get("api_key", "")
                if provided and hmac.compare_digest(provided, config.api_key):
                    authenticated = True
                else:
                    await websocket.send_json({"type": "auth_failed"})
            else:
                await websocket.send_json({"type": "auth_failed", "reason": "expected auth message"})
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "auth_failed", "reason": "timeout"})
        except (json.JSONDecodeError, Exception):
            await websocket.send_json({"type": "auth_failed", "reason": "invalid format"})

    if not authenticated:
        await websocket.close(code=1008)
        return

    # Get event bus
    event_bus = getattr(websocket.app.state, "event_bus", None)
    if not event_bus:
        await websocket.close(code=1011)
        return

    # Subscribe with unique ID
    sub_id = f"ws-{uuid.uuid4().hex[:8]}"
    try:
        sub_queue = event_bus.subscribe(sub_id)
    except RuntimeError:
        await websocket.close(code=1013)
        return
    metrics = getattr(websocket.app.state, 'sensor_metrics', None)
    event = None

    async def send(payload):
        await asyncio.wait_for(websocket.send_json(payload), config.ws_send_timeout_sec)

    try:
        await send({"type": "auth_ok"})
        while True:
            # Check for events non-blockingly, send heartbeat if none
            event = None
            try:
                # Non-blocking check
                import queue as stdlib_queue
                event = sub_queue.get_nowait()
            except stdlib_queue.Empty:
                pass

            if event is not None:
                await send({"type": "event", "data": event})
                if metrics:
                    metrics.increment('events_delivered')
                event = None
            else:
                # Wait briefly, then send heartbeat or check for disconnect
                try:
                    # Wait for client message (ping/pong/disconnect) with short timeout
                    client_msg = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=min(1.0, config.ws_heartbeat_interval_sec),
                    )
                    # Client sent something — could be a filter update, ignore for now
                except asyncio.TimeoutError:
                    # No client message — send heartbeat
                    await send({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception('WebSocket delivery failed')
        if metrics:
            metrics.increment('processing_errors')
            metrics.increment('output_errors')
            metrics.set_gauge('last_error_kind', 'OUTPUT_ERROR')
    finally:
        dropped = event_bus.unsubscribe(sub_id) + (1 if event is not None else 0)
        if metrics:
            metrics.increment('events_dropped', dropped)
