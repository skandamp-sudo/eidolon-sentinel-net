"""Authenticated, read-only analyst operations. No filesystem paths from clients."""

from __future__ import annotations

import asyncio
import json
from importlib.resources import files

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import Response

from sentinel_net.api.routes.status import get_status
from sentinel_net.operations.investigation import (
    ID_PATTERN,
    InvalidInvestigation,
    build_investigation,
    export_bytes,
)
from sentinel_net.operations.schema import InvestigationExport

router = APIRouter(prefix="/api/v1", tags=["Analyst operations"])


SEND_TIMEOUT_SECONDS = 15


class BoundedResponse(Response):
    """Hold admission until send completes; a slow consumer has a finite lease."""

    def __init__(self, content, *, gate, headers):
        super().__init__(content, media_type="application/json", headers=headers)
        self.gate = gate

    async def __call__(self, scope, receive, send):
        try:
            async with asyncio.timeout(SEND_TIMEOUT_SECONDS):
                await super().__call__(scope, receive, send)
        finally:
            self.gate.release()


async def investigation_response(request: Request, event_id: str, download: bool):
    if not ID_PATTERN.fullmatch(event_id):
        raise HTTPException(422, "Invalid event identifier")
    gate = request.app.state.investigation_gate
    if gate.locked():
        raise HTTPException(429, "Investigation capacity reached; retry later")
    await gate.acquire()
    try:
        async with asyncio.timeout(5):
            records, truncated = await request.app.state.db.investigation_records(event_id)
        if not records:
            raise HTTPException(404, "Persisted event not found")
        view = build_investigation(records[0], records[1:], truncated=truncated)
        content, digest = export_bytes(view)
        headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Content-SHA256": digest,
        }
        if download:
            headers["Content-Disposition"] = (
                f'attachment; filename="sentinel-investigation-{view["investigation_id"][:16]}.json"'
            )
        return BoundedResponse(content, gate=gate, headers=headers)
    except BaseException as exc:
        gate.release()
        if isinstance(
            exc, (InvalidInvestigation, TypeError, KeyError, AttributeError, RecursionError)
        ):
            raise HTTPException(
                422, "Persisted evidence is malformed or exceeds investigation bounds"
            ) from None
        if isinstance(exc, TimeoutError):
            raise HTTPException(503, "Investigation temporarily unavailable") from None
        raise


@router.get(
    "/events/{event_id}/investigation",
    summary="Bounded persisted investigation projection",
    response_model=InvestigationExport,
)
async def investigation(request: Request, event_id: str):
    return await investigation_response(request, event_id, False)


@router.get(
    "/events/{event_id}/export",
    summary="Canonical JSON evidence export; SHA-256 in X-Content-SHA256",
    response_model=InvestigationExport,
)
async def forensic_export(request: Request, event_id: str):
    return await investigation_response(request, event_id, True)


@router.get("/assurance")
async def assurance(request: Request):
    status = await get_status(request)
    identity = status.get("model_identity")
    verified = isinstance(identity, dict) and all(
        identity.get(k) for k in ("model_name", "model_version", "manifest_sha256")
    )
    db = getattr(request.app.state, "db", None)
    healthy = await db.health_check() if db else False
    rows = [
        (
            "Passive observation",
            "VERIFIED SOFTWARE PROPERTY",
            "Passive ingest implementation; deployment topology is not attested.",
        ),
        ("Active probing", "DISABLED", "No active probing operation provided."),
        ("Packet injection", "DISABLED", "No packet injection operation provided."),
        (
            "Payload decryption",
            "DISABLED",
            "TLS application data and QUIC Initial decryption are not implemented.",
        ),
        ("Runtime model training", "DISABLED", "Frozen inference only."),
        (
            "Model integrity",
            "VERIFIED" if verified else "UNAVAILABLE",
            "Loaded bundle checksum and inference checks at load time; not a digital signature or continuous attestation."
            if verified
            else "No verified loaded identity available.",
        ),
        (
            "Sensor state",
            str(status.get("sensor_state", "UNAVAILABLE")).upper(),
            "Current lifecycle snapshot.",
        ),
        (
            "Traffic source",
            "LIVE"
            if status["sensor_mode"] == "live_passive_sensor"
            else "RECORDED TRAFFIC REPLAY"
            if status["sensor_mode"] == "recorded_traffic_replay"
            else "UNAVAILABLE",
            "Current mode; individual events retain their own source labels.",
        ),
        (
            "Database",
            "VERIFIED" if healthy else "UNAVAILABLE",
            "SELECT 1 health check; not a full integrity audit.",
        ),
        (
            "Native real-interface capture",
            "NOT VERIFIED",
            "No deployment-specific native BPF validation established.",
        ),
        (
            "Physical data-diode validation",
            "NOT VERIFIED",
            "Software simulation does not validate hardware.",
        ),
    ]
    try:
        science = json.loads(files("sentinel_net.operations").joinpath("science.json").read_text())
    except (OSError, ValueError):
        science = {"status": "UNAVAILABLE"}
    return {
        "rows": [{"property": k, "status": s, "detail": d} for k, s, d in rows],
        "model_identity": {
            k: identity.get(k) for k in ("model_name", "model_version", "manifest_sha256")
        }
        if verified
        else None,
        "feature_schema_version": status["feature_schema_version"],
        "science": science,
    }
