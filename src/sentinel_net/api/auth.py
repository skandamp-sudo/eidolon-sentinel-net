"""API key authentication middleware for SENTINEL-NET.

Enforces timing-safe API key validation on all protected endpoints.

SECURITY:
- Uses hmac.compare_digest() for constant-time comparison
- Never logs credential values
- Never includes credentials in error responses
- Health/readiness/docs endpoints are intentionally public
"""

from __future__ import annotations

import hmac
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel_net.config import get_config

logger = logging.getLogger(__name__)

# Paths that do not require authentication
_PUBLIC_PATHS = frozenset({
    "/health",
    "/readiness",
    "/docs",
    "/openapi.json",
    "/redoc",
})

# Prefixes that do not require authentication
_PUBLIC_PREFIXES = (
    "/api/v1/health",
)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing API key authentication.

    Validates the X-API-Key header against the configured secret
    using constant-time comparison. WebSocket connections are
    handled separately by the WebSocket endpoint itself.
    """

    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        """Validate API key for protected endpoints."""
        # CORS preflight (OPTIONS) must pass through unauthenticated.
        # Browsers never attach custom headers (X-API-Key) to preflight
        # requests per the Fetch spec. CORSMiddleware handles the response.
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path

        # Allow public endpoints
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # BaseHTTPMiddleware only processes HTTP scopes. Real WebSockets use
        # their own auth handler; an untrusted HTTP Upgrade header is no exemption.

        config = get_config()
        expected_key = config.api_key

        # Reject if no key is configured (misconfiguration)
        if not expected_key:
            logger.error("API key not configured — rejecting all requests")
            return JSONResponse(
                status_code=500,
                content={"detail": "Server authentication not configured"},
            )

        provided_key = request.headers.get("X-API-Key", "")

        # Reject empty keys explicitly
        if not provided_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key"},
            )

        # Constant-time comparison — prevents timing attacks
        if not hmac.compare_digest(provided_key, expected_key):
            logger.warning("Authentication failed from %s", request.client.host if request.client else "unknown")
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key"},
            )

        return await call_next(request)
