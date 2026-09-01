"""API key middleware for Sentinel-NET API."""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging

from sentinel_net.config import get_config

logger = logging.getLogger(__name__)

class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce API key authentication."""
    
    def __init__(self, app):
        """Initialize middleware."""
        super().__init__(app)
        self.skip_paths = {"/health", "/readiness", "/docs", "/openapi.json", "/redoc"}
        
    async def dispatch(self, request: Request, call_next):
        """Process the request and check for API key if needed."""
        if request.url.path in self.skip_paths:
            return await call_next(request)
            
        config = get_config()
        # In a real app we'd get the expected key from config or secrets
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return JSONResponse(status_code=401, content={"detail": "Missing API Key"})
            
        return await call_next(request)
