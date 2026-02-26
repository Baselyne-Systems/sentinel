"""
Custom ASGI middleware for SENTINEL.

Middleware stack (applied in reverse registration order in main.py):
1. ``SecurityHeadersMiddleware`` — adds defensive HTTP headers to every response.
2. ``ApiKeyMiddleware`` — enforces X-API-Key when ``API_KEY`` env var is set.

Both middlewares are no-ops when their respective feature flags are unset,
so dev and test environments need no extra configuration.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from sentinel_api.config import get_settings

# Paths that bypass API key enforcement (health checks must always be reachable)
_PUBLIC_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """
    Enforce ``X-API-Key`` header when ``API_KEY`` is configured.

    When ``settings.api_key`` is empty (the default), this middleware is a
    transparent passthrough.  Set ``API_KEY=<secret>`` in the environment to
    enable authentication.

    Public paths (``/health``, ``/docs``, ``/redoc``, ``/openapi.json``) are
    always allowed without a key so that load balancers and browser clients can
    reach documentation.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        settings = get_settings()
        if settings.api_key and request.url.path not in _PUBLIC_PATHS:
            provided = request.headers.get("X-API-Key", "")
            if provided != settings.api_key:
                return JSONResponse(
                    {"detail": "Invalid or missing API key"},
                    status_code=401,
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add defensive security headers to every response.

    Headers applied:
    - ``X-Content-Type-Options: nosniff`` — prevents MIME-type sniffing
    - ``X-Frame-Options: DENY`` — disables iframe embedding (clickjacking protection)
    - ``X-XSS-Protection: 1; mode=block`` — legacy XSS filter (belt-and-suspenders)
    - ``Referrer-Policy: strict-origin-when-cross-origin`` — limits referrer leakage
    - ``Permissions-Policy`` — disables dangerous browser APIs
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response
