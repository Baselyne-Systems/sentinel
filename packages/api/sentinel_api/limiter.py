"""
slowapi rate limiter configuration.

The module-level ``limiter`` instance is shared across all routers.
Limits are expressed as callables so they can inspect ``RATE_LIMIT_ENABLED``
at request time (not import time), enabling tests to disable them via env-var.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# ── Per-endpoint rate limit strings ──────────────────────────────────────────
# When RATE_LIMIT_ENABLED is false (default), limits are set absurdly high so
# tests are never throttled. In production set RATE_LIMIT_ENABLED=true.


def _limit(production_limit: str) -> str:
    """Return the production limit or a test-friendly no-op limit."""
    enabled = os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
    return production_limit if enabled else "10000/minute"


# POST /scan/trigger — expensive AWS calls; allow 10/minute per IP
SCAN_TRIGGER_LIMIT = lambda: _limit("10/minute")  # noqa: E731

# POST /agent/findings/{id}/analyze — LLM calls; allow 20/minute per IP
AGENT_ANALYZE_LIMIT = lambda: _limit("20/minute")  # noqa: E731

# POST /remediation/propose — graph + planning; allow 30/minute per IP
REMEDIATION_PROPOSE_LIMIT = lambda: _limit("30/minute")  # noqa: E731
