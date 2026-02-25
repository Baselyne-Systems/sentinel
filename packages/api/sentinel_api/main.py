"""
SENTINEL FastAPI application entry point.

Creates and configures the FastAPI application with:
- Neo4j connection lifecycle management
- CORS for the Next.js frontend
- All API routers under /api/v1
- Rich OpenAPI documentation metadata
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel_api import __version__
from sentinel_api.config import get_settings
from sentinel_api.deps import set_neo4j_client
from sentinel_api.routers import accounts, graph, posture, scan
from sentinel_core.graph.client import Neo4jClient

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

_OPENAPI_DESCRIPTION = """
## SENTINEL — Autonomous Cloud Security Architect

SENTINEL builds a live graph of your AWS environment and continuously evaluates
it against the **CIS AWS Foundations Benchmark v1.5**.

### Core concepts

| Concept | Description |
|---------|-------------|
| **Graph node** | Any discovered AWS resource (EC2, S3, IAM role, SG, VPC…) |
| **Graph edge** | A relationship between resources (IN_VPC, MEMBER_OF_SG, CAN_ASSUME…) |
| **Posture flag** | A CIS violation stamped on a node during evaluation (e.g. `SG_OPEN_SSH`) |
| **Finding** | A node that has at least one posture flag |
| **Scan job** | A background task that discovers resources and runs evaluation |

### Typical workflow

1. `POST /api/v1/scan/trigger` — start a scan, receive `job_id`
2. `GET /api/v1/scan/{job_id}/status` — poll until `status = completed`
3. `GET /api/v1/posture/findings` — inspect CIS violations
4. `GET /api/v1/graph/nodes/{node_id}` — drill into a specific resource
5. `GET /api/v1/graph/nodes/{node_id}/neighbors` — visualize the blast radius

### Environment setup

Copy `.env.example` to `.env` and fill in:
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`
- `AWS_REGIONS` — comma-separated list of regions to scan
- `AWS_ASSUME_ROLE_ARN` — optional, for cross-account access

Run `make dev` to start Neo4j + this API in watch mode.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    FastAPI lifespan context manager.

    Runs on startup:
    - Connects to Neo4j
    - Creates graph indexes (idempotent)
    - Registers the client as a module-level singleton

    Runs on shutdown:
    - Closes the Neo4j connection pool
    """
    settings = get_settings()

    client = Neo4jClient(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    try:
        await client.connect()
        await client.ensure_indexes()
        set_neo4j_client(client)
        logger.info("SENTINEL API v%s ready", __version__)
        yield
    finally:
        await client.close()


def create_app() -> FastAPI:
    """
    Create and configure the SENTINEL FastAPI application.

    Returns:
        Configured FastAPI app instance ready for ASGI serving.
    """
    app = FastAPI(
        title="SENTINEL API",
        description=_OPENAPI_DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        contact={
            "name": "Baselyne Systems",
            "url": "https://github.com/baselyne-systems/sentinel",
        },
        license_info={"name": "MIT"},
        openapi_tags=[
            {
                "name": "graph",
                "description": (
                    "Query the environment graph. All discovered AWS resources are nodes; "
                    "their relationships are edges."
                ),
            },
            {
                "name": "posture",
                "description": (
                    "CIS benchmark findings and posture summary. "
                    "Findings are read from the graph — run a scan first."
                ),
            },
            {
                "name": "scan",
                "description": (
                    "Trigger and monitor full environment scans. "
                    "Scans run as background jobs and update the graph asynchronously."
                ),
            },
            {
                "name": "accounts",
                "description": (
                    "Register AWS accounts for cross-account scanning. "
                    "Optional for same-account usage."
                ),
            },
        ],
    )

    # CORS (allow frontend dev server)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    PREFIX = "/api/v1"
    app.include_router(graph.router, prefix=PREFIX)
    app.include_router(posture.router, prefix=PREFIX)
    app.include_router(scan.router, prefix=PREFIX)
    app.include_router(accounts.router, prefix=PREFIX)

    @app.get(
        "/health",
        summary="Health check",
        description="Returns API health status and version. Used by load balancers and Docker health checks.",
        tags=["health"],
    )
    async def health() -> dict:
        """Return API health status."""
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
