"""
/api/v1/scan — trigger environment scans and poll job status.

Scans are long-running background jobs. Triggering a scan returns a `job_id`
immediately. Poll ``GET /scan/{job_id}/status`` to track progress.

Scan lifecycle:
    queued → running → completed | failed

The background job:
    1. Discovers all AWS resources via boto3 connectors (EC2, IAM, S3, Lambda, RDS)
    2. Writes nodes and edges to Neo4j
    3. Runs CIS rule evaluation and stamps posture_flags on violating nodes
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from sentinel_api.config import get_settings
from sentinel_api.deps import Neo4jDep
from sentinel_api.schemas import ErrorResponse, ScanJobResponse, ScanTriggerResponse
from sentinel_perception.graph_builder import GraphBuilder, ScanResult

router = APIRouter(prefix="/scan", tags=["scan"])

# In-memory job store (Phase 1).
# Phase 2 upgrade: replace with Redis or a lightweight DB for persistence + multi-instance support.
_jobs: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Request body for POST /scan/trigger."""

    account_id: str | None = Field(
        None,
        description=(
            "AWS account ID to scan. If omitted, uses the default credential chain. "
            "Must be registered via POST /accounts if using assume-role."
        ),
        examples=["123456789012"],
    )
    regions: list[str] | None = Field(
        None,
        description=(
            "AWS regions to scan. Defaults to the AWS_REGIONS environment variable. "
            "Specify a subset to speed up scans during development."
        ),
        examples=[["us-east-1"], ["us-east-1", "us-west-2"]],
    )
    assume_role_arn: str | None = Field(
        None,
        description=(
            "IAM Role ARN to assume for this scan. Overrides AWS_ASSUME_ROLE_ARN env var. "
            "Required for cross-account scanning."
        ),
    )
    clear_first: bool = Field(
        False,
        description=(
            "If true, delete all existing nodes for this account before scanning. "
            "Use for a clean re-scan. Default is incremental (upsert)."
        ),
    )


@router.post(
    "/trigger",
    response_model=ScanTriggerResponse,
    status_code=200,
    summary="Trigger a full environment scan",
    description=(
        "Start a full AWS environment scan in the background. "
        "Returns a `job_id` immediately — use ``GET /scan/{job_id}/status`` to poll progress. "
        "The scan discovers all AWS resources, writes them to Neo4j, and evaluates CIS rules. "
        "Multiple scans can run concurrently (each gets its own job_id)."
    ),
    responses={
        200: {"description": "Scan job queued successfully"},
    },
)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    client: Neo4jDep,
) -> dict[str, Any]:
    """
    Trigger a full AWS environment scan.

    The scan runs as a FastAPI background task. Results (nodes written, findings,
    timing) are available via ``GET /scan/{job_id}/status`` once completed.
    """
    settings = get_settings()
    account_id = request.account_id or "default"
    regions = request.regions or settings.regions_list
    assume_role_arn = request.assume_role_arn or settings.aws_assume_role_arn or None

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "account_id": account_id,
        "regions": regions,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
    }

    background_tasks.add_task(
        _run_scan,
        job_id=job_id,
        client=client,
        account_id=account_id,
        regions=regions,
        assume_role_arn=assume_role_arn,
        clear_first=request.clear_first,
    )

    return {"job_id": job_id, "status": "queued", "account_id": account_id}


@router.get(
    "/{job_id}/status",
    response_model=ScanJobResponse,
    summary="Get scan job status",
    description=(
        "Return the current status and results of a scan job. "
        "Poll this endpoint every 2–5 seconds while ``status`` is 'queued' or 'running'. "
        "When ``status`` is 'completed', the ``result`` field contains node/edge counts and findings. "
        "Job history is kept in memory for the lifetime of the API process."
    ),
    responses={
        200: {"description": "Current job state"},
        404: {"model": ErrorResponse, "description": "No job with this ID exists"},
    },
)
async def get_scan_status(job_id: str) -> dict[str, Any]:
    """
    Get the status and result of a scan job.

    Possible status values:
    - ``queued``: Job accepted, not yet started.
    - ``running``: Discovery and graph writes in progress.
    - ``completed``: All steps finished. Check ``result`` for details.
    - ``failed``: An unrecoverable error occurred. Check ``error`` for the message.
    """
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")
    return job


@router.get(
    "/",
    response_model=list[ScanJobResponse],
    summary="List all scan jobs",
    description="Return all scan jobs known to this API instance, ordered newest-first.",
    responses={
        200: {"description": "All scan jobs"},
    },
)
async def list_scans() -> list[dict[str, Any]]:
    """List all scan jobs, most recent first."""
    return sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)


async def _run_scan(
    job_id: str,
    client: Any,
    account_id: str,
    regions: list[str],
    assume_role_arn: str | None,
    clear_first: bool,
) -> None:
    """
    Background task: runs the full scan and updates the job record.

    Sets job status to 'running' on start, then 'completed' or 'failed' on finish.
    Non-fatal per-region errors are recorded in ``result.errors`` but do not
    cause the overall job to fail.
    """
    _jobs[job_id]["status"] = "running"
    try:
        builder = GraphBuilder(client)
        result: ScanResult = await builder.full_scan(
            account_id=account_id,
            regions=regions,
            assume_role_arn=assume_role_arn,
            clear_first=clear_first,
        )
        _jobs[job_id].update(
            {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": result.to_dict(),
            }
        )
    except Exception as exc:
        _jobs[job_id].update(
            {
                "status": "failed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
            }
        )
