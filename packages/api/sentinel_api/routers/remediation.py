"""
/api/v1/remediation — propose, approve, reject, and track remediation jobs.

Remediation lifecycle:
    POST /remediation/propose           → list[RemediationJob] (all PENDING)
    GET  /remediation/                  → list[RemediationJob] (newest first)
    GET  /remediation/{job_id}          → RemediationJob
    POST /remediation/{job_id}/approve  → RemediationJob (triggers background execute)
    POST /remediation/{job_id}/reject   → RemediationJob

Human approval is always required — auto-approve is never enabled.

The in-memory job store follows the same pattern as scan.py.
Background execution uses FastAPI BackgroundTasks.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from sentinel_api.config import get_settings
from sentinel_api.deps import Neo4jDep
from sentinel_remediation.executor import RemediationExecutor
from sentinel_remediation.models import JobStatus, RemediationJob
from sentinel_remediation.planner import RemediationPlanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remediation", tags=["remediation"])

# In-memory job store — same pattern as scan.py.
# Jobs survive for the lifetime of the API process.
_jobs: dict[str, RemediationJob] = {}


# ── Request / Response schemas ─────────────────────────────────────────────────


class ProposeRequest(BaseModel):
    """Request body for POST /remediation/propose."""

    node_id: str


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.post(
    "/propose",
    response_model=list[RemediationJob],
    status_code=200,
    summary="Propose remediations for a finding",
    description=(
        "Inspect the posture_flags on a graph node and return a list of "
        "``RemediationJob`` objects (one per actionable flag).\n\n"
        "All jobs start with ``status=pending``.  No AWS changes are made until "
        "a job is explicitly approved via ``POST /remediation/{job_id}/approve``.\n\n"
        "Flags without a registered remediator are silently skipped."
    ),
)
async def propose_remediations(
    request: ProposeRequest,
    client: Neo4jDep,
) -> list[RemediationJob]:
    """Propose pending remediation jobs for a flagged graph node."""
    planner = RemediationPlanner()
    try:
        jobs = await planner.propose(node_id=request.node_id, neo4j_client=client)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if not jobs:
        return []

    for job in jobs:
        _jobs[job.job_id] = job

    return jobs


@router.get(
    "/",
    response_model=list[RemediationJob],
    summary="List all remediation jobs",
    description="Return all remediation jobs known to this API instance, newest first.",
)
async def list_jobs() -> list[RemediationJob]:
    """List all remediation jobs, most recent first."""
    return sorted(_jobs.values(), key=lambda j: j.proposed_at, reverse=True)


@router.get(
    "/{job_id}",
    response_model=RemediationJob,
    summary="Get a remediation job",
    description="Return the current state of a specific remediation job.",
    responses={404: {"description": "Job not found"}},
)
async def get_job(job_id: str) -> RemediationJob:
    """Return the current state of a remediation job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return job


@router.post(
    "/{job_id}/approve",
    response_model=RemediationJob,
    summary="Approve and execute a remediation job",
    description=(
        "Approve a pending remediation job.  The job is immediately queued for "
        "background execution against AWS.\n\n"
        "**State transition:** ``pending → approved → executing → completed | failed``\n\n"
        "Returns the updated job (status will be ``approved`` or ``executing`` "
        "depending on how quickly the background task starts).\n\n"
        "Auto-approve is never enabled — this endpoint always requires explicit human action."
    ),
    responses={
        404: {"description": "Job not found"},
        409: {"description": "Job is not in PENDING state"},
    },
)
async def approve_job(
    job_id: str,
    background_tasks: BackgroundTasks,
    client: Neo4jDep,
) -> RemediationJob:
    """Approve a pending remediation job and queue it for execution."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    if job.status != JobStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Job '{job_id}' is {job.status!r}, not pending",
        )

    job.status = JobStatus.APPROVED
    job.approved_at = datetime.now(UTC).isoformat()
    _jobs[job_id] = job

    settings = get_settings()
    assume_role_arn = settings.aws_assume_role_arn or None

    background_tasks.add_task(_execute_job, job_id, client, assume_role_arn)
    logger.info("Approved job %s (%s)", job_id, job.proposal.action)
    return job


@router.post(
    "/{job_id}/reject",
    response_model=RemediationJob,
    summary="Reject a remediation job",
    description=(
        "Reject a pending remediation job.  No AWS changes are made.\n\n"
        "**State transition:** ``pending → rejected``"
    ),
    responses={
        404: {"description": "Job not found"},
        409: {"description": "Job is not in PENDING state"},
    },
)
async def reject_job(job_id: str) -> RemediationJob:
    """Reject a pending remediation job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    if job.status != JobStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Job '{job_id}' is {job.status!r}, not pending",
        )

    job.status = JobStatus.REJECTED
    job.rejected_at = datetime.now(UTC).isoformat()
    _jobs[job_id] = job

    logger.info("Rejected job %s (%s)", job_id, job.proposal.action)
    return job


# ── Background task ────────────────────────────────────────────────────────────


async def _execute_job(
    job_id: str,
    neo4j_client: Any,
    assume_role_arn: str | None,
) -> None:
    """Background task: run the remediation and update the job store."""
    job = _jobs.get(job_id)
    if not job:
        logger.error("Background task: job %s not found", job_id)
        return

    executor = RemediationExecutor()
    updated_job = await executor.execute(
        job=job,
        neo4j_client=neo4j_client,
        assume_role_arn=assume_role_arn,
    )
    _jobs[job_id] = updated_job
