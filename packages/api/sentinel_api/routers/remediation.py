"""
/api/v1/remediation — propose, approve, reject, and track remediation jobs.

Remediation lifecycle:
    POST /remediation/propose           → list[RemediationJob] (all PENDING)
    GET  /remediation/                  → list[RemediationJob] (newest first)
    GET  /remediation/{job_id}          → RemediationJob
    POST /remediation/{job_id}/approve  → RemediationJob (triggers background execute)
    POST /remediation/{job_id}/reject   → RemediationJob

Human approval is always required — auto-approve is never enabled.

Job state is persisted to the SQLite store (sentinel.db) and survives API restarts.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel
from sentinel_remediation.executor import RemediationExecutor
from sentinel_remediation.models import JobStatus, RemediationJob
from sentinel_remediation.planner import RemediationPlanner

from sentinel_api.config import get_settings
from sentinel_api.deps import Neo4jDep, StoreDep
from sentinel_api.limiter import REMEDIATION_PROPOSE_LIMIT, limiter
from sentinel_api.store import SentinelStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remediation", tags=["remediation"])


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
@limiter.limit(REMEDIATION_PROPOSE_LIMIT)
async def propose_remediations(
    request: Request,
    body: ProposeRequest,
    client: Neo4jDep,
    store: StoreDep,
) -> list[RemediationJob]:
    """Propose pending remediation jobs for a flagged graph node."""
    planner = RemediationPlanner()
    try:
        jobs = await planner.propose(node_id=body.node_id, neo4j_client=client)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if not jobs:
        return []

    for job in jobs:
        await store.create_remediation_job(job)

    return jobs


@router.get(
    "/",
    response_model=list[RemediationJob],
    summary="List all remediation jobs",
    description="Return all remediation jobs, newest first. History persists across API restarts.",
)
async def list_jobs(store: StoreDep) -> list[RemediationJob]:
    """List all remediation jobs, most recent first."""
    return await store.list_remediation_jobs()


@router.get(
    "/{job_id}",
    response_model=RemediationJob,
    summary="Get a remediation job",
    description="Return the current state of a specific remediation job.",
    responses={404: {"description": "Job not found"}},
)
async def get_job(job_id: str, store: StoreDep) -> RemediationJob:
    """Return the current state of a remediation job."""
    job = await store.get_remediation_job(job_id)
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
    store: StoreDep,
) -> RemediationJob:
    """Approve a pending remediation job and queue it for execution."""
    job = await store.get_remediation_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    if job.status != JobStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Job '{job_id}' is {job.status!r}, not pending",
        )

    job.status = JobStatus.APPROVED
    job.approved_at = datetime.now(UTC).isoformat()
    await store.update_remediation_job(job)

    settings = get_settings()
    assume_role_arn = settings.aws_assume_role_arn or None

    background_tasks.add_task(_execute_job, job_id, client, store, assume_role_arn)
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
async def reject_job(job_id: str, store: StoreDep) -> RemediationJob:
    """Reject a pending remediation job."""
    job = await store.get_remediation_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    if job.status != JobStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Job '{job_id}' is {job.status!r}, not pending",
        )

    job.status = JobStatus.REJECTED
    job.rejected_at = datetime.now(UTC).isoformat()
    await store.update_remediation_job(job)

    logger.info("Rejected job %s (%s)", job_id, job.proposal.action)
    return job


# ── Background task ────────────────────────────────────────────────────────────


async def _execute_job(
    job_id: str,
    neo4j_client: Any,
    store: SentinelStore,
    assume_role_arn: str | None,
) -> None:
    """Background task: run the remediation and update the job store."""
    job = await store.get_remediation_job(job_id)
    if not job:
        logger.error("Background task: job %s not found", job_id)
        return

    executor = RemediationExecutor()
    updated_job = await executor.execute(
        job=job,
        neo4j_client=neo4j_client,
        assume_role_arn=assume_role_arn,
    )
    await store.update_remediation_job(updated_job)
