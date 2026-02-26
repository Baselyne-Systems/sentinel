"""
RemediationExecutor — dispatches approved jobs to the correct remediator.

Design:
    - Receives an approved ``RemediationJob`` and runs the boto3 call via
      ``asyncio.to_thread()`` to avoid blocking the async event loop.
    - On success: sets status=COMPLETED, records output, writes back to Neo4j.
    - On failure: sets status=FAILED, records error message.
    - Neo4j write-back stamps ``remediated_at`` and ``remediation_job_id`` on
      the source node so the graph reflects the remediation.

The executor does NOT manage the job store — that is the router's responsibility.
It receives a job by reference (or returns an updated copy), and the router
updates the in-memory store.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import boto3

from sentinel_remediation.models import JobStatus, RemediationAction, RemediationJob
from sentinel_remediation.remediators import cloudtrail, ec2, rds, s3

logger = logging.getLogger(__name__)


# ── Dispatch table ─────────────────────────────────────────────────────────────

# Maps RemediationAction → sync remediator function(params, session) -> dict
_REMEDIATOR_MAP: dict[RemediationAction, Any] = {
    RemediationAction.S3_BLOCK_PUBLIC_ACCESS: s3.block_public_access,
    RemediationAction.S3_ENABLE_VERSIONING: s3.enable_versioning,
    RemediationAction.S3_ENABLE_SSE: s3.enable_sse,
    RemediationAction.S3_ENABLE_LOGGING: s3.enable_logging,
    RemediationAction.EC2_ENABLE_EBS_ENCRYPTION: ec2.enable_ebs_encryption,
    RemediationAction.CLOUDTRAIL_ENABLE: cloudtrail.enable_trail,
    RemediationAction.CLOUDTRAIL_LOG_VALIDATION: cloudtrail.enable_log_validation,
    RemediationAction.RDS_DISABLE_PUBLIC_ACCESS: rds.disable_public_access,
}


# ── Executor ───────────────────────────────────────────────────────────────────


class RemediationExecutor:
    """Executes approved remediation jobs against AWS.

    Resolves the correct remediator function from the dispatch table,
    builds a boto3 session (with optional role assumption for cross-account),
    and runs the boto3 call in a thread pool to preserve async compatibility.
    """

    async def execute(
        self,
        job: RemediationJob,
        neo4j_client: Any,
        assume_role_arn: str | None = None,
    ) -> RemediationJob:
        """Execute an approved remediation job.

        Updates ``job`` in-place and returns it.  The caller (router) is
        responsible for persisting the updated job back to the job store.

        Args:
            job:             An approved ``RemediationJob`` (status=APPROVED).
            neo4j_client:    Connected ``Neo4jClient`` for post-execution write-back.
            assume_role_arn: Optional IAM role ARN to assume before calling boto3.

        Returns:
            The updated ``RemediationJob`` with final status and output/error.
        """
        remediator_fn = _REMEDIATOR_MAP.get(job.proposal.action)
        if remediator_fn is None:
            job.status = JobStatus.FAILED
            job.error = f"No remediator registered for action {job.proposal.action!r}"
            job.completed_at = datetime.now(UTC).isoformat()
            logger.error("No remediator for %s (job %s)", job.proposal.action, job.job_id)
            return job

        job.status = JobStatus.EXECUTING
        job.executed_at = datetime.now(UTC).isoformat()
        logger.info("Executing %s (job %s)", job.proposal.action, job.job_id)

        try:
            session = _build_session(
                region=job.proposal.region,
                assume_role_arn=assume_role_arn,
            )
            output: dict = await asyncio.to_thread(remediator_fn, job.proposal.params, session)
            job.status = JobStatus.COMPLETED
            job.output = output
            job.completed_at = datetime.now(UTC).isoformat()
            logger.info("Completed %s (job %s): %s", job.proposal.action, job.job_id, output)

            await _write_neo4j_outcome(
                node_id=job.proposal.node_id,
                job_id=job.job_id,
                neo4j_client=neo4j_client,
            )
        except Exception as exc:
            job.status = JobStatus.FAILED
            job.error = str(exc)
            job.completed_at = datetime.now(UTC).isoformat()
            logger.exception("Failed %s (job %s): %s", job.proposal.action, job.job_id, exc)

        return job


# ── Helpers ────────────────────────────────────────────────────────────────────


def _build_session(
    region: str,
    assume_role_arn: str | None,
) -> boto3.Session:
    """Build a boto3 session, optionally assuming a cross-account role.

    Args:
        region:          Default region for the session.
        assume_role_arn: If set, assume this IAM role before calling boto3.

    Returns:
        A ``boto3.Session`` configured with the correct credentials.
    """
    if assume_role_arn:
        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=assume_role_arn,
            RoleSessionName="sentinel-remediation",
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    return boto3.Session(region_name=region)


async def _write_neo4j_outcome(
    node_id: str,
    job_id: str,
    neo4j_client: Any,
) -> None:
    """Stamp the remediated node in Neo4j with outcome metadata.

    Sets ``remediated_at`` (ISO UTC) and ``remediation_job_id`` on the node
    so the graph reflects that the issue was addressed.

    Args:
        node_id:      The graph node that was remediated.
        job_id:       The job_id of the completed job.
        neo4j_client: Connected ``Neo4jClient``.
    """
    try:
        await neo4j_client.execute(
            """
            MATCH (n {node_id: $node_id})
            SET n.remediated_at = $remediated_at,
                n.remediation_job_id = $job_id
            """,
            {
                "node_id": node_id,
                "remediated_at": datetime.now(UTC).isoformat(),
                "job_id": job_id,
            },
        )
        logger.info("Neo4j: stamped remediation outcome on node %s", node_id)
    except Exception as exc:
        # Don't fail the job if the Neo4j write-back fails — the AWS remediation succeeded.
        logger.warning("Failed to write Neo4j outcome for node %s: %s", node_id, exc)
