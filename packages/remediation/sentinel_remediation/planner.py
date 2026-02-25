"""
RemediationPlanner — maps CIS posture_flags on a graph node to RemediationJobs.

Design:
    - Each supported PostureFlag maps to a factory function that builds a
      ``RemediationProposal`` from the node's Neo4j properties.
    - Unknown flags are silently skipped (future-proof for new CIS rules).
    - The planner reads the node from Neo4j, never mutates it.
    - Returns a list of ``RemediationJob`` objects (status=PENDING), one per
      actionable flag found on the node.

Usage::

    planner = RemediationPlanner()
    jobs = await planner.propose(node_id="s3::my-bucket", neo4j_client=client)
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any

from sentinel_remediation.models import (
    JobStatus,
    RemediationAction,
    RemediationJob,
    RemediationProposal,
)

logger = logging.getLogger(__name__)


# ── Proposal factory helpers ───────────────────────────────────────────────────


def _s3_block_public_access(node: dict[str, Any]) -> RemediationProposal | None:
    bucket_name = node.get("name") or node.get("node_id", "")
    if not bucket_name:
        return None
    return RemediationProposal(
        action=RemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "S3Bucket"),
        account_id=node.get("account_id", ""),
        region=node.get("region", "us-east-1"),
        description=f"Enable S3 Block Public Access on bucket '{bucket_name}'.",
        risk_reduction=(
            "Prevents data exfiltration and public exposure of sensitive objects "
            "by blocking all ACL- and policy-based public access vectors."
        ),
        params={"bucket_name": bucket_name},
    )


def _s3_enable_versioning(node: dict[str, Any]) -> RemediationProposal | None:
    bucket_name = node.get("name") or node.get("node_id", "")
    if not bucket_name:
        return None
    return RemediationProposal(
        action=RemediationAction.S3_ENABLE_VERSIONING,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "S3Bucket"),
        account_id=node.get("account_id", ""),
        region=node.get("region", "us-east-1"),
        description=f"Enable object versioning on S3 bucket '{bucket_name}'.",
        risk_reduction=(
            "Protects against accidental deletion and overwrites; enables point-in-time "
            "recovery of objects compromised by ransomware or misconfiguration."
        ),
        params={"bucket_name": bucket_name},
    )


def _s3_enable_sse(node: dict[str, Any]) -> RemediationProposal | None:
    bucket_name = node.get("name") or node.get("node_id", "")
    if not bucket_name:
        return None
    return RemediationProposal(
        action=RemediationAction.S3_ENABLE_SSE,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "S3Bucket"),
        account_id=node.get("account_id", ""),
        region=node.get("region", "us-east-1"),
        description=f"Enable AES-256 server-side encryption on S3 bucket '{bucket_name}'.",
        risk_reduction=(
            "Ensures data-at-rest is encrypted; satisfies CIS AWS 2.1.1 and common "
            "compliance requirements (PCI-DSS, HIPAA, SOC 2)."
        ),
        params={"bucket_name": bucket_name},
    )


def _s3_enable_logging(node: dict[str, Any]) -> RemediationProposal | None:
    bucket_name = node.get("name") or node.get("node_id", "")
    if not bucket_name:
        return None
    return RemediationProposal(
        action=RemediationAction.S3_ENABLE_LOGGING,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "S3Bucket"),
        account_id=node.get("account_id", ""),
        region=node.get("region", "us-east-1"),
        description=f"Enable server access logging on S3 bucket '{bucket_name}'.",
        risk_reduction=(
            "Provides an audit trail for object access requests; required for "
            "forensics after a data exposure incident."
        ),
        params={"bucket_name": bucket_name, "target_prefix": "logs/"},
    )


def _ec2_enable_ebs_encryption(node: dict[str, Any]) -> RemediationProposal | None:
    region = node.get("region", "us-east-1")
    return RemediationProposal(
        action=RemediationAction.EC2_ENABLE_EBS_ENCRYPTION,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "EC2Instance"),
        account_id=node.get("account_id", ""),
        region=region,
        description=f"Enable EBS encryption by default in region '{region}'.",
        risk_reduction=(
            "All new EBS volumes and snapshots are automatically encrypted, "
            "preventing unencrypted data from persisting if an EC2 instance "
            "is terminated or a snapshot is shared."
        ),
        params={"region": region},
    )


def _cloudtrail_enable(node: dict[str, Any]) -> RemediationProposal | None:
    account_id = node.get("account_id", "")
    region = node.get("region", "us-east-1")
    return RemediationProposal(
        action=RemediationAction.CLOUDTRAIL_ENABLE,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "AWSAccount"),
        account_id=account_id,
        region=region,
        description=f"Create and start a multi-region CloudTrail trail in account '{account_id}'.",
        risk_reduction=(
            "CloudTrail is the primary audit log for AWS management-plane activity. "
            "Without it, there is no forensic record of API calls made by attackers "
            "or misconfigured automation."
        ),
        params={"account_id": account_id, "region": region},
    )


def _cloudtrail_log_validation(node: dict[str, Any]) -> RemediationProposal | None:
    account_id = node.get("account_id", "")
    region = node.get("region", "us-east-1")
    trail_name = node.get("trail_name") or "sentinel-trail"
    return RemediationProposal(
        action=RemediationAction.CLOUDTRAIL_LOG_VALIDATION,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "AWSAccount"),
        account_id=account_id,
        region=region,
        description=f"Enable log file integrity validation on CloudTrail trail '{trail_name}'.",
        risk_reduction=(
            "Log file validation uses digest files to detect tampering or deletion "
            "of CloudTrail log files — critical for meeting CIS AWS 3.2."
        ),
        params={"trail_name": trail_name, "region": region},
    )


def _rds_disable_public_access(node: dict[str, Any]) -> RemediationProposal | None:
    db_id = node.get("db_id") or node.get("node_id", "")
    region = node.get("region", "us-east-1")
    if not db_id:
        return None
    return RemediationProposal(
        action=RemediationAction.RDS_DISABLE_PUBLIC_ACCESS,
        node_id=node["node_id"],
        resource_type=node.get("resource_type", "RDSInstance"),
        account_id=node.get("account_id", ""),
        region=region,
        description=f"Disable public accessibility on RDS instance '{db_id}'.",
        risk_reduction=(
            "Removes direct internet exposure of the database endpoint; "
            "prevents unauthenticated connection attempts and brute-force attacks "
            "from outside the VPC."
        ),
        params={"db_id": db_id, "region": region},
    )


# ── Flag → factory mapping ─────────────────────────────────────────────────────

# Maps PostureFlag string value → proposal factory function.
# Keys match the actual PostureFlag enum values from sentinel_core.models.enums.
_FLAG_MAP: dict[str, Callable[[dict[str, Any]], RemediationProposal | None]] = {
    "S3_PUBLIC_ACCESS": _s3_block_public_access,
    "S3_NO_VERSIONING": _s3_enable_versioning,
    "S3_NO_ENCRYPTION": _s3_enable_sse,
    "S3_NO_LOGGING": _s3_enable_logging,
    "EBS_UNENCRYPTED": _ec2_enable_ebs_encryption,
    "NO_CLOUDTRAIL": _cloudtrail_enable,
    "NO_CLOUDTRAIL_VALIDATION": _cloudtrail_log_validation,
    "RDS_PUBLIC": _rds_disable_public_access,
}


# ── Planner ────────────────────────────────────────────────────────────────────


class RemediationPlanner:
    """Maps posture_flags on a graph node to a list of RemediationJobs.

    Queries Neo4j for the node's current properties and flags, then builds
    a ``RemediationJob`` (status=PENDING) for each flag that has a supported
    remediation action.

    Flags with no registered handler are silently skipped — this future-proofs
    the planner as new CIS rules are added without breaking existing behaviour.
    """

    async def propose(
        self,
        node_id: str,
        neo4j_client: Any,
    ) -> list[RemediationJob]:
        """Build pending remediation jobs for all actionable flags on a node.

        Args:
            node_id:      The Neo4j node_id to inspect.
            neo4j_client: An connected ``Neo4jClient`` instance.

        Returns:
            List of ``RemediationJob`` objects (status=PENDING), one per
            actionable posture_flag.  Empty list if no actionable flags.

        Raises:
            ValueError: If the node_id is not found in Neo4j.
        """
        records = await neo4j_client.query(
            "MATCH (n {node_id: $node_id}) RETURN properties(n) AS props LIMIT 1",
            {"node_id": node_id},
        )
        if not records:
            raise ValueError(f"Node '{node_id}' not found in the graph.")

        node_data: dict[str, Any] = records[0]["props"]
        node_data["node_id"] = node_id  # ensure node_id is in the dict

        flags: list[str] = node_data.get("posture_flags") or []
        jobs: list[RemediationJob] = []

        for flag in flags:
            factory = _FLAG_MAP.get(flag)
            if factory is None:
                logger.debug("No remediator registered for flag %s — skipping", flag)
                continue

            proposal = factory(node_data)
            if proposal is None:
                logger.warning("Factory for flag %s returned None for node %s", flag, node_id)
                continue

            job = RemediationJob(
                job_id=str(uuid.uuid4()),
                proposal=proposal,
                status=JobStatus.PENDING,
            )
            jobs.append(job)
            logger.info("Proposed %s for node %s (job %s)", proposal.action, node_id, job.job_id)

        return jobs
