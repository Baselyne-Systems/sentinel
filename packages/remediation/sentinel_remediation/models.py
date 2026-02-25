"""
Data contracts for the SENTINEL remediation layer.

Defines the full lifecycle of a remediation job:

    RemediationAction  — enum of 8 safe, reversible AWS remediations
    JobStatus          — pending → approved → executing → completed | failed
                                         ↓
                                      rejected
    RemediationProposal — what the planner wants to do (not yet approved)
    RemediationJob      — a proposal with lifecycle tracking fields
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RemediationAction(StrEnum):
    """8 safe, reversible AWS remediation actions supported by Phase 3.

    Each action maps to a single boto3 API call in the corresponding remediator
    module and is triggered by a specific CIS posture flag.

    All actions are reversible — no data is permanently destroyed.
    """

    S3_BLOCK_PUBLIC_ACCESS = "s3_block_public_access"
    S3_ENABLE_VERSIONING = "s3_enable_versioning"
    S3_ENABLE_SSE = "s3_enable_sse"
    S3_ENABLE_LOGGING = "s3_enable_logging"
    EC2_ENABLE_EBS_ENCRYPTION = "ec2_enable_ebs_encryption"
    CLOUDTRAIL_ENABLE = "cloudtrail_enable"
    CLOUDTRAIL_LOG_VALIDATION = "cloudtrail_log_validation"
    RDS_DISABLE_PUBLIC_ACCESS = "rds_disable_public_access"


class JobStatus(StrEnum):
    """Lifecycle states for a remediation job.

    State machine:
        PENDING    → APPROVED   (user clicks Approve in UI)
        PENDING    → REJECTED   (user clicks Reject in UI)
        APPROVED   → EXECUTING  (background task starts)
        EXECUTING  → COMPLETED  (boto3 call succeeded)
        EXECUTING  → FAILED     (boto3 call raised exception)
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class RemediationProposal(BaseModel):
    """A proposed remediation for a specific flagged resource.

    Built by ``RemediationPlanner`` from a node's posture_flags.
    Carried inside ``RemediationJob`` for the full lifecycle.

    Attributes:
        action:         Which remediation to execute.
        node_id:        Neo4j node_id of the resource to remediate.
        resource_type:  Human-readable type (e.g. ``S3Bucket``).
        account_id:     AWS account where the resource lives.
        region:         AWS region for the resource.
        description:    One-sentence human-readable explanation of the action.
        risk_reduction: Why this matters — concise impact statement.
        params:         boto3 call parameters (e.g. bucket_name, db_id).
    """

    action: RemediationAction
    node_id: str
    resource_type: str
    account_id: str
    region: str
    description: str
    risk_reduction: str
    params: dict = Field(default_factory=dict)


class RemediationJob(BaseModel):
    """A remediation proposal with full lifecycle tracking.

    Created by ``RemediationPlanner.propose()`` with status=PENDING.
    Transitions through states as the human approves/rejects and the
    executor runs the boto3 call.

    Attributes:
        job_id:       UUID string, assigned at creation.
        proposal:     The underlying remediation proposal.
        status:       Current lifecycle state.
        proposed_at:  ISO UTC timestamp when job was created.
        approved_at:  ISO UTC when user approved (None until then).
        rejected_at:  ISO UTC when user rejected (None until then).
        executed_at:  ISO UTC when execution started (None until then).
        completed_at: ISO UTC when execution finished (None until then).
        error:        Error message if status=FAILED (None otherwise).
        output:       Summary dict from the boto3 call (None until completed).
    """

    job_id: str
    proposal: RemediationProposal
    status: JobStatus = JobStatus.PENDING
    proposed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    approved_at: str | None = None
    rejected_at: str | None = None
    executed_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    output: dict | None = None
