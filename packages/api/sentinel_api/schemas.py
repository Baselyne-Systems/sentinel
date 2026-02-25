"""
Pydantic response schemas for the SENTINEL API.

These models define the exact shape of every API response, ensuring
consistent serialization and rich OpenAPI documentation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Shared primitives ─────────────────────────────────────────────────────────


class PostureFlagItem(BaseModel):
    """A single CIS posture flag stamped on a resource."""

    flag: str = Field(..., description="Machine-readable flag name, e.g. 'SG_OPEN_SSH'")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")

    model_config = {
        "json_schema_extra": {
            "example": {"flag": "SG_OPEN_SSH", "severity": "CRITICAL"}
        }
    }


# ── Graph ─────────────────────────────────────────────────────────────────────


class GraphNodeResponse(BaseModel):
    """A node in the SENTINEL environment graph."""

    node_id: str = Field(..., description="Globally unique identifier for this node.")
    resource_type: str = Field(
        ...,
        description=(
            "AWS resource type label. One of: AWSAccount, Region, EC2Instance, "
            "SecurityGroup, VPC, Subnet, S3Bucket, RDSInstance, LambdaFunction, "
            "IAMRole, IAMUser, IAMPolicy."
        ),
    )
    cloud_provider: str = Field(default="aws", description="Cloud provider (always 'aws' in Phase 1).")
    account_id: str = Field(..., description="AWS account ID that owns this resource.")
    region: str = Field(default="", description="AWS region. Empty string for global resources (IAM, S3).")
    tags: dict[str, str] = Field(default_factory=dict, description="AWS resource tags as key-value pairs.")
    posture_flags: list[str] = Field(
        default_factory=list,
        description=(
            "CIS posture violations detected on this node. Includes both severity labels "
            "(CRITICAL, HIGH, MEDIUM, LOW) and specific flag names (SG_OPEN_SSH, S3_PUBLIC_ACCESS…)."
        ),
    )
    discovered_at: str = Field(..., description="ISO-8601 timestamp when this node was last discovered.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "node_id": "sg-0abc12345",
                "resource_type": "SecurityGroup",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "tags": {"Name": "web-sg", "Env": "prod"},
                "posture_flags": ["CRITICAL", "SG_OPEN_SSH"],
                "discovered_at": "2026-02-25T10:30:00Z",
            }
        }
    }


class GraphNodeDetailResponse(GraphNodeResponse):
    """A graph node with its immediate edges."""

    edges: list[dict[str, Any]] = Field(
        default_factory=list,
        description="All edges connected to this node. Each edge has edge_type, neighbor_id, neighbor_type, is_outbound.",
    )

    model_config = {"extra": "allow"}


class GraphEdgeResponse(BaseModel):
    """An edge (relationship) between two nodes."""

    from_node_id: str = Field(..., description="Source node ID.")
    to_node_id: str = Field(..., description="Target node ID.")
    edge_type: str = Field(
        ...,
        description="Relationship type. One of: HAS_RESOURCE, IN_VPC, IN_SUBNET, MEMBER_OF_SG, CAN_ASSUME, HAS_ATTACHED_POLICY, EXECUTES_AS, PEER_OF.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "from_node_id": "i-0abc12345",
                "to_node_id": "sg-0abc12345",
                "edge_type": "MEMBER_OF_SG",
            }
        }
    }


class SubgraphResponse(BaseModel):
    """A subgraph (nodes + edges) for the Graph Explorer."""

    root_node_id: str = Field(..., description="The node ID at the center of this subgraph.")
    nodes: list[dict[str, Any]] = Field(
        ..., description="All nodes within the requested depth from the root."
    )
    edges: list[dict[str, Any]] = Field(
        ..., description="All edges connecting the returned nodes."
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "root_node_id": "vpc-0abc12345",
                "nodes": [
                    {"node_id": "vpc-0abc12345", "resource_type": "VPC"},
                    {"node_id": "subnet-0abc12345", "resource_type": "Subnet"},
                ],
                "edges": [
                    {"from": "subnet-0abc12345", "to": "vpc-0abc12345", "type": "IN_VPC"}
                ],
            }
        }
    }


# ── Posture ───────────────────────────────────────────────────────────────────


class FindingResponse(BaseModel):
    """A security posture finding — a CIS rule violation on a specific resource."""

    node_id: str = Field(..., description="ID of the violating resource.")
    resource_type: str = Field(..., description="Type of the violating resource.")
    severity: str = Field(..., description="Highest severity among this node's posture flags.")
    posture_flags: list[str] = Field(
        ..., description="All CIS posture flags stamped on this node."
    )
    account_id: str = Field(..., description="AWS account ID.")
    region: str = Field(default="", description="AWS region (empty for global resources).")

    model_config = {
        "json_schema_extra": {
            "example": {
                "node_id": "s3-my-prod-bucket",
                "resource_type": "S3Bucket",
                "severity": "CRITICAL",
                "posture_flags": ["CRITICAL", "S3_PUBLIC_ACCESS", "S3_NO_VERSIONING"],
                "account_id": "123456789012",
                "region": "us-east-1",
            }
        }
    }


class FindingsBySeverity(BaseModel):
    """Finding counts broken down by severity."""

    CRITICAL: int = Field(0, description="Number of resources with at least one CRITICAL finding.")
    HIGH: int = Field(0, description="Number of resources with at least one HIGH finding.")
    MEDIUM: int = Field(0, description="Number of resources with at least one MEDIUM finding.")
    LOW: int = Field(0, description="Number of resources with at least one LOW finding.")


class PostureSummaryResponse(BaseModel):
    """Aggregated security posture summary for an account."""

    total_nodes: int = Field(
        ..., description="Total number of discovered resources in the graph."
    )
    findings_by_severity: FindingsBySeverity = Field(
        ..., description="Count of resources with findings at each severity level."
    )
    alignment_percentage: float = Field(
        ...,
        ge=0,
        le=100,
        description=(
            "Percentage of resources with no CIS violations. "
            "100% = fully compliant. Calculated as (1 - findings/total) * 100."
        ),
    )
    account_id: str | None = Field(
        None, description="AWS account ID filter applied to this summary, if any."
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "total_nodes": 142,
                "findings_by_severity": {
                    "CRITICAL": 3,
                    "HIGH": 12,
                    "MEDIUM": 7,
                    "LOW": 4,
                },
                "alignment_percentage": 81.7,
                "account_id": "123456789012",
            }
        }
    }


class CISRuleResponse(BaseModel):
    """A CIS AWS Foundations Benchmark v1.5 rule loaded into SENTINEL."""

    id: str = Field(..., description="CIS rule identifier, e.g. 'CIS-2.1.5'.")
    title: str = Field(..., description="Human-readable rule title.")
    severity: str = Field(..., description="Rule severity: CRITICAL | HIGH | MEDIUM | LOW.")
    resource_types: list[str] = Field(
        ..., description="AWS resource types this rule applies to."
    )
    posture_flag: str = Field(
        ..., description="Flag stamped on violating nodes, e.g. 'S3_PUBLIC_ACCESS'."
    )
    remediation_hint: str = Field(
        ..., description="Brief remediation guidance for this rule."
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Categorization tags, e.g. ['s3', 'public-access'].",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "CIS-2.1.5",
                "title": "Ensure that S3 Buckets are configured with 'Block public access'",
                "severity": "CRITICAL",
                "resource_types": ["S3Bucket"],
                "posture_flag": "S3_PUBLIC_ACCESS",
                "remediation_hint": "Enable S3 Block Public Access at both bucket and account level.",
                "tags": ["s3", "public-access"],
            }
        }
    }


# ── Scan ──────────────────────────────────────────────────────────────────────


class ScanTriggerResponse(BaseModel):
    """Response from POST /scan/trigger."""

    job_id: str = Field(..., description="UUID identifying this scan job. Use to poll /scan/{job_id}/status.")
    status: str = Field(default="queued", description="Initial job status. Always 'queued' on trigger.")
    account_id: str = Field(..., description="AWS account being scanned.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "queued",
                "account_id": "123456789012",
            }
        }
    }


class ScanResultDetail(BaseModel):
    """Detailed results from a completed scan."""

    nodes_written: int = Field(..., description="Total graph nodes upserted to Neo4j.")
    edges_written: int = Field(..., description="Total graph edges upserted to Neo4j.")
    findings_count: int = Field(..., description="Total CIS rule violations found.")
    duration_seconds: float = Field(..., description="Total scan duration in seconds.")
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during the scan (e.g., permission-denied for a region).",
    )


class ScanJobResponse(BaseModel):
    """Full scan job record, returned from GET /scan/{job_id}/status."""

    job_id: str = Field(..., description="Unique scan job identifier.")
    status: str = Field(
        ...,
        description="Job lifecycle state: queued → running → completed | failed.",
    )
    account_id: str = Field(..., description="AWS account being scanned.")
    regions: list[str] = Field(..., description="AWS regions included in this scan.")
    started_at: str = Field(..., description="ISO-8601 timestamp when job was queued.")
    completed_at: str | None = Field(
        None, description="ISO-8601 timestamp when job finished (null if still running)."
    )
    result: ScanResultDetail | None = Field(
        None, description="Scan results (null until status = completed)."
    )
    error: str | None = Field(
        None, description="Top-level error message (null unless status = failed)."
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "account_id": "123456789012",
                "regions": ["us-east-1", "us-west-2"],
                "started_at": "2026-02-25T10:30:00Z",
                "completed_at": "2026-02-25T10:31:47Z",
                "result": {
                    "nodes_written": 234,
                    "edges_written": 412,
                    "findings_count": 18,
                    "duration_seconds": 107.3,
                    "errors": [],
                },
                "error": None,
            }
        }
    }


# ── Accounts ──────────────────────────────────────────────────────────────────


class AccountResponse(BaseModel):
    """A registered AWS account in SENTINEL."""

    account_id: str = Field(..., description="12-digit AWS account ID.")
    name: str = Field(default="", description="Human-friendly account name.")
    assume_role_arn: str = Field(
        default="",
        description=(
            "IAM Role ARN to assume for cross-account access. "
            "Leave empty to use the default credential chain."
        ),
    )
    regions: list[str] = Field(
        ..., description="AWS regions to scan for this account."
    )
    registered_at: str = Field(..., description="ISO-8601 timestamp when account was registered.")
    updated_at: str = Field(..., description="ISO-8601 timestamp of last update.")

    model_config = {
        "json_schema_extra": {
            "example": {
                "account_id": "123456789012",
                "name": "Production",
                "assume_role_arn": "arn:aws:iam::123456789012:role/SentinelReadOnly",
                "regions": ["us-east-1", "us-west-2", "eu-west-1"],
                "registered_at": "2026-02-25T09:00:00Z",
                "updated_at": "2026-02-25T09:00:00Z",
            }
        }
    }


# ── Error ─────────────────────────────────────────────────────────────────────


class ErrorResponse(BaseModel):
    """Standard error response body."""

    detail: str = Field(..., description="Human-readable error description.")

    model_config = {
        "json_schema_extra": {"example": {"detail": "Node 'i-nonexistent' not found"}}
    }
