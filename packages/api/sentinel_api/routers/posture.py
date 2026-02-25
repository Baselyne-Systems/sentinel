"""
/api/v1/posture — security posture findings and CIS benchmark endpoints.

These endpoints expose the result of running CIS AWS Foundations Benchmark v1.5
rules against the environment graph. Findings are read from posture_flags already
stamped on nodes during the last scan — they are NOT recomputed on each request.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from sentinel_api.deps import EvaluatorDep, QueriesDep
from sentinel_api.schemas import (
    CISRuleResponse,
    FindingResponse,
    PostureSummaryResponse,
)
from sentinel_core.knowledge.rules import ALL_RULES

router = APIRouter(prefix="/posture", tags=["posture"])


@router.get(
    "/findings",
    response_model=list[FindingResponse],
    summary="List security findings",
    description=(
        "Return all resources that have CIS posture violations stamped from the last scan. "
        "Findings are read from the graph (posture_flags property on nodes) — "
        "this endpoint does **not** re-run the evaluator. "
        "Filter by severity and/or resource type to narrow results."
    ),
    responses={
        200: {"description": "List of resources with active posture violations"},
    },
)
async def get_findings(
    evaluator: EvaluatorDep,
    severity: str | None = Query(
        None,
        description="Filter by severity level.",
        examples={
            "critical": {"value": "CRITICAL"},
            "high": {"value": "HIGH"},
        },
    ),
    resource_type: str | None = Query(
        None,
        description="Filter by resource type (e.g. 'S3Bucket', 'SecurityGroup').",
        examples={
            "s3": {"value": "S3Bucket"},
            "sg": {"value": "SecurityGroup"},
        },
    ),
    account_id: str | None = Query(
        None, description="Filter findings to a specific AWS account."
    ),
) -> list[dict[str, Any]]:
    """
    Return all nodes with posture violations.

    Reads stamped posture_flags from the graph. The highest severity in a node's
    posture_flags is used as the finding's severity. A node with both HIGH-level
    and CRITICAL-level flags is reported with severity CRITICAL.
    """
    return await evaluator.get_findings_from_graph(
        account_id=account_id,
        severity=severity,
        resource_type=resource_type,
    )


@router.get(
    "/summary",
    response_model=PostureSummaryResponse,
    summary="Posture summary",
    description=(
        "Return an aggregated posture summary: total resource count, finding counts by severity, "
        "and overall CIS alignment percentage. "
        "The alignment percentage is `(1 - nodes_with_any_finding / total_nodes) * 100`. "
        "A score of 100% means zero CIS violations detected."
    ),
    responses={
        200: {"description": "Aggregated posture summary"},
    },
)
async def get_posture_summary(
    queries: QueriesDep,
    account_id: str | None = Query(
        None, description="Scope summary to a specific AWS account."
    ),
) -> dict[str, Any]:
    """
    Return posture summary with counts by severity and CIS alignment percentage.
    """
    summary = await queries.get_posture_summary(account_id=account_id)

    total = summary.get("total_nodes", 0)
    critical = summary.get("critical_count", 0)
    high = summary.get("high_count", 0)
    medium = summary.get("medium_count", 0)
    low = summary.get("low_count", 0)

    total_findings = critical + high + medium + low
    alignment_pct = round((1 - total_findings / max(total, 1)) * 100, 1)

    return {
        "total_nodes": total,
        "findings_by_severity": {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
        },
        "alignment_percentage": alignment_pct,
        "account_id": account_id,
    }


@router.get(
    "/rules",
    response_model=list[CISRuleResponse],
    summary="List CIS benchmark rules",
    description=(
        "Return all CIS AWS Foundations Benchmark v1.5 rules loaded into SENTINEL. "
        "Each rule includes the Cypher-based check description, severity, affected resource types, "
        "and remediation guidance. Rules are the source of truth for what SENTINEL evaluates — "
        "new rules added here are automatically evaluated on the next scan."
    ),
    responses={
        200: {"description": "All loaded CIS benchmark rules"},
    },
)
async def list_rules() -> list[dict[str, Any]]:
    """
    Return all CIS benchmark rules.

    Rules are Python dataclasses loaded at startup from
    ``sentinel_core/knowledge/rules.py``. Adding a new rule there immediately
    exposes it in this endpoint and in future scan evaluations.
    """
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "resource_types": [str(rt) for rt in rule.resource_types],
            "posture_flag": rule.posture_flag,
            "remediation_hint": rule.remediation_hint,
            "tags": rule.tags,
        }
        for rule in ALL_RULES
    ]
