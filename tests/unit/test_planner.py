"""
Unit tests for RemediationPlanner.

Tests that:
- Each actionable PostureFlag maps to the correct RemediationAction.
- Unknown flags are silently skipped.
- Missing required node properties degrade gracefully.
- Multiple flags on one node produce multiple jobs.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sentinel_remediation.models import JobStatus, RemediationAction
from sentinel_remediation.planner import RemediationPlanner

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_neo4j_client(node_props: dict) -> AsyncMock:
    """Return a mock Neo4j client whose query() returns the given node properties."""
    client = AsyncMock()
    client.query = AsyncMock(return_value=[{"props": node_props}])
    return client


def _make_s3_node(flags: list[str]) -> dict:
    return {
        "node_id": "s3::my-bucket",
        "resource_type": "S3Bucket",
        "account_id": "123456789012",
        "region": "us-east-1",
        "name": "my-bucket",
        "posture_flags": flags,
    }


def _make_ec2_node(flags: list[str]) -> dict:
    return {
        "node_id": "ec2::i-12345",
        "resource_type": "EC2Instance",
        "account_id": "123456789012",
        "region": "us-east-1",
        "instance_id": "i-12345",
        "posture_flags": flags,
    }


def _make_rds_node(flags: list[str]) -> dict:
    return {
        "node_id": "rds::my-db",
        "resource_type": "RDSInstance",
        "account_id": "123456789012",
        "region": "us-east-1",
        "db_id": "my-db",
        "posture_flags": flags,
    }


def _make_account_node(flags: list[str]) -> dict:
    return {
        "node_id": "account::123456789012",
        "resource_type": "AWSAccount",
        "account_id": "123456789012",
        "region": "us-east-1",
        "posture_flags": flags,
    }


# ── S3 flag tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_s3_public_access_maps_to_block_public_access():
    node = _make_s3_node(["S3_PUBLIC_ACCESS"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.S3_BLOCK_PUBLIC_ACCESS
    assert jobs[0].proposal.params["bucket_name"] == "my-bucket"
    assert jobs[0].status == JobStatus.PENDING


@pytest.mark.asyncio
async def test_s3_no_versioning_maps_to_enable_versioning():
    node = _make_s3_node(["S3_NO_VERSIONING"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.S3_ENABLE_VERSIONING


@pytest.mark.asyncio
async def test_s3_no_encryption_maps_to_enable_sse():
    node = _make_s3_node(["S3_NO_ENCRYPTION"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.S3_ENABLE_SSE


@pytest.mark.asyncio
async def test_s3_no_logging_maps_to_enable_logging():
    node = _make_s3_node(["S3_NO_LOGGING"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.S3_ENABLE_LOGGING


# ── EC2 / CloudTrail / RDS flag tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_ebs_unencrypted_maps_to_enable_ebs_encryption():
    node = _make_ec2_node(["EBS_UNENCRYPTED"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("ec2::i-12345", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.EC2_ENABLE_EBS_ENCRYPTION
    assert jobs[0].proposal.params["region"] == "us-east-1"


@pytest.mark.asyncio
async def test_no_cloudtrail_maps_to_cloudtrail_enable():
    node = _make_account_node(["NO_CLOUDTRAIL"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("account::123456789012", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.CLOUDTRAIL_ENABLE


@pytest.mark.asyncio
async def test_no_cloudtrail_validation_maps_to_cloudtrail_log_validation():
    node = _make_account_node(["NO_CLOUDTRAIL_VALIDATION"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("account::123456789012", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.CLOUDTRAIL_LOG_VALIDATION


@pytest.mark.asyncio
async def test_rds_public_maps_to_disable_public_access():
    node = _make_rds_node(["RDS_PUBLIC"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("rds::my-db", client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.RDS_DISABLE_PUBLIC_ACCESS
    assert jobs[0].proposal.params["db_id"] == "my-db"


# ── Edge cases ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_flag_is_skipped():
    node = _make_s3_node(["SG_OPEN_SSH", "IAM_NO_MFA"])  # not remediable
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert jobs == []


@pytest.mark.asyncio
async def test_empty_flags_returns_empty_list():
    node = _make_s3_node([])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert jobs == []


@pytest.mark.asyncio
async def test_multiple_flags_produce_multiple_jobs():
    node = _make_s3_node(["S3_PUBLIC_ACCESS", "S3_NO_VERSIONING", "S3_NO_ENCRYPTION"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 3
    actions = {j.proposal.action for j in jobs}
    assert RemediationAction.S3_BLOCK_PUBLIC_ACCESS in actions
    assert RemediationAction.S3_ENABLE_VERSIONING in actions
    assert RemediationAction.S3_ENABLE_SSE in actions


@pytest.mark.asyncio
async def test_mixed_known_and_unknown_flags():
    node = _make_s3_node(["S3_PUBLIC_ACCESS", "IAM_NO_MFA", "S3_NO_LOGGING"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    assert len(jobs) == 2
    actions = {j.proposal.action for j in jobs}
    assert RemediationAction.S3_BLOCK_PUBLIC_ACCESS in actions
    assert RemediationAction.S3_ENABLE_LOGGING in actions


@pytest.mark.asyncio
async def test_node_not_found_raises_value_error():
    client = AsyncMock()
    client.query = AsyncMock(return_value=[])
    planner = RemediationPlanner()
    with pytest.raises(ValueError, match="not found"):
        await planner.propose("nonexistent::node", client)


@pytest.mark.asyncio
async def test_all_jobs_start_pending():
    node = _make_s3_node(["S3_PUBLIC_ACCESS", "S3_NO_VERSIONING"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    for job in jobs:
        assert job.status == JobStatus.PENDING


@pytest.mark.asyncio
async def test_each_job_has_unique_job_id():
    node = _make_s3_node(["S3_PUBLIC_ACCESS", "S3_NO_VERSIONING", "S3_NO_ENCRYPTION"])
    client = _make_neo4j_client(node)
    planner = RemediationPlanner()
    jobs = await planner.propose("s3::my-bucket", client)

    job_ids = [j.job_id for j in jobs]
    assert len(job_ids) == len(set(job_ids))
