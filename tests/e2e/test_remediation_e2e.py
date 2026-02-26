"""
E2E tests for the remediation pipeline.

Tests the full flow:
    1. Write a flagged node to Neo4j (testcontainers).
    2. Propose remediations via RemediationPlanner.
    3. Approve a job via RemediationExecutor with a mocked boto3 session.
    4. Verify the Neo4j node is updated with remediated_at + remediation_job_id.
    5. Verify job status is COMPLETED.

AWS calls use moto (S3/EC2/RDS/CloudTrail) or are mocked at the boto3 level
so no real AWS credentials are required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import RDSInstance, S3Bucket
from sentinel_remediation.executor import RemediationExecutor
from sentinel_remediation.models import JobStatus, RemediationAction
from sentinel_remediation.planner import RemediationPlanner

pytestmark = pytest.mark.e2e


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def s3_flagged_node(clean_db: Neo4jClient) -> tuple[str, Neo4jClient]:
    """Write an S3 bucket node with S3_PUBLIC_ACCESS and S3_NO_VERSIONING flags."""
    bucket = S3Bucket(
        node_id="s3::test-remediation-bucket",
        account_id="123456789012",
        region="us-east-1",
        name="test-remediation-bucket",
        is_public=True,
        versioning=False,
        posture_flags=[PostureFlag.S3_PUBLIC_ACCESS, PostureFlag.S3_NO_VERSIONING],
    )
    await clean_db.upsert_node(bucket)
    return bucket.node_id, clean_db


@pytest_asyncio.fixture
async def rds_flagged_node(clean_db: Neo4jClient) -> tuple[str, Neo4jClient]:
    """Write an RDS instance node with RDS_PUBLIC flag."""
    db = RDSInstance(
        node_id="rds::test-remediation-db",
        account_id="123456789012",
        region="us-east-1",
        db_id="test-remediation-db",
        publicly_accessible=True,
        engine="postgres",
        posture_flags=[PostureFlag.RDS_PUBLIC],
    )
    await clean_db.upsert_node(db)
    return db.node_id, clean_db


# ── Planner E2E tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_planner_proposes_jobs_from_neo4j_node(s3_flagged_node):
    node_id, client = s3_flagged_node
    planner = RemediationPlanner()
    jobs = await planner.propose(node_id=node_id, neo4j_client=client)

    assert len(jobs) == 2
    actions = {j.proposal.action for j in jobs}
    assert RemediationAction.S3_BLOCK_PUBLIC_ACCESS in actions
    assert RemediationAction.S3_ENABLE_VERSIONING in actions

    for job in jobs:
        assert job.status == JobStatus.PENDING
        assert job.proposal.node_id == node_id
        assert job.proposal.account_id == "123456789012"
        assert job.proposal.params["bucket_name"] == "test-remediation-bucket"


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_planner_proposes_rds_job(rds_flagged_node):
    node_id, client = rds_flagged_node
    planner = RemediationPlanner()
    jobs = await planner.propose(node_id=node_id, neo4j_client=client)

    assert len(jobs) == 1
    assert jobs[0].proposal.action == RemediationAction.RDS_DISABLE_PUBLIC_ACCESS
    assert jobs[0].proposal.params["db_id"] == "test-remediation-db"


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_planner_node_not_found_raises(clean_db: Neo4jClient):
    planner = RemediationPlanner()
    with pytest.raises(ValueError, match="not found"):
        await planner.propose(node_id="nonexistent::node", neo4j_client=clean_db)


# ── Executor E2E tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_executor_completes_s3_job_and_writes_neo4j(s3_flagged_node):
    """Executor runs S3 block-public-access and stamps the Neo4j node."""
    node_id, client = s3_flagged_node

    planner = RemediationPlanner()
    jobs = await planner.propose(node_id=node_id, neo4j_client=client)
    # Pick the block_public_access job
    job = next(j for j in jobs if j.proposal.action == RemediationAction.S3_BLOCK_PUBLIC_ACCESS)
    job.status = JobStatus.APPROVED

    # Mock the boto3 session so no real S3 calls are made
    mock_session = MagicMock()
    s3_mock = MagicMock()
    mock_session.client.return_value = s3_mock

    executor = RemediationExecutor()
    with patch("sentinel_remediation.executor._build_session", return_value=mock_session):
        updated = await executor.execute(job=job, neo4j_client=client)

    assert updated.status == JobStatus.COMPLETED
    assert updated.output is not None
    assert updated.output["public_access_blocked"] is True
    assert updated.completed_at is not None
    assert updated.error is None

    # Verify Neo4j node was stamped
    records = await client.query(
        "MATCH (n {node_id: $nid}) RETURN n.remediated_at AS ra, n.remediation_job_id AS jid",
        {"nid": node_id},
    )
    assert records[0]["ra"] is not None
    assert records[0]["jid"] == updated.job_id


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_executor_handles_boto3_failure_with_failed_status(s3_flagged_node):
    """Executor sets status=FAILED if boto3 raises an exception."""
    node_id, client = s3_flagged_node

    planner = RemediationPlanner()
    jobs = await planner.propose(node_id=node_id, neo4j_client=client)
    job = next(j for j in jobs if j.proposal.action == RemediationAction.S3_BLOCK_PUBLIC_ACCESS)
    job.status = JobStatus.APPROVED

    mock_session = MagicMock()
    s3_mock = MagicMock()
    s3_mock.put_public_access_block.side_effect = Exception("AccessDenied")
    mock_session.client.return_value = s3_mock

    executor = RemediationExecutor()
    with patch("sentinel_remediation.executor._build_session", return_value=mock_session):
        updated = await executor.execute(job=job, neo4j_client=client)

    assert updated.status == JobStatus.FAILED
    assert "AccessDenied" in (updated.error or "")
    assert updated.output is None


@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_full_pipeline_propose_approve_complete(s3_flagged_node):
    """Full pipeline: propose → approve → execute → verify COMPLETED."""
    node_id, client = s3_flagged_node

    # 1. Propose
    planner = RemediationPlanner()
    jobs = await planner.propose(node_id=node_id, neo4j_client=client)
    assert len(jobs) == 2

    # 2. Pick one and approve
    job = jobs[0]
    job.status = JobStatus.APPROVED

    # 3. Execute with mocked boto3
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client

    executor = RemediationExecutor()
    with patch("sentinel_remediation.executor._build_session", return_value=mock_session):
        completed = await executor.execute(job=job, neo4j_client=client)

    # 4. Verify
    assert completed.status == JobStatus.COMPLETED
    assert completed.executed_at is not None
    assert completed.completed_at is not None

    # 5. Node stamped in Neo4j
    records = await client.query(
        "MATCH (n {node_id: $nid}) RETURN n.remediation_job_id AS jid",
        {"nid": node_id},
    )
    assert records[0]["jid"] == completed.job_id
