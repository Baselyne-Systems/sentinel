"""
E2E tests for the remediation HTTP API.

Exercises the full remediation lifecycle through the FastAPI router against
a real Neo4j testcontainer and mocked boto3 calls.

Lifecycle covered
-----------------
1. ``POST /remediation/propose``    → list of PENDING RemediationJob objects
2. ``GET  /remediation/``           → all jobs listed
3. ``GET  /remediation/{job_id}``   → single job retrieved
4. ``POST /remediation/{job_id}/approve`` → job transitions to COMPLETED
5. ``POST /remediation/{job_id}/reject``  → job transitions to REJECTED
6. 404 / 409 error cases

Strategy
--------
- Session-scoped Neo4j container (shared with other E2E tests).
- boto3 execution is patched at the ``_build_session`` level in the executor
  so no real AWS credentials are needed.
- The in-memory ``_jobs`` dict in the router is cleared before each test
  to prevent cross-test pollution.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from sentinel_api.deps import set_neo4j_client
from sentinel_api.main import create_app
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import S3Bucket

pytestmark = pytest.mark.e2e

ACCOUNT_ID = "123456789012"


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_job_store():
    """Clear the in-memory job store before and after every test."""
    from sentinel_api.routers.remediation import _jobs

    _jobs.clear()
    yield
    _jobs.clear()


@pytest_asyncio.fixture()
async def app_client(neo4j_client: Neo4jClient):
    """AsyncClient backed by real testcontainers Neo4j."""
    set_neo4j_client(neo4j_client)
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest_asyncio.fixture()
async def s3_node(clean_db: Neo4jClient) -> tuple[str, Neo4jClient]:
    """
    Write an S3 bucket with S3_PUBLIC_ACCESS and S3_NO_VERSIONING flags.
    Returns ``(node_id, neo4j_client)``.
    """
    bucket = S3Bucket(
        node_id="rem-api-s3",
        account_id=ACCOUNT_ID,
        region="us-east-1",
        name="rem-api-bucket",
        is_public=True,
        versioning=False,
        posture_flags=[PostureFlag.S3_PUBLIC_ACCESS, PostureFlag.S3_NO_VERSIONING],
    )
    await clean_db.upsert_node(bucket)
    return bucket.node_id, clean_db


# ── POST /remediation/propose ──────────────────────────────────────────────────


@pytest.mark.timeout(60)
async def test_propose_returns_pending_jobs(app_client, s3_node):
    node_id, _ = s3_node
    response = await app_client.post("/api/v1/remediation/propose", json={"node_id": node_id})
    assert response.status_code == 200

    jobs = response.json()
    assert isinstance(jobs, list)
    assert len(jobs) >= 1
    assert all(j["status"] == "pending" for j in jobs)

    actions = {j["proposal"]["action"] for j in jobs}
    assert "s3_block_public_access" in actions
    assert "s3_enable_versioning" in actions


@pytest.mark.timeout(60)
async def test_propose_404_for_unknown_node(app_client, clean_db):
    response = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": "node-does-not-exist"}
    )
    assert response.status_code == 404


@pytest.mark.timeout(60)
async def test_propose_empty_list_for_node_with_no_known_flags(app_client, clean_db):
    """A node with no remediable flags returns an empty list (not an error)."""
    # Write a compliant node with no posture flags
    async def _write():
        bucket = S3Bucket(
            node_id="rem-api-clean",
            account_id=ACCOUNT_ID,
            region="us-east-1",
            name="clean-bucket",
            posture_flags=[],
        )
        await clean_db.upsert_node(bucket)

    await _write()

    response = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": "rem-api-clean"}
    )
    assert response.status_code == 200
    assert response.json() == []


# ── GET /remediation/ and GET /remediation/{job_id} ───────────────────────────


@pytest.mark.timeout(60)
async def test_list_jobs_after_propose(app_client, s3_node):
    node_id, _ = s3_node
    await app_client.post("/api/v1/remediation/propose", json={"node_id": node_id})

    response = await app_client.get("/api/v1/remediation/")
    assert response.status_code == 200
    jobs = response.json()
    assert len(jobs) >= 1


@pytest.mark.timeout(60)
async def test_get_job_by_id(app_client, s3_node):
    node_id, _ = s3_node
    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    job_id = propose_resp.json()[0]["job_id"]

    response = await app_client.get(f"/api/v1/remediation/{job_id}")
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id


@pytest.mark.timeout(60)
async def test_get_job_404_unknown_id(app_client, clean_db):
    response = await app_client.get("/api/v1/remediation/job-does-not-exist")
    assert response.status_code == 404


# ── POST /remediation/{job_id}/reject ─────────────────────────────────────────


@pytest.mark.timeout(60)
async def test_reject_sets_rejected_status(app_client, s3_node):
    node_id, _ = s3_node
    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    job_id = propose_resp.json()[0]["job_id"]

    reject_resp = await app_client.post(f"/api/v1/remediation/{job_id}/reject")
    assert reject_resp.status_code == 200
    data = reject_resp.json()
    assert data["status"] == "rejected"
    assert data["rejected_at"] is not None


@pytest.mark.timeout(60)
async def test_reject_409_on_non_pending_job(app_client, s3_node):
    """Rejecting an already-rejected job returns 409."""
    node_id, _ = s3_node
    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    job_id = propose_resp.json()[0]["job_id"]

    await app_client.post(f"/api/v1/remediation/{job_id}/reject")
    # Second reject on a non-pending job → 409
    second_resp = await app_client.post(f"/api/v1/remediation/{job_id}/reject")
    assert second_resp.status_code == 409


# ── POST /remediation/{job_id}/approve ────────────────────────────────────────


@pytest.mark.timeout(60)
async def test_approve_executes_job_and_completes(app_client, s3_node):
    """
    Approve a pending job; the background task should run synchronously in
    TestClient and complete the job before the response is returned.
    """
    node_id, neo4j = s3_node

    # Propose
    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    jobs_data = propose_resp.json()
    block_job = next(
        j for j in jobs_data if j["proposal"]["action"] == "s3_block_public_access"
    )
    job_id = block_job["job_id"]

    # Build a mock boto3 session that simulates success
    mock_session = MagicMock()
    mock_s3 = MagicMock()
    mock_session.client.return_value = mock_s3

    with patch("sentinel_remediation.executor._build_session", return_value=mock_session):
        approve_resp = await app_client.post(f"/api/v1/remediation/{job_id}/approve")

    assert approve_resp.status_code == 200
    # Status immediately after approve is "approved" (background may still be running)
    assert approve_resp.json()["status"] in ("approved", "executing", "completed")

    # After background task finishes, GET should show completed
    get_resp = await app_client.get(f"/api/v1/remediation/{job_id}")
    final_status = get_resp.json()["status"]
    assert final_status == "completed", f"Expected completed, got {final_status}"

    # Verify boto3 call was made
    mock_s3.put_public_access_block.assert_called_once()


@pytest.mark.timeout(60)
async def test_approve_sets_failed_on_boto3_error(app_client, s3_node):
    """When boto3 raises, the job moves to FAILED status."""
    node_id, _ = s3_node

    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    job_id = propose_resp.json()[0]["job_id"]

    mock_session = MagicMock()
    mock_s3 = MagicMock()
    mock_s3.put_public_access_block.side_effect = Exception("AccessDenied")
    mock_session.client.return_value = mock_s3

    with patch("sentinel_remediation.executor._build_session", return_value=mock_session):
        await app_client.post(f"/api/v1/remediation/{job_id}/approve")

    get_resp = await app_client.get(f"/api/v1/remediation/{job_id}")
    data = get_resp.json()
    assert data["status"] == "failed"
    assert "AccessDenied" in (data["error"] or "")


@pytest.mark.timeout(60)
async def test_approve_409_on_non_pending_job(app_client, s3_node):
    """Approving a rejected job returns 409."""
    node_id, _ = s3_node
    propose_resp = await app_client.post(
        "/api/v1/remediation/propose", json={"node_id": node_id}
    )
    job_id = propose_resp.json()[0]["job_id"]

    await app_client.post(f"/api/v1/remediation/{job_id}/reject")  # reject first
    second_resp = await app_client.post(f"/api/v1/remediation/{job_id}/approve")
    assert second_resp.status_code == 409
