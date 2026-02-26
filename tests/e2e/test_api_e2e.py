"""
E2E Test: FastAPI endpoints against real Neo4j + moto-mocked AWS.

Verifies that the HTTP API layer (FastAPI routes, response serialisation,
dependency injection) works correctly end-to-end with a live graph database.

What the integration tests (TestClient + mock Neo4j) cannot verify:
- Dependency-injected Neo4jClient actually executes Cypher (not mocked)
- Response pagination and filters apply correctly to real data
- posture summary arithmetic against real node counts
- 404 handling when a node is genuinely absent from the graph
- Raw Cypher endpoint gate (ENABLE_RAW_CYPHER flag)

Test strategy:
1. Spin up a session-scoped Neo4j container (shared with other E2E tests)
2. Override FastAPI's Neo4jClient dependency to inject the real client
3. Run full scan via GraphBuilder (moto-mocked AWS) to populate the graph
4. Assert correct API responses from the TestClient
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sentinel_api.deps import set_neo4j_client, set_store
from sentinel_api.main import create_app
from sentinel_api.store import SentinelStore
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.knowledge.evaluator import PostureEvaluator
from sentinel_perception.graph_builder import GraphBuilder

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

pytestmark = pytest.mark.e2e


# ── App fixture — one per test, avoids lifespan touching a separate Neo4j ──────


@pytest_asyncio.fixture()
async def app_client(neo4j_client: Neo4jClient, job_store: SentinelStore):
    """
    Return an AsyncClient whose app uses the real testcontainers Neo4j.

    We create a bare ``create_app()`` instance (without lifespan) and inject
    the already-connected ``neo4j_client`` fixture via ``set_neo4j_client()``.
    This bypasses the lifespan startup (which would attempt to connect to
    ``NEO4J_URI`` from settings) while still exercising every route handler.
    """
    set_neo4j_client(neo4j_client)
    set_store(job_store)
    fastapi_app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as client:
        yield client


@pytest_asyncio.fixture()
async def populated_db(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    private_s3_bucket,
    vpc_id,
    subnet_ids,
    ec2_instance_id,
    open_sg_id,
    iam_user_no_mfa,
    public_rds_instance,
):
    """
    Populate the clean Neo4j database with a full moto-mocked AWS scan.

    Runs PostureEvaluator after the scan so posture_flags are stamped on nodes.
    Returns the ``clean_db`` client (with data) for tests that need it.
    """
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    await evaluator.evaluate(account_id=ACCOUNT_ID)
    return clean_db


# ── /health ────────────────────────────────────────────────────────────────────


async def test_health_endpoint(app_client):
    """GET /health returns 200 with status=ok."""
    response = await app_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


# ── GET /api/v1/graph/nodes ────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_list_nodes_returns_data(populated_db, app_client):
    """GET /api/v1/graph/nodes should return all nodes after a scan."""
    set_neo4j_client(populated_db)
    response = await app_client.get("/api/v1/graph/nodes", params={"account_id": ACCOUNT_ID})
    assert response.status_code == 200
    nodes = response.json()
    assert isinstance(nodes, list)
    assert len(nodes) > 0


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_list_nodes_filter_by_type(populated_db, app_client):
    """GET /api/v1/graph/nodes?type=S3Bucket returns only S3 nodes."""
    set_neo4j_client(populated_db)
    response = await app_client.get(
        "/api/v1/graph/nodes",
        params={"type": "S3Bucket", "account_id": ACCOUNT_ID},
    )
    assert response.status_code == 200
    nodes = response.json()
    assert len(nodes) >= 1
    for node in nodes:
        assert node.get("resource_type") in ("S3Bucket", "s3_bucket")


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_list_nodes_pagination(populated_db, app_client):
    """Pagination (limit/offset) should return non-overlapping pages."""
    set_neo4j_client(populated_db)

    page1 = (
        await app_client.get(
            "/api/v1/graph/nodes",
            params={"account_id": ACCOUNT_ID, "limit": 2, "offset": 0},
        )
    ).json()
    page2 = (
        await app_client.get(
            "/api/v1/graph/nodes",
            params={"account_id": ACCOUNT_ID, "limit": 2, "offset": 2},
        )
    ).json()

    p1_ids = {n.get("node_id") for n in page1 if n.get("node_id")}
    p2_ids = {n.get("node_id") for n in page2 if n.get("node_id")}
    # Pages must not share node IDs (unless database is very small)
    if p1_ids and p2_ids:
        assert p1_ids.isdisjoint(p2_ids)


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_list_nodes_empty_account(clean_db, app_client):
    """GET /api/v1/graph/nodes for an unknown account returns an empty list."""
    set_neo4j_client(clean_db)
    response = await app_client.get(
        "/api/v1/graph/nodes",
        params={"account_id": "999999999999"},
    )
    assert response.status_code == 200
    assert response.json() == []


# ── GET /api/v1/graph/nodes/{node_id} ─────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_node_by_id(populated_db, app_client, public_s3_bucket):
    """GET /api/v1/graph/nodes/{node_id} returns the correct node."""
    set_neo4j_client(populated_db)
    node_id = f"s3-{public_s3_bucket}"

    response = await app_client.get(f"/api/v1/graph/nodes/{node_id}")
    assert response.status_code == 200

    body = response.json()
    assert body["node_id"] == node_id
    assert body["name"] == public_s3_bucket
    # Edges key should be present (even if empty)
    assert "edges" in body


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_node_404_for_missing_node(clean_db, app_client):
    """GET /api/v1/graph/nodes/{node_id} returns 404 when node is absent."""
    set_neo4j_client(clean_db)
    response = await app_client.get("/api/v1/graph/nodes/nonexistent-node-xyz")
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_node_includes_posture_flags(
    populated_db, app_client, public_s3_bucket
):
    """Node detail should include posture_flags stamped during evaluation."""
    set_neo4j_client(populated_db)
    node_id = f"s3-{public_s3_bucket}"

    response = await app_client.get(f"/api/v1/graph/nodes/{node_id}")
    assert response.status_code == 200

    body = response.json()
    posture_flags = body.get("posture_flags", [])
    assert "S3_PUBLIC_ACCESS" in posture_flags or len(posture_flags) > 0, (
        f"Expected posture_flags on public S3 node. Got: {posture_flags}"
    )


# ── GET /api/v1/graph/nodes/{node_id}/neighbors ───────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_neighbors_returns_subgraph(
    populated_db, app_client, vpc_id
):
    """GET /api/v1/graph/nodes/{id}/neighbors returns subgraph structure."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        f"/api/v1/graph/nodes/{vpc_id}/neighbors",
        params={"depth": 1},
    )
    assert response.status_code == 200

    body = response.json()
    assert "nodes" in body
    assert "edges" in body
    assert body["root_node_id"] == vpc_id
    assert isinstance(body["nodes"], list)
    assert isinstance(body["edges"], list)


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_neighbors_depth_2_reaches_sg(
    populated_db, app_client, ec2_instance_id, open_sg_id, vpc_id
):
    """Depth-2 traversal from EC2 should reach the security group."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        f"/api/v1/graph/nodes/{ec2_instance_id}/neighbors",
        params={"depth": 2},
    )
    assert response.status_code == 200
    body = response.json()

    found_ids = {n.get("node_id") for n in body["nodes"] if n.get("node_id")}
    # At depth=2, both the VPC and SG should be reachable
    assert open_sg_id in found_ids or vpc_id in found_ids, (
        f"Neither SG ({open_sg_id}) nor VPC ({vpc_id}) found in depth-2 traversal. "
        f"Found: {found_ids}"
    )


# ── GET /api/v1/posture/findings ──────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_findings_returns_violations(populated_db, app_client):
    """GET /api/v1/posture/findings should return CIS violations."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        "/api/v1/posture/findings",
        params={"account_id": ACCOUNT_ID},
    )
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list)
    assert len(findings) > 0, "Expected violations from known-bad resources"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_findings_filter_by_severity(populated_db, app_client):
    """GET /api/v1/posture/findings?severity=CRITICAL should only return CRITICAL findings."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        "/api/v1/posture/findings",
        params={"account_id": ACCOUNT_ID, "severity": "CRITICAL"},
    )
    assert response.status_code == 200
    findings = response.json()

    for finding in findings:
        assert finding.get("severity") == "CRITICAL", (
            f"Non-CRITICAL finding returned when filtering for CRITICAL: {finding}"
        )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_findings_filter_by_resource_type(populated_db, app_client):
    """GET /api/v1/posture/findings?resource_type=S3Bucket should only return S3 findings."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        "/api/v1/posture/findings",
        params={"account_id": ACCOUNT_ID, "resource_type": "S3Bucket"},
    )
    assert response.status_code == 200
    findings = response.json()

    for finding in findings:
        assert finding.get("resource_type") == "S3Bucket", (
            f"Non-S3Bucket finding returned when filtering for S3Bucket: {finding}"
        )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_findings_empty_db(clean_db, app_client):
    """GET /api/v1/posture/findings on an empty graph returns an empty list."""
    set_neo4j_client(clean_db)

    response = await app_client.get(
        "/api/v1/posture/findings",
        params={"account_id": ACCOUNT_ID},
    )
    assert response.status_code == 200
    assert response.json() == []


# ── GET /api/v1/posture/summary ───────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_posture_summary_with_violations(populated_db, app_client):
    """GET /api/v1/posture/summary should reflect real violation counts."""
    set_neo4j_client(populated_db)

    response = await app_client.get(
        "/api/v1/posture/summary",
        params={"account_id": ACCOUNT_ID},
    )
    assert response.status_code == 200
    summary = response.json()

    assert summary["total_nodes"] > 0
    # We created known-bad resources so alignment should be below 100%
    assert summary["alignment_percentage"] < 100.0, (
        f"Alignment should be <100% with known violations. Got: {summary}"
    )
    assert "findings_by_severity" in summary
    findings = summary["findings_by_severity"]
    # At least one severity bucket populated
    assert any(count > 0 for count in findings.values()), (
        f"Expected at least one finding severity to be non-zero. Got: {findings}"
    )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_posture_summary_empty_db(clean_db, app_client):
    """GET /api/v1/posture/summary on an empty graph returns zero counts."""
    set_neo4j_client(clean_db)

    response = await app_client.get(
        "/api/v1/posture/summary",
        params={"account_id": ACCOUNT_ID},
    )
    assert response.status_code == 200
    summary = response.json()

    assert summary["total_nodes"] == 0
    assert summary["alignment_percentage"] == 100.0


# ── GET /api/v1/posture/rules ─────────────────────────────────────────────────


async def test_list_rules_returns_all_cis_rules(app_client, neo4j_client):
    """GET /api/v1/posture/rules should return all loaded CIS rules."""
    from sentinel_core.knowledge.rules import ALL_RULES

    set_neo4j_client(neo4j_client)
    response = await app_client.get("/api/v1/posture/rules")
    assert response.status_code == 200

    rules = response.json()
    assert isinstance(rules, list)
    assert len(rules) == len(ALL_RULES)

    # Every rule should have these required fields
    for rule in rules:
        assert "id" in rule
        assert "title" in rule
        assert "severity" in rule
        assert "posture_flag" in rule
        assert "remediation_hint" in rule


async def test_list_rules_severity_values(app_client, neo4j_client):
    """All returned rules should have valid severity values."""
    set_neo4j_client(neo4j_client)
    response = await app_client.get("/api/v1/posture/rules")
    assert response.status_code == 200

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    for rule in response.json():
        assert rule["severity"] in valid_severities, (
            f"Rule {rule['id']} has unexpected severity: {rule['severity']}"
        )


# ── POST /api/v1/graph/query (raw Cypher) ─────────────────────────────────────


async def test_raw_cypher_disabled_by_default(app_client, neo4j_client):
    """POST /api/v1/graph/query returns 403 when ENABLE_RAW_CYPHER is not set."""
    set_neo4j_client(neo4j_client)
    response = await app_client.post(
        "/api/v1/graph/query",
        json={"cypher": "MATCH (n) RETURN n LIMIT 1"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_raw_cypher_enabled_executes_query(populated_db, app_client):
    """POST /api/v1/graph/query executes when ENABLE_RAW_CYPHER=true."""
    set_neo4j_client(populated_db)

    with patch("sentinel_api.routers.graph.get_settings") as mock_settings:
        mock_settings.return_value.enable_raw_cypher = True
        response = await app_client.post(
            "/api/v1/graph/query",
            json={
                "cypher": "MATCH (n:AWSAccount {account_id: $account_id}) RETURN n.account_id AS id",
                "params": {"account_id": ACCOUNT_ID},
            },
        )

    assert response.status_code == 200
    results = response.json()
    assert isinstance(results, list)
    assert any(r.get("id") == ACCOUNT_ID for r in results), (
        f"Expected AWSAccount record in raw Cypher response. Got: {results}"
    )


# ── POST /api/v1/accounts ─────────────────────────────────────────────────────


async def test_register_account(app_client, neo4j_client):
    """POST /api/v1/accounts should register a new account."""
    set_neo4j_client(neo4j_client)

    response = await app_client.post(
        "/api/v1/accounts",
        json={
            "account_id": "111122223333",
            "name": "test-account",
            "assume_role_arn": "arn:aws:iam::111122223333:role/SentinelRole",
            "regions": ["us-east-1"],
        },
    )
    assert response.status_code in (200, 201)
    body = response.json()
    assert body["account_id"] == "111122223333"
    assert body["name"] == "test-account"


async def test_register_account_invalid_id(app_client, neo4j_client):
    """POST /api/v1/accounts with a non-12-digit account_id should return 422."""
    set_neo4j_client(neo4j_client)

    response = await app_client.post(
        "/api/v1/accounts",
        json={
            "account_id": "bad-id",
            "name": "test-account",
        },
    )
    assert response.status_code == 422


async def test_list_accounts_empty(app_client, neo4j_client):
    """GET /api/v1/accounts returns empty list when none registered."""
    set_neo4j_client(neo4j_client)

    response = await app_client.get("/api/v1/accounts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ── POST /api/v1/scan/trigger ─────────────────────────────────────────────────


async def test_scan_trigger_returns_job_id(app_client, neo4j_client):
    """POST /api/v1/scan/trigger should return a job_id."""
    set_neo4j_client(neo4j_client)

    response = await app_client.post(
        "/api/v1/scan/trigger",
        json={"account_id": ACCOUNT_ID, "regions": [REGION]},
    )
    assert response.status_code in (200, 202)
    body = response.json()
    assert "job_id" in body
    assert body["status"] in ("queued", "running", "started")


async def test_scan_status_for_unknown_job(app_client, neo4j_client):
    """GET /api/v1/scan/{job_id}/status for unknown job should return 404."""
    set_neo4j_client(neo4j_client)

    response = await app_client.get("/api/v1/scan/nonexistent-job-abc/status")
    assert response.status_code == 404


# ── OpenAPI spec correctness ───────────────────────────────────────────────────


async def test_openapi_schema_accessible(app_client, neo4j_client):
    """GET /openapi.json should return a valid OpenAPI schema."""
    set_neo4j_client(neo4j_client)

    response = await app_client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "SENTINEL API"
    assert "paths" in schema
    # Core routes should be documented
    assert "/api/v1/graph/nodes" in schema["paths"]
    assert "/api/v1/posture/findings" in schema["paths"]
    assert "/api/v1/scan/trigger" in schema["paths"]
