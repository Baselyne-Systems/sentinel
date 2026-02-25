"""
API integration tests using FastAPI TestClient with mocked graph client.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel_api.main import create_app
from sentinel_core.knowledge.rules import ALL_RULES


@pytest.fixture
def mock_neo4j():
    """Mock Neo4j client for API tests."""
    client = AsyncMock()
    client.query = AsyncMock(return_value=[])
    client.execute = AsyncMock()
    client.upsert_node = AsyncMock()
    client.upsert_edge = AsyncMock()
    client.ensure_indexes = AsyncMock()
    client.clear_account = AsyncMock()
    return client


@pytest.fixture
def api_client(mock_neo4j):
    """FastAPI test client with mocked Neo4j."""
    from sentinel_api.deps import set_neo4j_client as _set_client

    # Clear any client injected by e2e tests so the lifespan runs normally
    _set_client(None)  # type: ignore[arg-type]
    app = create_app()

    with patch("sentinel_api.main.Neo4jClient") as MockClient:
        instance = MockClient.return_value
        instance.connect = AsyncMock()
        instance.close = AsyncMock()
        instance.ensure_indexes = AsyncMock()
        instance.query = AsyncMock(return_value=[])
        instance.execute = AsyncMock()
        instance.upsert_node = AsyncMock()
        instance.upsert_edge = AsyncMock()
        instance.clear_account = AsyncMock()

        with patch("sentinel_api.deps.set_neo4j_client"):
            with patch("sentinel_api.deps.get_neo4j_client", return_value=instance):
                with TestClient(app) as client:
                    yield client, instance


def test_health_endpoint(api_client):
    """Health check should return 200."""
    client, _ = api_client
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_posture_rules_endpoint(api_client):
    """GET /api/v1/posture/rules should return all CIS rules."""
    client, _ = api_client
    resp = client.get("/api/v1/posture/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == len(ALL_RULES)

    # Spot-check a rule
    rule_ids = {r["id"] for r in rules}
    assert "CIS-2.1.5" in rule_ids
    assert "CIS-3.1" in rule_ids
    assert "CIS-1.10" in rule_ids


def test_posture_rules_have_required_fields(api_client):
    """Each rule in the API response should have all required fields."""
    client, _ = api_client
    resp = client.get("/api/v1/posture/rules")
    rules = resp.json()

    for rule in rules:
        assert "id" in rule
        assert "title" in rule
        assert "severity" in rule
        assert "resource_types" in rule
        assert "posture_flag" in rule
        assert "remediation_hint" in rule


def test_accounts_register(api_client):
    """POST /api/v1/accounts should register an account."""
    client, _ = api_client
    resp = client.post(
        "/api/v1/accounts",
        json={"account_id": "123456789012", "name": "Test Account", "regions": ["us-east-1"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["account_id"] == "123456789012"
    assert data["name"] == "Test Account"


def test_accounts_list(api_client):
    """GET /api/v1/accounts should return registered accounts."""
    client, _ = api_client
    # Register first
    client.post(
        "/api/v1/accounts",
        json={"account_id": "111111111111", "name": "Account 1"},
    )
    resp = client.get("/api/v1/accounts")
    assert resp.status_code == 200
    accounts = resp.json()
    assert isinstance(accounts, list)


def test_accounts_not_found(api_client):
    """GET /api/v1/accounts/{id} for non-existent account should return 404."""
    client, _ = api_client
    resp = client.get("/api/v1/accounts/nonexistent")
    assert resp.status_code == 404


def test_scan_trigger(api_client):
    """POST /api/v1/scan/trigger should return a job_id."""
    client, mock_client = api_client
    resp = client.post(
        "/api/v1/scan/trigger",
        json={"account_id": "123456789012", "regions": ["us-east-1"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "queued"


def test_scan_status_not_found(api_client):
    """GET /api/v1/scan/nonexistent/status should return 404."""
    client, _ = api_client
    resp = client.get("/api/v1/scan/nonexistent-job-id/status")
    assert resp.status_code == 404


def test_graph_raw_cypher_disabled_by_default(api_client):
    """POST /api/v1/graph/query should be disabled unless ENABLE_RAW_CYPHER=true."""
    client, _ = api_client
    resp = client.post(
        "/api/v1/graph/query",
        json={"cypher": "MATCH (n) RETURN n LIMIT 1"},
    )
    assert resp.status_code == 403


def test_posture_summary(api_client):
    """GET /api/v1/posture/summary should return summary structure."""
    client, mock_client = api_client
    mock_client.query = AsyncMock(
        return_value=[
            {
                "total_nodes": 10,
                "critical_count": 2,
                "high_count": 3,
                "medium_count": 1,
                "low_count": 0,
            }
        ]
    )
    resp = client.get("/api/v1/posture/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_nodes" in data
    assert "findings_by_severity" in data
    assert "alignment_percentage" in data
