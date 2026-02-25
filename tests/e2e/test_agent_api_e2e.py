"""
E2E tests for the agent HTTP API layer.

Exercises the three agent endpoints through the actual FastAPI router against
a real Neo4j testcontainer.  The Anthropic SDK is mocked so no real API key
is required.

Endpoints covered
-----------------
``POST /api/v1/agent/findings/{node_id}/analyze``
    - Returns an SSE stream with text_delta, analysis_complete events.
    - ``?thinking=true`` additionally emits thinking_delta events.
    - Returns HTTP 404 for an unknown node.

``GET /api/v1/agent/findings/{node_id}/analysis``
    - Returns cached AnalysisResult after analyze has run.
    - Returns HTTP 404 before analyze has run.

``POST /api/v1/agent/brief``
    - Returns an SSE stream with analysis_complete event.
    - Returns HTTP 404 when no findings in graph.

Strategy
--------
- Session-scoped Neo4j container (shared with other E2E tests).
- Mock Anthropic client injected via FastAPI dependency override so the
  agent produces a deterministic XML analysis.
- SSE responses are parsed with ``_collect_sse_events()``.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from sentinel_agent.agent import AgentSettings, SentinelAgent
from sentinel_api.deps import get_sentinel_agent, set_neo4j_client
from sentinel_api.main import create_app
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.models.nodes import S3Bucket, SecurityGroup

# ── Shared sample analysis XML ─────────────────────────────────────────────────

SAMPLE_XML = """
<analysis>
  <risk_narrative>
    This S3 bucket is publicly accessible, exposing all objects to the internet.
    An attacker can list and download all stored data without credentials.
  </risk_narrative>
  <priority_score>9</priority_score>
  <priority_rationale>Critical: public bucket with unencrypted sensitive data.</priority_rationale>
  <remediation_steps>
    <step number="1">
      <title>Enable Block Public Access</title>
      <description>Apply S3 Block Public Access at bucket and account level.</description>
      <iac_snippet>```hcl
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id
  block_public_acls = true
}
```</iac_snippet>
    </step>
  </remediation_steps>
  <attack_paths_summary>Direct internet access via public ACL — no authentication needed.</attack_paths_summary>
</analysis>
"""

THINKING_TEXT = "Let me first look at the blast radius then assess the risk..."

pytestmark = pytest.mark.e2e


# ── Anthropic mock helpers ─────────────────────────────────────────────────────


def _text_chunk(text: str) -> MagicMock:
    c = MagicMock()
    c.type = "content_block_delta"
    c.delta = MagicMock()
    c.delta.type = "text_delta"
    c.delta.text = text
    return c


def _thinking_chunk(text: str) -> MagicMock:
    c = MagicMock()
    c.type = "content_block_delta"
    c.delta = MagicMock()
    c.delta.type = "thinking_delta"
    c.delta.thinking = text
    return c


def _text_block(text: str) -> MagicMock:
    b = MagicMock()
    b.type = "text"
    b.text = text
    return b


def _thinking_block(text: str, sig: str = "sig-test") -> MagicMock:
    b = MagicMock()
    b.type = "thinking"
    b.thinking = text
    b.signature = sig
    return b


def _build_mock_anthropic(*, with_thinking: bool = False) -> MagicMock:
    """
    Build a mock Anthropic client.

    When ``with_thinking=True`` the stream emits a thinking_delta chunk
    before the text chunk and the final message includes a thinking block.
    """
    client = MagicMock()

    if with_thinking:
        chunks = [_thinking_chunk(THINKING_TEXT), _text_chunk(SAMPLE_XML)]
        content = [_thinking_block(THINKING_TEXT, "sig-1"), _text_block(SAMPLE_XML)]
    else:
        chunks = [_text_chunk(SAMPLE_XML)]
        content = [_text_block(SAMPLE_XML)]

    final_msg = MagicMock()
    final_msg.stop_reason = "end_turn"
    final_msg.content = content

    @asynccontextmanager
    async def _stream_cm(*args, **kwargs):
        class _S:
            def __aiter__(self):
                return self._iter()

            async def _iter(self):
                for c in chunks:
                    yield c

            async def get_final_message(self):
                return final_msg

        yield _S()

    client.messages.stream = _stream_cm
    return client


# ── SSE parsing helper ─────────────────────────────────────────────────────────


async def _collect_sse_events(response) -> list[dict[str, Any]]:
    """
    Parse an httpx streaming response body into a list of SSE event dicts.

    Reads ``data: {...}`` lines, skips ``data: [DONE]``, and returns all
    parsed payloads in order.
    """
    events: list[dict[str, Any]] = []
    async for line in response.aiter_lines():
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if raw == "[DONE]":
            break
        try:
            events.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return events


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def app_client(neo4j_client: Neo4jClient):
    """
    AsyncClient backed by real testcontainers Neo4j with mock Anthropic.

    Injects the real Neo4jClient via ``set_neo4j_client``, then overrides
    ``get_sentinel_agent`` to return a SentinelAgent whose Anthropic client
    is mocked — so no API key is required and responses are deterministic.
    """
    set_neo4j_client(neo4j_client)

    def _mock_agent() -> SentinelAgent:
        agent = SentinelAgent(
            neo4j_client=neo4j_client,
            settings=AgentSettings(anthropic_api_key="test-key"),
        )
        agent._client = _build_mock_anthropic()
        return agent

    app = create_app()
    app.dependency_overrides[get_sentinel_agent] = _mock_agent

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture()
async def app_client_thinking(neo4j_client: Neo4jClient):
    """Like ``app_client`` but the mock Anthropic emits thinking chunks."""
    set_neo4j_client(neo4j_client)

    def _mock_agent() -> SentinelAgent:
        agent = SentinelAgent(
            neo4j_client=neo4j_client,
            settings=AgentSettings(anthropic_api_key="test-key"),
        )
        agent._client = _build_mock_anthropic(with_thinking=True)
        return agent

    app = create_app()
    app.dependency_overrides[get_sentinel_agent] = _mock_agent

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture()
async def s3_finding(clean_db: Neo4jClient) -> str:
    """Write a public S3 bucket with posture flags; return its node_id."""
    bucket = S3Bucket(
        node_id="agent-api-s3-test",
        account_id="123456789012",
        region="us-east-1",
        name="agent-api-test-bucket",
        is_public=True,
        versioning=False,
        posture_flags=["S3_PUBLIC_ACCESS", "S3_NO_VERSIONING"],
    )
    await clean_db.upsert_node(bucket)
    return bucket.node_id


@pytest_asyncio.fixture()
async def populated_findings(clean_db: Neo4jClient) -> Neo4jClient:
    """Write two findings so the brief endpoint has data to work with."""
    bucket = S3Bucket(
        node_id="brief-s3-1",
        account_id="brief-account",
        region="us-east-1",
        name="brief-bucket",
        is_public=True,
        posture_flags=["S3_PUBLIC_ACCESS"],
    )
    sg = SecurityGroup(
        node_id="brief-sg-1",
        account_id="brief-account",
        region="us-east-1",
        group_id="sg-brief",
        name="open-sg",
        vpc_id="vpc-1",
        posture_flags=["SG_OPEN_SSH"],
    )
    await clean_db.upsert_node(bucket)
    await clean_db.upsert_node(sg)
    return clean_db


# ── POST /agent/findings/{node_id}/analyze ─────────────────────────────────────


@pytest.mark.timeout(60)
async def test_analyze_endpoint_returns_sse_stream(app_client, s3_finding):
    """
    POST /analyze streams SSE events ending with analysis_complete.
    """
    async with app_client.stream(
        "POST", f"/api/v1/agent/findings/{s3_finding}/analyze"
    ) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        events = await _collect_sse_events(response)

    event_types = {e["event"] for e in events}
    assert "text_delta" in event_types, "Expected text_delta events"
    assert "analysis_complete" in event_types, "Expected analysis_complete event"

    complete = next(e for e in events if e["event"] == "analysis_complete")
    result = complete["result"]
    assert result["priority_score"] == 9
    assert result["node_id"] == s3_finding
    assert len(result["remediation_steps"]) == 1
    assert result["attack_paths_summary"] != ""


@pytest.mark.timeout(60)
async def test_analyze_endpoint_404_for_unknown_node(app_client, clean_db):
    """POST /analyze returns 404 when the node_id is not in the graph."""
    response = await app_client.post("/api/v1/agent/findings/does-not-exist/analyze")
    assert response.status_code == 404


@pytest.mark.timeout(60)
async def test_analyze_with_thinking_param_emits_thinking_events(
    app_client_thinking, s3_finding
):
    """
    POST /analyze?thinking=true should emit thinking_delta events
    before the analysis_complete event.
    """
    async with app_client_thinking.stream(
        "POST", f"/api/v1/agent/findings/{s3_finding}/analyze?thinking=true"
    ) as response:
        assert response.status_code == 200
        events = await _collect_sse_events(response)

    event_types = {e["event"] for e in events}
    assert "thinking_delta" in event_types, "Expected thinking_delta events with ?thinking=true"
    assert "analysis_complete" in event_types

    thinking_events = [e for e in events if e["event"] == "thinking_delta"]
    combined_thinking = "".join(e["thinking"] for e in thinking_events)
    assert len(combined_thinking) > 0


# ── GET /agent/findings/{node_id}/analysis ────────────────────────────────────


@pytest.mark.timeout(60)
async def test_get_cached_analysis_404_before_analyze(app_client, s3_finding):
    """GET /analysis returns 404 when no analysis has been run yet."""
    response = await app_client.get(f"/api/v1/agent/findings/{s3_finding}/analysis")
    assert response.status_code == 404


@pytest.mark.timeout(60)
async def test_get_cached_analysis_after_analyze(app_client, s3_finding):
    """
    After running POST /analyze, GET /analysis returns the cached result.
    """
    # Run the analysis (consume the full stream)
    async with app_client.stream(
        "POST", f"/api/v1/agent/findings/{s3_finding}/analyze"
    ) as resp:
        await _collect_sse_events(resp)

    # Now the cache should be populated
    response = await app_client.get(f"/api/v1/agent/findings/{s3_finding}/analysis")
    assert response.status_code == 200

    data = response.json()
    assert data["node_id"] == s3_finding
    assert data["priority_score"] == 9
    assert isinstance(data["remediation_steps"], list)
    assert len(data["remediation_steps"]) >= 1


# ── POST /agent/brief ──────────────────────────────────────────────────────────


@pytest.mark.timeout(60)
async def test_brief_endpoint_404_when_no_findings(app_client, clean_db):
    """POST /brief returns 404 when no findings exist in the graph."""
    response = await app_client.post(
        "/api/v1/agent/brief", params={"account_id": "nonexistent-account"}
    )
    assert response.status_code == 404


@pytest.mark.timeout(60)
async def test_brief_endpoint_streams_analysis_complete(app_client, populated_findings):
    """POST /brief returns SSE stream with analysis_complete event."""
    async with app_client.stream(
        "POST", "/api/v1/agent/brief", params={"account_id": "brief-account", "top_n": 2}
    ) as response:
        assert response.status_code == 200
        events = await _collect_sse_events(response)

    event_types = {e["event"] for e in events}
    assert "analysis_complete" in event_types
