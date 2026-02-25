"""
End-to-end tests for the SENTINEL Phase 2 agent pipeline.

Unlike the unit tests which mock both the Neo4j client and the Anthropic SDK,
these tests use a *real* Neo4j database (via ``testcontainers``) and only mock
the Anthropic SDK.  This validates the full data path from graph write-in
(simulating a scan result) through the agent tool-use loop to the Neo4j
cache write-back.

Infrastructure
--------------
- **Neo4j**: started via the ``neo4j_client`` session-scoped fixture defined in
  ``tests/e2e/conftest.py``.  Requires Docker to be running.
- **Anthropic SDK**: replaced by ``_build_mock_anthropic_client()`` which
  immediately returns ``stop_reason = "end_turn"`` with the sample XML,
  simulating a single-round analysis with no tool calls.
- **``clean_db``** fixture: function-scoped; wipes all nodes before each test
  so tests are fully isolated from each other.

Run these tests with::

    pytest -m e2e tests/e2e/test_agent_e2e.py -v

Pipeline tested
---------------
  1. Write a finding node to Neo4j (simulated scan output)
  2. Run SentinelAgent.analyze_finding()
  3. Verify SSE events are emitted correctly
  4. Verify AnalysisResult is cached on the Neo4j node
  5. Fetch cached result via GET /agent/findings/{node_id}/analysis (API test)
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from sentinel_agent.agent import AgentSettings, SentinelAgent
from sentinel_agent.models import AnalysisCompleteEvent, ErrorEvent, TextDeltaEvent
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.models.nodes import S3Bucket

# ── Anthropic mock helpers (re-used from unit tests) ──────────────────────────

SAMPLE_XML = """
<analysis>
  <risk_narrative>
    This S3 bucket has a public ACL enabling unauthenticated access to all objects.
    Any internet user can list and download bucket contents without credentials.
  </risk_narrative>
  <priority_score>9</priority_score>
  <priority_rationale>Critical: public S3 bucket with sensitive data exposure.</priority_rationale>
  <remediation_steps>
    <step number="1">
      <title>Enable Block Public Access</title>
      <description>Apply S3 Block Public Access settings at bucket and account level.</description>
      <iac_snippet>```hcl
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```</iac_snippet>
    </step>
  </remediation_steps>
  <attack_paths_summary>Direct internet access via public ACL — no authentication required.</attack_paths_summary>
</analysis>
"""


def _make_text_chunk(text: str):
    chunk = MagicMock()
    chunk.type = "content_block_delta"
    chunk.delta = MagicMock()
    chunk.delta.text = text
    return chunk


def _make_text_block(text: str):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _build_mock_anthropic_client():
    """Build a mock Anthropic client that returns end_turn with XML immediately."""
    client = MagicMock()
    end_message = MagicMock()
    end_message.stop_reason = "end_turn"
    end_message.content = [_make_text_block(SAMPLE_XML)]

    @asynccontextmanager
    async def mock_stream_cm(*args, **kwargs):
        class _Stream:
            def __aiter__(self):
                return self._iter()

            async def _iter(self):
                yield _make_text_chunk(SAMPLE_XML)

            async def get_final_message(self):
                return end_message

        yield _Stream()

    client.messages.stream = mock_stream_cm
    return client


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def agent_settings():
    return AgentSettings(
        anthropic_api_key="test-key",
        agent_model="claude-opus-4-6",
        agent_max_tokens=4096,
    )


# ── E2E tests ──────────────────────────────────────────────────────────────────


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_analyze_finding_full_pipeline(clean_db: Neo4jClient, agent_settings):
    """
    Full pipeline: write a node → run agent → verify SSE events → verify cache.
    """
    neo4j = clean_db

    # 1. Write a finding node (simulating a scan)
    bucket = S3Bucket(
        node_id="s3-public-test-bucket",
        account_id="123456789012",
        region="us-east-1",
        bucket_name="public-test-bucket",
        is_public=True,
        versioning_enabled=False,
        encrypted=False,
        posture_flags=["CRITICAL", "S3_PUBLIC_ACL", "S3_NO_VERSIONING"],
    )
    await neo4j.upsert_node(bucket)

    # 2. Create agent with mocked Anthropic
    agent = SentinelAgent(neo4j_client=neo4j, settings=agent_settings)
    agent._client = _build_mock_anthropic_client()

    # 3. Collect all SSE events
    events = []
    async for event in agent.analyze_finding("s3-public-test-bucket", "123456789012"):
        events.append(event)

    # 4. Verify event types
    text_events = [e for e in events if isinstance(e, TextDeltaEvent)]
    complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]
    error_events = [e for e in events if isinstance(e, ErrorEvent)]

    assert len(error_events) == 0, f"Got unexpected error events: {[e.message for e in error_events]}"
    assert len(text_events) > 0, "Expected text_delta events"
    assert len(complete_events) == 1, "Expected exactly one analysis_complete event"

    # 5. Verify AnalysisResult content
    result = complete_events[0].result
    assert result.node_id == "s3-public-test-bucket"
    assert result.priority_score == 9
    assert len(result.remediation_steps) == 1
    assert result.remediation_steps[0].step_number == 1
    assert "aws_s3_bucket_public_access_block" in result.remediation_steps[0].iac_snippet
    assert result.attack_paths_summary != ""

    # 6. Verify cache was written to Neo4j
    cache_result = await neo4j.query(
        "MATCH (n {node_id: $node_id}) RETURN n.agent_analysis AS analysis, n.agent_analyzed_at AS ts",
        {"node_id": "s3-public-test-bucket"},
    )
    assert len(cache_result) == 1
    assert cache_result[0]["analysis"] is not None
    assert cache_result[0]["ts"] is not None

    # 7. Verify cached JSON is parseable back to AnalysisResult
    from sentinel_agent.models import AnalysisResult
    cached = AnalysisResult.model_validate(json.loads(cache_result[0]["analysis"]))
    assert cached.priority_score == 9
    assert cached.node_id == "s3-public-test-bucket"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_analyze_finding_node_not_found(clean_db: Neo4jClient, agent_settings):
    """Agent returns ErrorEvent when the node doesn't exist in graph."""
    neo4j = clean_db
    agent = SentinelAgent(neo4j_client=neo4j, settings=agent_settings)
    agent._client = _build_mock_anthropic_client()

    events = []
    async for event in agent.analyze_finding("does-not-exist", "123"):
        events.append(event)

    error_events = [e for e in events if isinstance(e, ErrorEvent)]
    assert len(error_events) == 1
    assert "not found" in error_events[0].message


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_analyze_finding_sse_wire_format(clean_db: Neo4jClient, agent_settings):
    """Verify SSE serialization produces valid JSON data: lines."""
    neo4j = clean_db

    from sentinel_core.models.nodes import SecurityGroup
    sg = SecurityGroup(
        node_id="sg-e2e-test",
        account_id="123456789012",
        region="us-east-1",
        group_id="sg-123",
        group_name="open-sg",
        vpc_id="vpc-1",
        posture_flags=["CRITICAL", "SG_OPEN_SSH"],
    )
    await neo4j.upsert_node(sg)

    agent = SentinelAgent(neo4j_client=neo4j, settings=agent_settings)
    agent._client = _build_mock_anthropic_client()

    sse_lines = []
    async for event in agent.analyze_finding("sg-e2e-test", "123456789012"):
        sse = event.to_sse()
        assert sse.startswith("data: "), f"SSE must start with 'data: ', got: {sse[:30]}"
        assert sse.endswith("\n\n"), f"SSE must end with double newline"
        payload = json.loads(sse[6:].strip())
        assert "event" in payload
        sse_lines.append(payload)

    event_types = {p["event"] for p in sse_lines}
    assert "text_delta" in event_types
    assert "analysis_complete" in event_types


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_generate_brief_no_findings(clean_db: Neo4jClient, agent_settings):
    """generate_brief yields ErrorEvent when no findings in graph."""
    neo4j = clean_db
    agent = SentinelAgent(neo4j_client=neo4j, settings=agent_settings)
    agent._client = _build_mock_anthropic_client()

    events = []
    async for event in agent.generate_brief("123456789012", top_n=5):
        events.append(event)

    error_events = [e for e in events if isinstance(e, ErrorEvent)]
    assert len(error_events) == 1
    assert "No findings" in error_events[0].message


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_generate_brief_with_findings(clean_db: Neo4jClient, agent_settings):
    """generate_brief emits analysis_complete event when findings exist."""
    neo4j = clean_db

    # Write multiple findings
    bucket = S3Bucket(
        node_id="s3-brief-test",
        account_id="999999999999",
        region="us-east-1",
        bucket_name="brief-test",
        is_public=True,
        posture_flags=["CRITICAL", "S3_PUBLIC_ACL"],
    )
    await neo4j.upsert_node(bucket)

    agent = SentinelAgent(neo4j_client=neo4j, settings=agent_settings)
    agent._client = _build_mock_anthropic_client()

    events = []
    async for event in agent.generate_brief("999999999999", top_n=5):
        events.append(event)

    complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]
    error_events = [e for e in events if isinstance(e, ErrorEvent)]

    assert len(error_events) == 0
    assert len(complete_events) == 1
