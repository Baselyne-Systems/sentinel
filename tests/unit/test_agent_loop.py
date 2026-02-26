"""
Unit tests for ``sentinel_agent.agent``.

All tests use a ``MockBackend`` injected directly onto ``agent._backend`` —
no real API calls to Anthropic or OpenAI are made.  The Neo4j client is
also mocked, so these tests run without a database.

Test strategy
-------------
``MockBackend`` replaces the concrete backend.  Its ``stream_turn`` coroutine
yields pre-configured ``TextChunk``/``TurnComplete`` events just like a real
backend would.

Two backend configurations are used:

``_make_backend(tool_round=False)``
    Single turn: yields text then ``TurnComplete(stop_reason="end_turn")``.

``_make_backend(tool_round=True)``
    First turn: yields text then ``TurnComplete(stop_reason="tool_use")``
    with a ``get_resource`` tool call.
    Second turn: yields XML text then ``TurnComplete(stop_reason="end_turn")``.

``TestParseAnalysisXML``
    Pure function tests for ``_parse_analysis_xml()``.

``TestAnalyzeFinding``
    Integration tests for the full ``analyze_finding()`` async generator.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sentinel_agent.agent import AgentSettings, SentinelAgent, _parse_analysis_xml
from sentinel_agent.backends.base import TextChunk, ToolCallChunk, TurnComplete
from sentinel_agent.models import AnalysisCompleteEvent, ErrorEvent, TextDeltaEvent, ToolUseEvent

# ── XML parsing tests ──────────────────────────────────────────────────────────


SAMPLE_XML = """
Some reasoning text here.

<analysis>
  <risk_narrative>
    This S3 bucket is publicly accessible and contains sensitive data.
    An attacker with internet access can download all objects without authentication.
  </risk_narrative>
  <priority_score>9</priority_score>
  <priority_rationale>Publicly accessible S3 bucket with no encryption — critical exposure.</priority_rationale>
  <remediation_steps>
    <step number="1">
      <title>Disable public access</title>
      <description>Enable S3 Block Public Access at the bucket and account level.</description>
      <iac_snippet>```hcl
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls   = true
  block_public_policy = true
}
```</iac_snippet>
    </step>
    <step number="2">
      <title>Enable versioning</title>
      <description>Enable bucket versioning to protect against accidental deletion.</description>
      <iac_snippet></iac_snippet>
    </step>
  </remediation_steps>
  <attack_paths_summary>Direct internet access to S3 objects via public ACL.</attack_paths_summary>
</analysis>
"""


class TestParseAnalysisXML:
    def test_parses_all_fields(self):
        result = _parse_analysis_xml("s3-test", SAMPLE_XML, "claude-opus-4-6")
        assert result is not None
        assert result.node_id == "s3-test"
        assert result.priority_score == 9
        assert "publicly accessible" in result.risk_narrative.lower()
        assert len(result.remediation_steps) == 2
        assert result.remediation_steps[0].step_number == 1
        assert "Disable" in result.remediation_steps[0].title
        assert "aws_s3_bucket_public_access_block" in result.remediation_steps[0].iac_snippet
        assert result.attack_paths_summary != ""
        assert result.model == "claude-opus-4-6"

    def test_priority_score_clamped(self):
        xml = "<analysis><risk_narrative>x</risk_narrative><priority_score>99</priority_score><priority_rationale>x</priority_rationale><remediation_steps></remediation_steps><attack_paths_summary></attack_paths_summary></analysis>"
        result = _parse_analysis_xml("n1", xml, "model")
        assert result is not None
        assert result.priority_score == 10

    def test_returns_none_when_no_analysis_tag(self):
        result = _parse_analysis_xml("n1", "No XML here at all", "model")
        assert result is None

    def test_iac_code_fence_stripped(self):
        result = _parse_analysis_xml("s3-test", SAMPLE_XML, "m")
        assert result is not None
        snippet = result.remediation_steps[0].iac_snippet
        assert not snippet.startswith("```")
        assert not snippet.endswith("```")


# ── MockBackend ────────────────────────────────────────────────────────────────


class MockBackend:
    """
    Minimal LLM backend mock for unit tests.

    Configured at construction time with the event sequences to yield.
    Each element of ``turn_sequences`` is a list of events for one turn.
    """

    def __init__(self, turn_sequences: list[list]) -> None:
        self._turns = turn_sequences
        self._call_count = 0

    async def stream_turn(
        self,
        messages: list[dict[str, Any]],
        system: str,
        max_tokens: int,
        **kwargs: Any,
    ) -> AsyncIterator:
        idx = min(self._call_count, len(self._turns) - 1)
        self._call_count += 1
        for event in self._turns[idx]:
            yield event


def _make_backend(tool_round: bool = False, final_response: str | None = None) -> MockBackend:
    """Build a MockBackend for common test scenarios."""
    final_text = final_response or SAMPLE_XML

    if tool_round:
        tool_turn = [
            TextChunk(text="Analyzing..."),
            TurnComplete(
                text="Analyzing...",
                tool_calls=[
                    ToolCallChunk(id="tu-1", name="get_resource", arguments={"node_id": "s3-test"})
                ],
                stop_reason="tool_use",
            ),
        ]
        end_turn = [
            TextChunk(text=final_text),
            TurnComplete(text=final_text, tool_calls=[], stop_reason="end_turn"),
        ]
        return MockBackend([tool_turn, end_turn])
    else:
        end_turn = [
            TextChunk(text=final_text),
            TurnComplete(text=final_text, tool_calls=[], stop_reason="end_turn"),
        ]
        return MockBackend([end_turn])


# ── SentinelAgent tests ────────────────────────────────────────────────────────


def _make_agent(backend: MockBackend, neo4j_client: Any) -> SentinelAgent:
    """Create a SentinelAgent with a MockBackend injected."""
    settings = AgentSettings(
        anthropic_api_key="test-key",
        agent_model="claude-opus-4-6",
        agent_max_tokens=4096,
    )
    agent = SentinelAgent(neo4j_client=neo4j_client, settings=settings)
    agent._backend = backend
    return agent


class TestAnalyzeFinding:
    @pytest.mark.asyncio
    async def test_yields_analysis_complete_event(self):
        node_data = {
            "node_id": "s3-test",
            "resource_type": "S3Bucket",
            "posture_flags": ["S3_PUBLIC_ACL"],
            "region": "us-east-1",
            "account_id": "123456789012",
        }
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(), neo4j)

        events = []
        async for e in agent.analyze_finding("s3-test", "123456789012"):
            events.append(e)

        complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]
        assert len(complete_events) == 1
        assert complete_events[0].result.priority_score == 9
        assert complete_events[0].result.node_id == "s3-test"

    @pytest.mark.asyncio
    async def test_yields_error_event_when_node_not_found(self):
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(), neo4j)

        events = []
        async for e in agent.analyze_finding("nonexistent", "123"):
            events.append(e)

        error_events = [e for e in events if isinstance(e, ErrorEvent)]
        assert len(error_events) == 1
        assert "not found" in error_events[0].message

    @pytest.mark.asyncio
    async def test_caches_result_in_neo4j(self):
        node_data = {
            "node_id": "s3-test",
            "resource_type": "S3Bucket",
            "posture_flags": ["S3_PUBLIC_ACL"],
            "region": "us-east-1",
            "account_id": "123456789012",
        }
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(), neo4j)

        async for _ in agent.analyze_finding("s3-test", "123456789012"):
            pass

        neo4j.execute.assert_called_once()
        call_kwargs = neo4j.execute.call_args
        assert "agent_analysis" in str(call_kwargs)

    @pytest.mark.asyncio
    async def test_yields_text_delta_events(self):
        node_data = {
            "node_id": "s3-test",
            "resource_type": "S3Bucket",
            "posture_flags": [],
            "region": "us-east-1",
            "account_id": "123",
        }
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(), neo4j)

        text_events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            if isinstance(e, TextDeltaEvent):
                text_events.append(e)

        assert len(text_events) > 0

    @pytest.mark.asyncio
    async def test_tool_use_round_dispatches_tool(self):
        node_data = {
            "node_id": "s3-test",
            "resource_type": "S3Bucket",
            "posture_flags": ["S3_PUBLIC_ACL"],
            "region": "us-east-1",
            "account_id": "123456789012",
        }
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(tool_round=True), neo4j)

        tool_events = []
        async for e in agent.analyze_finding("s3-test", "123456789012"):
            if isinstance(e, ToolUseEvent):
                tool_events.append(e)

        assert len(tool_events) >= 1
        assert tool_events[0].tool_name == "get_resource"

    @pytest.mark.asyncio
    async def test_fallback_result_when_xml_missing(self):
        node_data = {
            "node_id": "s3-test",
            "resource_type": "S3Bucket",
            "posture_flags": [],
            "region": "us-east-1",
            "account_id": "123",
        }
        neo4j = MagicMock()
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        agent = _make_agent(_make_backend(final_response="No XML in this response at all."), neo4j)

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]
        assert len(complete_events) == 1
        assert complete_events[0].result.node_id == "s3-test"
        assert complete_events[0].result.priority_score == 5  # default fallback
