"""
Unit tests for ``sentinel_agent.agent``.

All tests mock the Anthropic SDK completely — no real API calls are made.
The Neo4j client is also mocked, so these tests run without a database.

Test strategy
-------------
The Anthropic streaming API is mocked at the ``client.messages.stream``
context-manager level.  Each mock stream yields ``content_block_delta``
chunks carrying the text to deliver, then returns a pre-built ``final_message``
object whose ``stop_reason`` and ``content`` attributes control the loop flow.

Two stream-mock configurations are used:

``_build_mock_anthropic(tool_round_response=None)``
    With ``tool_round_response=True`` (default ``False``):
    - First stream call: returns ``stop_reason = "tool_use"`` with one
      ``get_resource`` tool block, simulating a mid-analysis tool call.
    - Second stream call: returns ``stop_reason = "end_turn"`` with the
      sample XML response, simulating the final answer.

    With ``tool_round_response=False``:
    - Single stream call returns ``stop_reason = "end_turn"`` immediately.

``TestParseAnalysisXML``
    Pure function tests for ``_parse_analysis_xml()``.  Verifies field
    extraction, priority score clamping, code-fence stripping from IaC
    snippets, and graceful ``None`` return on missing ``<analysis>`` block.

``TestAnalyzeFinding``
    Integration tests for the full ``analyze_finding()`` async generator:

    - Correct event sequence (text_delta → analysis_complete).
    - ``ErrorEvent`` on missing node.
    - Neo4j ``execute()`` called with caching Cypher after completion.
    - ``TextDeltaEvent`` objects are yielded during streaming.
    - ``ToolUseEvent`` objects are yielded when a tool round fires.
    - Fallback ``AnalysisResult`` (score=5) when XML is absent.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from sentinel_agent.agent import AgentSettings, SentinelAgent, _parse_analysis_xml
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


# ── Mock Anthropic streaming helper ───────────────────────────────────────────


def _make_text_chunk(text: str):
    chunk = MagicMock()
    chunk.type = "content_block_delta"
    chunk.delta = MagicMock()
    chunk.delta.type = "text_delta"
    chunk.delta.text = text
    return chunk


def _make_tool_use_block(tool_id: str, name: str, input_dict: dict):
    block = MagicMock()
    block.type = "tool_use"
    block.id = tool_id
    block.name = name
    block.input = input_dict
    return block


def _make_text_block(text: str):
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


class MockStream:
    """Simulates an async context manager stream from the Anthropic SDK."""

    def __init__(self, chunks, final_message):
        self._chunks = chunks
        self._final_message = final_message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        for chunk in self._chunks:
            yield chunk

    async def get_final_message(self):
        return self._final_message


def _build_mock_anthropic(tool_round_response=None, final_response=None):
    """
    Build a mock Anthropic client.

    - First call: tool_use round (if tool_round_response provided)
    - Second call (or first if no tool): end_turn with XML
    """
    client = MagicMock()

    final_text = final_response or SAMPLE_XML

    if tool_round_response:
        # First call: tool_use stop
        tool_message = MagicMock()
        tool_message.stop_reason = "tool_use"
        tool_message.content = [
            _make_tool_use_block("tu-1", "get_resource", {"node_id": "s3-test"}),
        ]

        # Second call: end_turn with XML
        end_message = MagicMock()
        end_message.stop_reason = "end_turn"
        end_message.content = [_make_text_block(final_text)]

        streams = [
            MockStream(
                chunks=[_make_text_chunk("Analyzing...")],
                final_message=tool_message,
            ),
            MockStream(
                chunks=[_make_text_chunk(final_text)],
                final_message=end_message,
            ),
        ]
        call_count = [0]

        @asynccontextmanager
        async def mock_stream_cm(*args, **kwargs):
            i = call_count[0]
            call_count[0] += 1
            stream = streams[min(i, len(streams) - 1)]
            yield stream

        client.messages.stream = mock_stream_cm
    else:
        # Single call: end_turn with XML
        end_message = MagicMock()
        end_message.stop_reason = "end_turn"
        end_message.content = [_make_text_block(final_text)]

        @asynccontextmanager
        async def mock_stream_cm(*args, **kwargs):
            yield MockStream(chunks=[_make_text_chunk(final_text)], final_message=end_message)

        client.messages.stream = mock_stream_cm

    return client


# ── SentinelAgent tests ────────────────────────────────────────────────────────


def _make_agent(anthropic_client, neo4j_client):
    """Create a SentinelAgent with mocked dependencies."""
    settings = AgentSettings(
        anthropic_api_key="test-key",
        agent_model="claude-opus-4-6",
        agent_max_tokens=4096,
    )
    agent = SentinelAgent(neo4j_client=neo4j_client, settings=settings)
    agent._client = anthropic_client
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

        ant_client = _build_mock_anthropic()
        agent = _make_agent(ant_client, neo4j)

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

        ant_client = _build_mock_anthropic()
        agent = _make_agent(ant_client, neo4j)

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

        ant_client = _build_mock_anthropic()
        agent = _make_agent(ant_client, neo4j)

        async for _ in agent.analyze_finding("s3-test", "123456789012"):
            pass

        # Verify execute was called with caching cypher
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

        ant_client = _build_mock_anthropic()
        agent = _make_agent(ant_client, neo4j)

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
        # First call: get_resource in analyze_finding
        # Subsequent calls: tool dispatch (get_resource again) + final
        neo4j.query = AsyncMock(return_value=[{"n": node_data}])
        neo4j.execute = AsyncMock()

        ant_client = _build_mock_anthropic(tool_round_response=True)
        agent = _make_agent(ant_client, neo4j)

        tool_events = []
        async for e in agent.analyze_finding("s3-test", "123456789012"):
            if isinstance(e, ToolUseEvent):
                tool_events.append(e)

        # Should have at least 1 ToolUseEvent from the tool_use round
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

        ant_client = _build_mock_anthropic(final_response="No XML in this response at all.")
        agent = _make_agent(ant_client, neo4j)

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]
        assert len(complete_events) == 1
        # Fallback result should still be valid
        assert complete_events[0].result.node_id == "s3-test"
        assert complete_events[0].result.priority_score == 5  # default fallback
