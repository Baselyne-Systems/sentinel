"""
Unit tests for the extended thinking opt-in mode in SentinelAgent.

Verifies that:
- ``AgentSettings`` exposes ``enable_thinking`` and ``thinking_budget_tokens``.
- When thinking is enabled, the Anthropic API call receives the correct
  ``thinking`` dict and ``betas`` list.
- ``max_tokens`` is automatically raised above ``thinking_budget_tokens``.
- Per-request ``enable_thinking`` kwarg overrides the instance-level default.
- ``ThinkingDeltaEvent`` is yielded for ``thinking_delta`` stream chunks.
- Thinking blocks with their ``signature`` are preserved in the message history
  (required for multi-turn correctness with interleaved thinking).

No real Anthropic API calls or Neo4j connections are made — all dependencies
are mocked.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel_agent.agent import AgentSettings, SentinelAgent
from sentinel_agent.models import (
    AnalysisCompleteEvent,
    TextDeltaEvent,
    ThinkingDeltaEvent,
)

# ── Sample XML that the mock LLM "returns" ─────────────────────────────────────

_XML = """
<analysis>
  <risk_narrative>Public S3 bucket exposes data to the internet.</risk_narrative>
  <priority_score>8</priority_score>
  <priority_rationale>High risk: unprotected data accessible to anyone.</priority_rationale>
  <remediation_steps>
    <step number="1">
      <title>Block public access</title>
      <description>Apply S3 block public access at bucket level.</description>
      <iac_snippet></iac_snippet>
    </step>
  </remediation_steps>
  <attack_paths_summary>Direct internet access via public ACL.</attack_paths_summary>
</analysis>
"""

# ── Stream / message mock builders ─────────────────────────────────────────────


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


def _thinking_block(thinking: str, signature: str = "sig-test") -> MagicMock:
    b = MagicMock()
    b.type = "thinking"
    b.thinking = thinking
    b.signature = signature
    return b


def _build_client(chunks, content_blocks, *, capture: dict | None = None) -> MagicMock:
    """
    Build a mock Anthropic client that streams ``chunks`` and returns a
    final message whose ``.content`` is ``content_blocks``.

    If ``capture`` is provided it will be updated with the kwargs passed
    to ``messages.stream()`` — useful for verifying thinking params.
    """
    client = MagicMock()
    final_msg = MagicMock()
    final_msg.stop_reason = "end_turn"
    final_msg.content = content_blocks

    @asynccontextmanager
    async def _stream_cm(*args, **kwargs):
        if capture is not None:
            capture.update(kwargs)

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


def _neo4j_with_node() -> MagicMock:
    """Mock Neo4jClient that returns a single S3Bucket finding node."""
    neo4j = MagicMock()
    neo4j.query = AsyncMock(
        return_value=[
            {
                "n": {
                    "node_id": "s3-test",
                    "resource_type": "S3Bucket",
                    "posture_flags": ["S3_PUBLIC_ACCESS"],
                    "region": "us-east-1",
                    "account_id": "123",
                }
            }
        ]
    )
    neo4j.execute = AsyncMock()
    return neo4j


# ── AgentSettings field tests ──────────────────────────────────────────────────


class TestAgentSettingsFields:
    def test_enable_thinking_defaults_false(self):
        s = AgentSettings(anthropic_api_key="k")
        assert s.enable_thinking is False

    def test_thinking_budget_tokens_default(self):
        s = AgentSettings(anthropic_api_key="k")
        assert s.thinking_budget_tokens == 8000

    def test_thinking_fields_configurable(self):
        s = AgentSettings(
            anthropic_api_key="k",
            enable_thinking=True,
            thinking_budget_tokens=5000,
        )
        assert s.enable_thinking is True
        assert s.thinking_budget_tokens == 5000


# ── API parameter tests ────────────────────────────────────────────────────────


class TestThinkingApiParams:
    @pytest.mark.asyncio
    async def test_no_thinking_params_when_disabled(self):
        cap: dict = {}
        client = _build_client([_text_chunk(_XML)], [_text_block(_XML)], capture=cap)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._client = client
        async for _ in agent.analyze_finding("s3-test", "123"):
            pass

        assert "thinking" not in cap, "thinking param must not be sent when disabled"
        assert "betas" not in cap, "betas param must not be sent when disabled"

    @pytest.mark.asyncio
    async def test_thinking_param_sent_when_enabled(self):
        cap: dict = {}
        client = _build_client([_text_chunk(_XML)], [_text_block(_XML)], capture=cap)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._client = client
        async for _ in agent.analyze_finding("s3-test", "123"):
            pass

        assert cap.get("thinking") == {"type": "enabled", "budget_tokens": 5000}
        assert "interleaved-thinking-2025-05-14" in cap.get("betas", [])

    @pytest.mark.asyncio
    async def test_max_tokens_raised_above_budget(self):
        """max_tokens must exceed thinking_budget_tokens to avoid API rejection."""
        cap: dict = {}
        client = _build_client([_text_chunk(_XML)], [_text_block(_XML)], capture=cap)
        neo4j = _neo4j_with_node()
        # agent_max_tokens=4096 < budget_tokens=8000 — should be auto-raised
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=8000,
                agent_max_tokens=4096,
            ),
        )
        agent._client = client
        async for _ in agent.analyze_finding("s3-test", "123"):
            pass

        mt = cap.get("max_tokens", 0)
        assert mt > 8000, f"max_tokens={mt} should exceed budget_tokens=8000"

    @pytest.mark.asyncio
    async def test_per_request_override_enables_thinking(self):
        """enable_thinking kwarg on analyze_finding overrides instance default."""
        cap: dict = {}
        client = _build_client([_text_chunk(_XML)], [_text_block(_XML)], capture=cap)
        neo4j = _neo4j_with_node()
        # Instance has thinking DISABLED
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._client = client
        async for _ in agent.analyze_finding("s3-test", "123", enable_thinking=True):
            pass

        assert "thinking" in cap, "thinking should be enabled via per-request kwarg"

    @pytest.mark.asyncio
    async def test_per_request_override_disables_thinking(self):
        """enable_thinking=False kwarg disables thinking even when instance has it on."""
        cap: dict = {}
        client = _build_client([_text_chunk(_XML)], [_text_block(_XML)], capture=cap)
        neo4j = _neo4j_with_node()
        # Instance has thinking ENABLED
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._client = client
        async for _ in agent.analyze_finding("s3-test", "123", enable_thinking=False):
            pass

        assert "thinking" not in cap, "thinking should be disabled via per-request kwarg"


# ── ThinkingDeltaEvent yield tests ─────────────────────────────────────────────


class TestThinkingDeltaEvents:
    @pytest.mark.asyncio
    async def test_thinking_event_yielded(self):
        """ThinkingDeltaEvent is yielded for thinking_delta stream chunks."""
        client = _build_client(
            [_thinking_chunk("reasoning…"), _text_chunk(_XML)],
            [_thinking_block("reasoning…", "s1"), _text_block(_XML)],
        )
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._client = client

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        thinking_events = [e for e in events if isinstance(e, ThinkingDeltaEvent)]
        assert len(thinking_events) > 0
        assert thinking_events[0].thinking == "reasoning…"

    @pytest.mark.asyncio
    async def test_no_thinking_event_when_disabled(self):
        """No ThinkingDeltaEvent when enable_thinking=False."""
        client = _build_client(
            [_thinking_chunk("hidden reasoning"), _text_chunk(_XML)],
            [_text_block(_XML)],
        )
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._client = client

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        thinking_events = [e for e in events if isinstance(e, ThinkingDeltaEvent)]
        assert len(thinking_events) == 0

    def test_thinking_event_sse_format(self):
        """ThinkingDeltaEvent.to_sse() produces a valid SSE data line."""
        event = ThinkingDeltaEvent(thinking="step 1: blast radius")
        sse = event.to_sse()
        assert sse.startswith("data: ")
        assert sse.endswith("\n\n")
        payload = json.loads(sse[6:].strip())
        assert payload["event"] == "thinking_delta"
        assert payload["thinking"] == "step 1: blast radius"

    @pytest.mark.asyncio
    async def test_text_events_still_yielded_alongside_thinking(self):
        """TextDeltaEvent is still emitted even when thinking is enabled."""
        client = _build_client(
            [_thinking_chunk("reasoning"), _text_chunk(_XML)],
            [_thinking_block("reasoning", "sig"), _text_block(_XML)],
        )
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._client = client

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        text_events = [e for e in events if isinstance(e, TextDeltaEvent)]
        thinking_events = [e for e in events if isinstance(e, ThinkingDeltaEvent)]
        complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]

        assert len(text_events) > 0
        assert len(thinking_events) > 0
        assert len(complete_events) == 1


# ── Message history preservation ───────────────────────────────────────────────


class TestThinkingHistoryPreservation:
    @pytest.mark.asyncio
    async def test_thinking_block_and_signature_in_history(self):
        """
        After _run_tool_loop, the assistant message must contain a thinking
        block with the original signature (required for multi-turn correctness).
        """
        # Build a client that returns one thinking block + one text block
        final_msg = MagicMock()
        final_msg.stop_reason = "end_turn"
        final_msg.content = [
            _thinking_block("I analysed the blast radius", "sig-xyz"),
            _text_block(_XML),
        ]

        @asynccontextmanager
        async def _stream(*args, **kwargs):
            class _S:
                def __aiter__(self):
                    return self._iter()

                async def _iter(self):
                    yield _thinking_chunk("I analysed the blast radius")
                    yield _text_chunk(_XML)

                async def get_final_message(self):
                    return final_msg

            yield _S()

        client = MagicMock()
        client.messages.stream = _stream

        neo4j = MagicMock()
        neo4j.execute = AsyncMock()

        settings = AgentSettings(
            anthropic_api_key="k",
            enable_thinking=True,
            thinking_budget_tokens=5000,
        )
        agent = SentinelAgent(neo4j_client=neo4j, settings=settings)
        agent._client = client

        messages: list = [{"role": "user", "content": "analyse this"}]
        async for _ in agent._run_tool_loop(messages, enable_thinking=True):
            pass

        # The assistant turn (index 1) must include the thinking block with signature
        assert len(messages) == 2
        assistant_content = messages[1]["content"]
        thinking_blocks = [b for b in assistant_content if b.get("type") == "thinking"]

        assert len(thinking_blocks) == 1, "Expected exactly one thinking block in history"
        assert thinking_blocks[0]["thinking"] == "I analysed the blast radius"
        assert thinking_blocks[0]["signature"] == "sig-xyz"
