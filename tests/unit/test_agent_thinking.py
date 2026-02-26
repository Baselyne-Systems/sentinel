"""
Unit tests for extended thinking support in SentinelAgent.

Verifies that:
- ``AgentSettings`` exposes ``enable_thinking``, ``thinking_budget_tokens``,
  ``provider``, ``openai_api_key``, and ``openai_base_url`` fields.
- When ``enable_thinking=True`` is passed to ``stream_turn``, the backend
  receives the flag.
- Per-request ``enable_thinking`` kwarg on ``analyze_finding`` overrides the
  instance-level default.
- ``ThinkingDeltaEvent`` is yielded when the backend emits ``ThinkingChunk``.

No real API calls or Neo4j connections are made — all dependencies mocked.
Anthropic-specific backend behavior (thinking dict format, betas, max_tokens
calculation) is tested separately in ``test_backends.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sentinel_agent.agent import AgentSettings, SentinelAgent
from sentinel_agent.backends.base import TextChunk, ThinkingChunk, TurnComplete
from sentinel_agent.models import (
    AnalysisCompleteEvent,
    TextDeltaEvent,
    ThinkingDeltaEvent,
)

# ── Sample XML ─────────────────────────────────────────────────────────────────

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


# ── CapturingMockBackend ───────────────────────────────────────────────────────


class CapturingMockBackend:
    """
    MockBackend that records what kwargs were passed to ``stream_turn``.

    Used to verify that the agent passes ``enable_thinking`` and
    ``thinking_budget_tokens`` through correctly.

    If ``yield_thinking=True``, also emits a ``ThinkingChunk`` before the text.
    """

    def __init__(self, *, yield_thinking: bool = False) -> None:
        self.captured_kwargs: dict[str, Any] = {}
        self._yield_thinking = yield_thinking

    async def stream_turn(
        self,
        messages: list[dict[str, Any]],
        system: str,
        max_tokens: int,
        enable_thinking: bool = False,
        thinking_budget_tokens: int = 8000,
    ) -> AsyncIterator:
        self.captured_kwargs = {
            "enable_thinking": enable_thinking,
            "thinking_budget_tokens": thinking_budget_tokens,
            "max_tokens": max_tokens,
        }
        if self._yield_thinking:
            yield ThinkingChunk(thinking="Let me check...")
        yield TextChunk(text=_XML)
        yield TurnComplete(text=_XML, tool_calls=[], stop_reason="end_turn")


def _neo4j_with_node() -> MagicMock:
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

    def test_provider_defaults_anthropic(self):
        s = AgentSettings(anthropic_api_key="k")
        assert s.provider == "anthropic"

    def test_openai_fields_configurable(self):
        s = AgentSettings(
            anthropic_api_key="",
            provider="openai",
            openai_api_key="sk-test",
            openai_base_url="http://localhost:11434/v1",
        )
        assert s.provider == "openai"
        assert s.openai_api_key == "sk-test"
        assert s.openai_base_url == "http://localhost:11434/v1"


# ── Backend kwargs pass-through tests ─────────────────────────────────────────


class TestThinkingApiParams:
    @pytest.mark.asyncio
    async def test_no_thinking_flag_when_disabled(self):
        backend = CapturingMockBackend()
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._backend = backend
        async for _ in agent.analyze_finding("s3-test", "123"):
            pass

        assert backend.captured_kwargs["enable_thinking"] is False

    @pytest.mark.asyncio
    async def test_thinking_flag_sent_when_enabled(self):
        backend = CapturingMockBackend()
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._backend = backend
        async for _ in agent.analyze_finding("s3-test", "123"):
            pass

        assert backend.captured_kwargs["enable_thinking"] is True
        assert backend.captured_kwargs["thinking_budget_tokens"] == 5000

    @pytest.mark.asyncio
    async def test_per_request_override_enables_thinking(self):
        """enable_thinking kwarg on analyze_finding overrides the instance default."""
        backend = CapturingMockBackend()
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._backend = backend
        async for _ in agent.analyze_finding("s3-test", "123", enable_thinking=True):
            pass

        assert backend.captured_kwargs["enable_thinking"] is True

    @pytest.mark.asyncio
    async def test_per_request_override_disables_thinking(self):
        """enable_thinking=False kwarg disables thinking even when instance has it on."""
        backend = CapturingMockBackend()
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._backend = backend
        async for _ in agent.analyze_finding("s3-test", "123", enable_thinking=False):
            pass

        assert backend.captured_kwargs["enable_thinking"] is False


# ── ThinkingDeltaEvent yield tests ─────────────────────────────────────────────


class TestThinkingDeltaEvents:
    @pytest.mark.asyncio
    async def test_thinking_event_yielded(self):
        """ThinkingDeltaEvent is yielded when the backend emits ThinkingChunk."""
        backend = CapturingMockBackend(yield_thinking=True)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._backend = backend

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        thinking_events = [e for e in events if isinstance(e, ThinkingDeltaEvent)]
        assert len(thinking_events) > 0
        assert thinking_events[0].thinking == "Let me check..."

    @pytest.mark.asyncio
    async def test_no_thinking_event_when_backend_doesnt_emit(self):
        """No ThinkingDeltaEvent when the backend doesn't emit ThinkingChunk."""
        backend = CapturingMockBackend(yield_thinking=False)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(anthropic_api_key="k", enable_thinking=False),
        )
        agent._backend = backend

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
        """TextDeltaEvent is still emitted even when thinking chunks are yielded."""
        backend = CapturingMockBackend(yield_thinking=True)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._backend = backend

        events = []
        async for e in agent.analyze_finding("s3-test", "123"):
            events.append(e)

        text_events = [e for e in events if isinstance(e, TextDeltaEvent)]
        thinking_events = [e for e in events if isinstance(e, ThinkingDeltaEvent)]
        complete_events = [e for e in events if isinstance(e, AnalysisCompleteEvent)]

        assert len(text_events) > 0
        assert len(thinking_events) > 0
        assert len(complete_events) == 1


# ── Loop behavior with thinking backend ────────────────────────────────────────


class TestThinkingLoopBehavior:
    @pytest.mark.asyncio
    async def test_analysis_completes_with_thinking_backend(self):
        """
        When the backend yields ThinkingChunk + TextChunk + TurnComplete,
        the agent loop completes and emits AnalysisCompleteEvent.
        """
        backend = CapturingMockBackend(yield_thinking=True)
        neo4j = _neo4j_with_node()
        agent = SentinelAgent(
            neo4j_client=neo4j,
            settings=AgentSettings(
                anthropic_api_key="k",
                enable_thinking=True,
                thinking_budget_tokens=5000,
            ),
        )
        agent._backend = backend

        messages: list = [{"role": "user", "content": "analyse this"}]
        loop_events = []
        async for e in agent._run_tool_loop(messages, enable_thinking=True):
            loop_events.append(e)

        # Loop should yield TextDeltaEvent and ThinkingDeltaEvent
        assert any(isinstance(e, TextDeltaEvent) for e in loop_events)
        assert any(isinstance(e, ThinkingDeltaEvent) for e in loop_events)
