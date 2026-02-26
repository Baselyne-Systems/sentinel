"""
Unit tests for ``sentinel_agent.backends``.

Covers:
- ``to_openai_tools()`` schema translation correctness.
- ``AnthropicBackend._to_anthropic_messages()`` OpenAI → Anthropic format translation.
- Consecutive tool messages merged into a single Anthropic user message.
- ``AnthropicBackend`` thinking block injection into multi-turn messages.
- ``AnthropicBackend`` max_tokens raised above budget when thinking enabled.
- ``AnthropicBackend`` thinking / betas params sent to the Anthropic API.

No real API calls are made — the Anthropic client is patched at the
``anthropic.AsyncAnthropic`` level.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest
from sentinel_agent.backends.anthropic import AnthropicBackend
from sentinel_agent.backends.base import TextChunk, TurnComplete
from sentinel_agent.tools import TOOL_SCHEMAS, to_openai_tools

# ── to_openai_tools ─────────────────────────────────────────────────────────


class TestToOpenAITools:
    def test_converts_all_schemas(self):
        result = to_openai_tools(TOOL_SCHEMAS)
        assert len(result) == len(TOOL_SCHEMAS)

    def test_type_is_function(self):
        result = to_openai_tools(TOOL_SCHEMAS)
        for tool in result:
            assert tool["type"] == "function"
            assert "function" in tool

    def test_name_description_parameters_present(self):
        result = to_openai_tools(TOOL_SCHEMAS)
        for tool in result:
            fn = tool["function"]
            assert "name" in fn
            assert "description" in fn
            assert "parameters" in fn

    def test_parameters_equals_input_schema(self):
        for schema, converted in zip(TOOL_SCHEMAS, to_openai_tools(TOOL_SCHEMAS), strict=False):
            assert converted["function"]["parameters"] == schema["input_schema"]

    def test_name_preserved(self):
        result = to_openai_tools(TOOL_SCHEMAS)
        names = {t["function"]["name"] for t in result}
        expected = {s["name"] for s in TOOL_SCHEMAS}
        assert names == expected

    def test_empty_input(self):
        assert to_openai_tools([]) == []

    def test_single_schema(self):
        schema = {
            "name": "test_tool",
            "description": "A test tool",
            "input_schema": {
                "type": "object",
                "properties": {"x": {"type": "string"}},
                "required": ["x"],
            },
        }
        result = to_openai_tools([schema])
        assert len(result) == 1
        fn = result[0]["function"]
        assert fn["name"] == "test_tool"
        assert fn["description"] == "A test tool"
        assert fn["parameters"] == schema["input_schema"]


# ── AnthropicBackend._to_anthropic_messages ─────────────────────────────────


def _make_backend() -> AnthropicBackend:
    """Create an AnthropicBackend with a fake API key (not used in these tests)."""
    return AnthropicBackend(api_key="test-key", model="claude-opus-4-6", tool_schemas=TOOL_SCHEMAS)


class TestAnthropicMessageTranslation:
    def test_plain_user_message_passes_through(self):
        backend = _make_backend()
        msgs = [{"role": "user", "content": "hello"}]
        result = backend._to_anthropic_messages(msgs)
        assert result == [{"role": "user", "content": "hello"}]

    def test_plain_assistant_text_message(self):
        backend = _make_backend()
        msgs = [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello back", "tool_calls": []},
        ]
        result = backend._to_anthropic_messages(msgs)
        assert result[1]["role"] == "assistant"
        content = result[1]["content"]
        assert any(b.get("type") == "text" and b.get("text") == "hello back" for b in content)

    def test_assistant_tool_calls_converted(self):
        backend = _make_backend()
        msgs = [
            {"role": "user", "content": "find resource"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "tc-1",
                        "type": "function",
                        "function": {
                            "name": "get_resource",
                            "arguments": json.dumps({"node_id": "s3-test"}),
                        },
                    }
                ],
            },
        ]
        result = backend._to_anthropic_messages(msgs)
        asst = result[1]
        assert asst["role"] == "assistant"
        tool_block = next(b for b in asst["content"] if b.get("type") == "tool_use")
        assert tool_block["id"] == "tc-1"
        assert tool_block["name"] == "get_resource"
        assert tool_block["input"] == {"node_id": "s3-test"}

    def test_tool_result_merged_into_user_message(self):
        backend = _make_backend()
        msgs = [
            {"role": "user", "content": "start"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "tc-1",
                        "type": "function",
                        "function": {"name": "get_resource", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "tc-1", "content": '{"node_id": "x"}'},
        ]
        result = backend._to_anthropic_messages(msgs)
        # Last message should be user with tool_result
        last = result[-1]
        assert last["role"] == "user"
        assert isinstance(last["content"], list)
        tr = last["content"][0]
        assert tr["type"] == "tool_result"
        assert tr["tool_use_id"] == "tc-1"

    def test_multiple_tool_results_merged(self):
        """Two consecutive tool messages → single Anthropic user message."""
        backend = _make_backend()
        msgs = [
            {"role": "user", "content": "start"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "tc-1",
                        "type": "function",
                        "function": {"name": "get_resource", "arguments": "{}"},
                    },
                    {
                        "id": "tc-2",
                        "type": "function",
                        "function": {"name": "get_neighbors", "arguments": "{}"},
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "tc-1", "content": '{"a": 1}'},
            {"role": "tool", "tool_call_id": "tc-2", "content": '{"b": 2}'},
        ]
        result = backend._to_anthropic_messages(msgs)
        # Should have: user, assistant, user(merged tool results)
        assert len(result) == 3
        merged_user = result[2]
        assert merged_user["role"] == "user"
        assert len(merged_user["content"]) == 2
        ids = {b["tool_use_id"] for b in merged_user["content"]}
        assert ids == {"tc-1", "tc-2"}


class TestThinkingBlockInjection:
    def test_pending_thinking_injected_into_next_assistant_message(self):
        """
        Thinking blocks stored from a previous turn are prepended to the
        next assistant message during format conversion.
        """
        backend = _make_backend()
        # Pre-load a pending thinking block
        backend._pending_thinking_blocks = [
            {"type": "thinking", "thinking": "I reasoned...", "signature": "sig-1"}
        ]

        msgs = [
            {"role": "user", "content": "start"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "tc-1",
                        "type": "function",
                        "function": {"name": "get_resource", "arguments": "{}"},
                    }
                ],
            },
        ]
        result = backend._to_anthropic_messages(msgs)
        asst_content = result[1]["content"]
        # First block should be the thinking block
        assert asst_content[0]["type"] == "thinking"
        assert asst_content[0]["thinking"] == "I reasoned..."
        assert asst_content[0]["signature"] == "sig-1"
        # Pending blocks cleared after injection
        assert backend._pending_thinking_blocks == []

    def test_pending_thinking_cleared_after_injection(self):
        backend = _make_backend()
        backend._pending_thinking_blocks = [
            {"type": "thinking", "thinking": "thought", "signature": "s"}
        ]
        msgs = [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "ok", "tool_calls": []},
        ]
        backend._to_anthropic_messages(msgs)
        assert backend._pending_thinking_blocks == []


# ── AnthropicBackend stream_turn (Anthropic API params) ─────────────────────


def _build_mock_client(*, with_thinking: bool = False, capture: dict | None = None) -> MagicMock:
    """Build a mock Anthropic client that captures kwargs and returns a simple end_turn response."""
    client = MagicMock()

    text_chunk = MagicMock()
    text_chunk.type = "content_block_delta"
    text_chunk.delta = MagicMock()
    text_chunk.delta.type = "text_delta"
    text_chunk.delta.text = "hello"

    final_msg = MagicMock()
    final_msg.stop_reason = "end_turn"
    final_msg.content = []

    if with_thinking:
        thinking_block = MagicMock()
        thinking_block.type = "thinking"
        thinking_block.thinking = "reasoning..."
        thinking_block.signature = "sig-test"
        final_msg.content = [thinking_block]

    @asynccontextmanager
    async def _stream_cm(*args, **kwargs):
        if capture is not None:
            capture.update(kwargs)

        class _S:
            def __aiter__(self):
                return self._iter()

            async def _iter(self):
                yield text_chunk

            async def get_final_message(self):
                return final_msg

        yield _S()

    client.messages.stream = _stream_cm
    return client


class TestAnthropicStreamTurnParams:
    @pytest.mark.asyncio
    async def test_no_thinking_params_when_disabled(self):
        cap: dict = {}
        backend = _make_backend()
        backend._client = _build_mock_client(capture=cap)

        events = []
        async for e in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=1024,
            enable_thinking=False,
        ):
            events.append(e)

        assert "thinking" not in cap
        assert "betas" not in cap

    @pytest.mark.asyncio
    async def test_thinking_params_sent_when_enabled(self):
        cap: dict = {}
        backend = _make_backend()
        backend._client = _build_mock_client(capture=cap)

        events = []
        async for e in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=1024,
            enable_thinking=True,
            thinking_budget_tokens=5000,
        ):
            events.append(e)

        assert cap.get("thinking") == {"type": "enabled", "budget_tokens": 5000}
        assert "interleaved-thinking-2025-05-14" in cap.get("betas", [])

    @pytest.mark.asyncio
    async def test_max_tokens_raised_above_thinking_budget(self):
        """max_tokens must exceed thinking_budget_tokens."""
        cap: dict = {}
        backend = _make_backend()
        backend._client = _build_mock_client(capture=cap)

        async for _ in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=1024,  # below budget
            enable_thinking=True,
            thinking_budget_tokens=8000,
        ):
            pass

        mt = cap.get("max_tokens", 0)
        assert mt > 8000, f"max_tokens={mt} should exceed thinking_budget_tokens=8000"

    @pytest.mark.asyncio
    async def test_thinking_blocks_stored_as_pending(self):
        """When the Anthropic response includes a thinking block, it's stored in _pending_thinking_blocks."""
        backend = _make_backend()
        backend._client = _build_mock_client(with_thinking=True)

        events = []
        async for e in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=1024,
            enable_thinking=True,
            thinking_budget_tokens=5000,
        ):
            events.append(e)

        assert len(backend._pending_thinking_blocks) == 1
        block = backend._pending_thinking_blocks[0]
        assert block["type"] == "thinking"
        assert block["thinking"] == "reasoning..."
        assert block["signature"] == "sig-test"

    @pytest.mark.asyncio
    async def test_stream_turn_yields_turn_complete(self):
        backend = _make_backend()
        backend._client = _build_mock_client()

        events = []
        async for e in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=512,
        ):
            events.append(e)

        complete_events = [e for e in events if isinstance(e, TurnComplete)]
        assert len(complete_events) == 1
        assert complete_events[0].stop_reason == "end_turn"

    @pytest.mark.asyncio
    async def test_stream_turn_yields_text_chunks(self):
        backend = _make_backend()
        backend._client = _build_mock_client()

        text_chunks = []
        async for e in backend.stream_turn(
            messages=[{"role": "user", "content": "hi"}],
            system="sys",
            max_tokens=512,
        ):
            if isinstance(e, TextChunk):
                text_chunks.append(e)

        assert len(text_chunks) > 0
        assert text_chunks[0].text == "hello"
