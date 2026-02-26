"""
AnthropicBackend — wraps the Anthropic SDK streaming API.

Translates between the agent's internal OpenAI-format message list and the
Anthropic API's native format.  Handles extended thinking blocks with their
signature fields for multi-turn correctness.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

import anthropic

from sentinel_agent.backends.base import (
    TextChunk,
    ThinkingChunk,
    ToolCallChunk,
    TurnComplete,
)

logger = logging.getLogger(__name__)


class AnthropicBackend:
    """
    LLM backend that calls the Anthropic Messages API.

    Args:
        api_key: Anthropic API key.
        model: Model ID (e.g. ``"claude-opus-4-6"``).
        tool_schemas: Anthropic-format tool schemas (list of dicts with
            ``name``, ``description``, ``input_schema``).
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        tool_schemas: list[dict[str, Any]],
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model
        self._tools = tool_schemas
        # Pending thinking blocks from the previous turn, preserved for multi-turn injection.
        self._pending_thinking_blocks: list[dict[str, Any]] = []

    async def stream_turn(
        self,
        messages: list[dict[str, Any]],
        system: str,
        max_tokens: int,
        enable_thinking: bool = False,
        thinking_budget_tokens: int = 8000,
    ) -> AsyncIterator[TextChunk | ThinkingChunk | TurnComplete]:
        """Stream one Anthropic turn and yield backend-agnostic events."""
        anthropic_messages = self._to_anthropic_messages(messages)

        effective_max_tokens = max_tokens
        api_kwargs: dict[str, Any] = {
            "model": self._model,
            "system": system,
            "tools": self._tools,
            "messages": anthropic_messages,
        }
        if enable_thinking:
            effective_max_tokens = max(max_tokens, thinking_budget_tokens + 2048)
            api_kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget_tokens,
            }
            api_kwargs["betas"] = ["interleaved-thinking-2025-05-14"]
        api_kwargs["max_tokens"] = effective_max_tokens

        accumulated_text = ""
        async with self._client.messages.stream(**api_kwargs) as stream:
            async for chunk in stream:
                if chunk.type == "content_block_delta":
                    delta = chunk.delta
                    if delta.type == "text_delta":
                        accumulated_text += delta.text
                        yield TextChunk(text=delta.text)
                    elif delta.type == "thinking_delta":
                        yield ThinkingChunk(thinking=delta.thinking)

            final = await stream.get_final_message()

        tool_calls: list[ToolCallChunk] = []
        for block in final.content:
            if block.type == "tool_use":
                tool_calls.append(
                    ToolCallChunk(
                        id=block.id,
                        name=block.name,
                        arguments=block.input,
                    )
                )
            elif block.type == "thinking":
                # Preserve signature for the next Anthropic-format turn.
                self._pending_thinking_blocks.append(
                    {
                        "type": "thinking",
                        "thinking": block.thinking,
                        "signature": block.signature,
                    }
                )

        stop = "tool_use" if final.stop_reason == "tool_use" else "end_turn"
        yield TurnComplete(
            text=accumulated_text,
            tool_calls=tool_calls,
            stop_reason=stop,
        )

    # ── Message format translation ─────────────────────────────────────────────

    def _to_anthropic_messages(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Convert OpenAI-format messages to Anthropic format.

        Translations applied:
        - ``{"role":"assistant","tool_calls":[...]}`` → assistant with
          ``tool_use`` content blocks (thinking blocks injected first).
        - Consecutive ``{"role":"tool",...}`` messages → single user message
          with ``tool_result`` content blocks.
        - Plain ``user``/``assistant`` text messages pass through.
        """
        result: list[dict[str, Any]] = []
        i = 0
        while i < len(messages):
            msg = messages[i]
            role = msg["role"]

            if role == "user":
                user_content = msg.get("content", "")
                result.append({"role": "user", "content": user_content})
                i += 1

            elif role == "assistant":
                content: list[dict[str, Any]] = []

                # Inject any pending thinking blocks (from previous turn).
                if self._pending_thinking_blocks:
                    content.extend(self._pending_thinking_blocks)
                    self._pending_thinking_blocks = []

                tool_calls = msg.get("tool_calls") or []
                if tool_calls:
                    for tc in tool_calls:
                        fn = tc["function"]
                        raw_args = fn.get("arguments", "{}")
                        parsed_args = (
                            json.loads(raw_args)
                            if isinstance(raw_args, str)
                            else raw_args
                        )
                        content.append(
                            {
                                "type": "tool_use",
                                "id": tc["id"],
                                "name": fn["name"],
                                "input": parsed_args,
                            }
                        )
                else:
                    text = msg.get("content") or ""
                    if text:
                        content.append({"type": "text", "text": text})

                result.append({"role": "assistant", "content": content})
                i += 1

            elif role == "tool":
                # Merge consecutive tool messages into one Anthropic user message.
                tool_results: list[dict[str, Any]] = []
                while i < len(messages) and messages[i]["role"] == "tool":
                    t = messages[i]
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": t["tool_call_id"],
                            "content": t["content"],
                        }
                    )
                    i += 1
                result.append({"role": "user", "content": tool_results})

            else:
                # Unknown role: pass through as-is.
                result.append(msg)
                i += 1

        return result
