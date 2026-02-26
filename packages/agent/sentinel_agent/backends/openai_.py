"""
OpenAIBackend — wraps the OpenAI SDK for OpenAI-compatible endpoints.

Works with standard OpenAI, Groq, Together AI, vLLM, and Ollama
(anything that speaks the OpenAI Chat Completions API).

Pass ``base_url`` to point at a non-OpenAI endpoint:
    ``base_url="http://localhost:11434/v1"``  → Ollama
    ``base_url="https://api.groq.com/openai/v1"``  → Groq
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from openai import AsyncOpenAI, AsyncStream
from openai.types.chat import ChatCompletionChunk

from sentinel_agent.backends.base import (
    TextChunk,
    ThinkingChunk,
    ToolCallChunk,
    TurnComplete,
)
from sentinel_agent.tools import to_openai_tools

logger = logging.getLogger(__name__)


class OpenAIBackend:
    """
    LLM backend for OpenAI-compatible streaming APIs.

    Args:
        api_key: API key.  Pass ``"none"`` for local endpoints (Ollama).
        model: Model name to request.
        tool_schemas: Anthropic-format ``TOOL_SCHEMAS``; converted to OpenAI
            function format via ``to_openai_tools()``.
        base_url: Optional base URL override for non-OpenAI providers.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        tool_schemas: list[dict[str, Any]],
        base_url: str | None = None,
    ) -> None:
        self._client = AsyncOpenAI(
            api_key=api_key or "none",
            base_url=base_url,
        )
        self._model = model
        self._tools = to_openai_tools(tool_schemas)

    async def stream_turn(
        self,
        messages: list[dict[str, Any]],
        system: str,
        max_tokens: int,
        enable_thinking: bool = False,
        thinking_budget_tokens: int = 8000,
    ) -> AsyncIterator[TextChunk | ThinkingChunk | TurnComplete]:
        """
        Stream one OpenAI-compatible turn.

        ``enable_thinking`` and ``thinking_budget_tokens`` are silently ignored
        (extended thinking is an Anthropic-only feature).
        """
        all_msgs: list[dict[str, Any]] = [{"role": "system", "content": system}] + messages

        raw_stream = await self._client.chat.completions.create(
            model=self._model,
            messages=all_msgs,  # type: ignore[arg-type]
            tools=self._tools,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            stream=True,
        )
        stream: AsyncStream[ChatCompletionChunk] = raw_stream  # type: ignore[assignment]

        full_text = ""
        raw_calls: dict[int, dict[str, str]] = {}
        last_chunk = None

        async for chunk in stream:
            last_chunk = chunk
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if delta.content:
                full_text += delta.content
                yield TextChunk(text=delta.content)
            if delta.tool_calls:
                for tc in delta.tool_calls:
                    slot = raw_calls.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                    if tc.id:
                        slot["id"] = tc.id
                    if tc.function and tc.function.name:
                        slot["name"] = tc.function.name
                    if tc.function and tc.function.arguments:
                        slot["args"] += tc.function.arguments

        finish = (
            last_chunk.choices[0].finish_reason if last_chunk and last_chunk.choices else "stop"
        )
        tool_calls = [
            ToolCallChunk(
                id=v["id"],
                name=v["name"],
                arguments=json.loads(v["args"] or "{}"),
            )
            for v in raw_calls.values()
        ]
        stop = "tool_use" if finish == "tool_calls" else "end_turn"
        yield TurnComplete(text=full_text, tool_calls=tool_calls, stop_reason=stop)
