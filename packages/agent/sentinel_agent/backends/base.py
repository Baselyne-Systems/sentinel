"""
LLMBackend Protocol and stream event dataclasses.

Defines the provider-agnostic interface that ``SentinelAgent`` uses.
Any concrete backend (Anthropic, OpenAI-compatible) implements this Protocol.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class TextChunk:
    """A streamed text token."""

    text: str


@dataclass
class ThinkingChunk:
    """A streamed thinking token (only emitted by AnthropicBackend)."""

    thinking: str


@dataclass
class ToolCallChunk:
    """A fully assembled tool call (name + parsed arguments)."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class TurnComplete:
    """
    Signals the end of one LLM turn.

    Always the LAST event yielded per ``stream_turn`` call.

    Attributes:
        text: Accumulated assistant text for this turn.
        tool_calls: All tool calls requested in this turn (may be empty).
        stop_reason: ``"end_turn"`` when done; ``"tool_use"`` when tool calls follow.
    """

    text: str
    tool_calls: list[ToolCallChunk] = field(default_factory=list)
    stop_reason: str = "end_turn"


#: Union of all stream events that a backend may yield.
LLMStreamEvent = TextChunk | ThinkingChunk | TurnComplete


@runtime_checkable
class LLMBackend(Protocol):
    """
    Provider-agnostic LLM backend interface.

    ``SentinelAgent`` calls ``stream_turn`` once per conversation round and
    processes the yielded events to drive the tool-use loop.

    Implementors: ``AnthropicBackend``, ``OpenAIBackend``.

    Note: Declared as a regular method (not ``async def``) so that callers can
    use ``async for event in backend.stream_turn(...)`` directly.  Concrete
    backends implement this as an async generator function, which returns an
    ``AsyncGenerator`` (a subtype of ``AsyncIterator``) when called.
    """

    def stream_turn(
        self,
        messages: list[dict[str, Any]],
        system: str,
        max_tokens: int,
        enable_thinking: bool = False,
        thinking_budget_tokens: int = 8000,
    ) -> AsyncIterator[LLMStreamEvent]:
        """
        Stream one assistant turn and yield events.

        Args:
            messages: Conversation history in OpenAI message format.
            system: System prompt string.
            max_tokens: Maximum tokens for the response.
            enable_thinking: Enable extended thinking (Anthropic only; ignored elsewhere).
            thinking_budget_tokens: Token budget for extended thinking.

        Yields:
            ``TextChunk``, ``ThinkingChunk``, and finally ``TurnComplete``.
        """
        ...
