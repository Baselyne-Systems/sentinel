"""
LLM backend factory and re-exports.

Usage::

    from sentinel_agent.backends import create_backend, LLMBackend

    backend = create_backend(settings)  # returns AnthropicBackend or OpenAIBackend
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sentinel_agent.backends.anthropic import AnthropicBackend
from sentinel_agent.backends.base import (
    LLMBackend,
    LLMStreamEvent,
    TextChunk,
    ThinkingChunk,
    ToolCallChunk,
    TurnComplete,
)
from sentinel_agent.backends.openai_ import OpenAIBackend
from sentinel_agent.tools import TOOL_SCHEMAS

if TYPE_CHECKING:
    pass

__all__ = [
    "LLMBackend",
    "LLMStreamEvent",
    "TextChunk",
    "ThinkingChunk",
    "ToolCallChunk",
    "TurnComplete",
    "AnthropicBackend",
    "OpenAIBackend",
    "create_backend",
]


def create_backend(settings: Any) -> LLMBackend:
    """
    Instantiate the correct backend from ``AgentSettings``.

    Args:
        settings: ``AgentSettings`` dataclass with ``provider``,
            ``anthropic_api_key``, ``openai_api_key``, ``openai_base_url``,
            and ``agent_model`` fields.

    Returns:
        ``OpenAIBackend`` when ``settings.provider == "openai"``;
        ``AnthropicBackend`` otherwise (the default).
    """
    if settings.provider == "openai":
        return OpenAIBackend(
            api_key=settings.openai_api_key,
            model=settings.agent_model,
            tool_schemas=TOOL_SCHEMAS,
            base_url=settings.openai_base_url or None,
        )
    return AnthropicBackend(
        api_key=settings.anthropic_api_key,
        model=settings.agent_model,
        tool_schemas=TOOL_SCHEMAS,
    )
