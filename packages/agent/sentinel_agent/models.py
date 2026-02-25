"""
Data contracts for the SENTINEL agent layer.

This module defines two categories of types:

**SSE Event dataclasses** — emitted by ``SentinelAgent`` and serialised by
``routers/agent.py`` into the ``text/event-stream`` wire format.  Each
dataclass has a ``to_sse()`` method that returns a ready-to-send SSE line
(``data: {...}\\n\\n``).  The frontend ``agentApi.streamAnalysis()`` parses
these lines and dispatches on the ``event`` discriminator field.

**Pydantic output models** — ``AnalysisResult`` is the authoritative record
produced at the end of an agent run.  It is:

- Yielded inside ``AnalysisCompleteEvent`` to the streaming client
- Serialised to JSON and stored on the Neo4j node as ``agent_analysis``
- Returned by ``GET /agent/findings/{node_id}/analysis`` (cache read)
- Validated via ``AnalysisResult.model_validate()`` on cache read

Wire format (SSE)
-----------------
Each event is one line of the ``text/event-stream`` body::

    data: {"event": "text_delta", "text": "..."}\n\n
    data: {"event": "tool_use", "tool_name": "get_neighbors", ...}\n\n
    data: {"event": "analysis_complete", "result": {...}}\n\n
    data: {"event": "error", "message": "..."}\n\n
    data: [DONE]\n\n

The final ``[DONE]`` sentinel is written by the router, not by the agent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Union

from pydantic import BaseModel, Field


# ── SSE Event types ────────────────────────────────────────────────────────────


@dataclass
class TextDeltaEvent:
    """
    A single streamed text token from the LLM.

    Emitted for every ``content_block_delta`` chunk whose delta has a ``text``
    attribute.  The frontend accumulates these into the live reasoning display
    shown while the agent is working.

    Attributes:
        text: The raw token string (may be one character or a short word).
        event: Fixed discriminator ``"text_delta"`` — do not override.
    """

    text: str
    event: str = field(default="text_delta", init=False)

    def to_sse(self) -> str:
        """Return an SSE-formatted data line for this token."""
        return f"data: {json.dumps({'event': self.event, 'text': self.text})}\n\n"


@dataclass
class ToolUseEvent:
    """
    The agent invoked one of the four graph query tools.

    Emitted once per tool call, *after* the tool has returned its result.
    The frontend uses these events to render the "Graph queries" pill list
    that shows which tools were called and what they found.

    Attributes:
        tool_name: Name of the tool called (``get_resource``, ``get_neighbors``,
            ``find_attack_paths``, or ``query_graph``).
        tool_input: The exact ``input`` dict passed by the LLM to the tool.
        tool_result_summary: Human-readable one-liner summarising the result
            (e.g. ``"Returned 12 item(s)"`` or ``"Error: write op blocked"``).
        event: Fixed discriminator ``"tool_use"``.
    """

    tool_name: str
    tool_input: dict
    tool_result_summary: str
    event: str = field(default="tool_use", init=False)

    def to_sse(self) -> str:
        """Return an SSE-formatted data line for this tool event."""
        return (
            f"data: {json.dumps({'event': self.event, 'tool_name': self.tool_name, 'tool_input': self.tool_input, 'tool_result_summary': self.tool_result_summary})}\n\n"
        )


@dataclass
class AnalysisCompleteEvent:
    """
    The final structured analysis — emitted exactly once at the end of the stream.

    Wraps an :class:`AnalysisResult` and signals to the client that the agent
    run is finished.  The frontend renders the full analysis panel (priority
    badge, risk narrative, remediation steps) on receipt of this event.

    Attributes:
        result: The complete, validated :class:`AnalysisResult`.
        event: Fixed discriminator ``"analysis_complete"``.
    """

    result: "AnalysisResult"
    event: str = field(default="analysis_complete", init=False)

    def to_sse(self) -> str:
        """Return an SSE-formatted data line containing the full result."""
        return (
            f"data: {json.dumps({'event': self.event, 'result': self.result.model_dump()})}\n\n"
        )


@dataclass
class ErrorEvent:
    """
    The agent encountered a non-recoverable error.

    Emitted in place of ``AnalysisCompleteEvent`` when something goes wrong:
    node not found, Anthropic API failure, or unhandled exception.
    The frontend displays an inline error message with a retry button.

    Attributes:
        message: Human-readable description of what went wrong.
        event: Fixed discriminator ``"error"``.
    """

    message: str
    event: str = field(default="error", init=False)

    def to_sse(self) -> str:
        """Return an SSE-formatted data line for this error."""
        return f"data: {json.dumps({'event': self.event, 'message': self.message})}\n\n"


# Union type used as the return/yield type annotation throughout the agent layer.
SSEEvent = Union[TextDeltaEvent, ToolUseEvent, AnalysisCompleteEvent, ErrorEvent]


# ── Structured output model ────────────────────────────────────────────────────


class RemediationStep(BaseModel):
    """
    A single, actionable remediation step produced by the agent.

    Attributes:
        step_number: 1-based ordering index.
        title: Short imperative title (e.g. ``"Enable Block Public Access"``).
        description: Detailed explanation of the action and its rationale.
        iac_snippet: Optional Terraform HCL snippet (code fences stripped).
            Empty string when no IaC applies.
    """

    step_number: int
    title: str
    description: str
    iac_snippet: str = ""


class AnalysisResult(BaseModel):
    """
    Complete structured output from a SENTINEL agent run.

    Produced by parsing the ``<analysis>`` XML block in Claude's final response.
    Stored in Neo4j as a JSON string on ``node.agent_analysis`` and returned
    verbatim by ``GET /agent/findings/{node_id}/analysis``.

    Attributes:
        node_id: The graph node that was analysed (or account_id for briefs).
        risk_narrative: 2–4 paragraph free-text assessment of the finding's
            real-world impact, attacker opportunities, and business risk.
        priority_score: Integer 1–10 risk score (1 = informational,
            10 = critical / actively exploitable).
        priority_rationale: 1–2 sentences explaining the score choice.
        remediation_steps: Ordered list of :class:`RemediationStep` objects.
        attack_paths_summary: Brief text summarising the most significant
            attack paths found, or ``"No critical attack paths identified."``.
        model: Anthropic model ID used for this analysis run.
        analyzed_at: ISO 8601 UTC timestamp of when the analysis completed.
    """

    node_id: str
    risk_narrative: str
    priority_score: int = Field(ge=1, le=10)
    priority_rationale: str
    remediation_steps: list[RemediationStep]
    attack_paths_summary: str = ""
    model: str = ""
    analyzed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_neo4j_props(self) -> dict:
        """
        Serialise this result for storage on a Neo4j node.

        Returns a dict with two keys suitable for a Cypher ``SET`` statement:

        - ``agent_analysis``: full JSON string of ``model_dump()``
        - ``agent_analyzed_at``: ISO UTC timestamp string

        Example Cypher usage::

            SET n.agent_analysis = $agent_analysis,
                n.agent_analyzed_at = $agent_analyzed_at
        """
        return {
            "agent_analysis": json.dumps(self.model_dump()),
            "agent_analyzed_at": self.analyzed_at,
        }
