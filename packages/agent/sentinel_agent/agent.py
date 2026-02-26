"""
SentinelAgent: Streaming tool-use loop for cloud security analysis.

Architecture
------------
``SentinelAgent`` is the orchestration layer for Phase 2.  It connects the
Anthropic streaming API to the SENTINEL Neo4j graph via a tool-use loop, then
parses the LLM's structured XML output into an ``AnalysisResult`` that is both
streamed to the client and cached on the graph node.

High-level flow for ``analyze_finding``::

    SentinelAgent.analyze_finding(node_id, account_id)
        │
        ├─ get_resource(node_id)          ← preflight: node must exist
        │
        ├─ build_finding_message(…)       ← seed the conversation
        │
        └─ _run_tool_loop(messages)       ← streaming loop, ≤ _MAX_TOOL_ROUNDS
               │
               ├─ client.messages.stream(…)
               │       ├─ yield TextDeltaEvent per token
               │       └─ collect tool_use blocks
               │
               ├─ AgentTools.dispatch(tool_name, input)
               │       └─ yield ToolUseEvent (name + result summary)
               │
               └─ repeat until stop_reason == "end_turn"
               │
    ├─ _parse_analysis_xml(full_text)    ← extract <analysis> block
    ├─ _cache_result(node_id, result)    ← SET n.agent_analysis = $json
    └─ yield AnalysisCompleteEvent(result)

Tool-use loop design
--------------------
- ``_MAX_TOOL_ROUNDS = 8`` caps the number of Claude ↔ tool round-trips.
  In practice the agent typically uses 3–4 rounds.
- On ``stop_reason == "tool_use"``: dispatch all ``tool_use`` blocks in
  sequence, append a ``tool_result`` user message, and continue streaming.
- On ``stop_reason == "end_turn"`` (or no tool_use blocks): break.
- If the loop exhausts all rounds, a warning is logged and the last
  accumulated text is used for XML parsing.

XML parsing
-----------
Claude is instructed to wrap its final answer in ``<analysis>…</analysis>``
(see ``prompts.py``).  The ``_parse_analysis_xml()`` function extracts each
sub-element with non-greedy regex and constructs an ``AnalysisResult``.  If
the block is absent or malformed, a minimal fallback result is created so the
stream always terminates with ``AnalysisCompleteEvent`` rather than an error.

Caching
-------
After parsing, ``_cache_result()`` writes two properties to the Neo4j node::

    n.agent_analysis    = <JSON string of AnalysisResult.model_dump()>
    n.agent_analyzed_at = <ISO 8601 UTC timestamp>

Subsequent ``GET /agent/findings/{node_id}/analysis`` requests read these
properties directly without re-running the agent.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import anthropic
from sentinel_core.graph.client import Neo4jClient

from sentinel_agent.models import (
    AnalysisCompleteEvent,
    AnalysisResult,
    ErrorEvent,
    RemediationStep,
    SSEEvent,
    TextDeltaEvent,
    ThinkingDeltaEvent,
    ToolUseEvent,
)
from sentinel_agent.prompts import SYSTEM_PROMPT, build_brief_message, build_finding_message
from sentinel_agent.tools import TOOL_SCHEMAS, AgentTools

logger = logging.getLogger(__name__)


# ── Settings dataclass ─────────────────────────────────────────────────────────


@dataclass
class AgentSettings:
    """
    Runtime configuration for ``SentinelAgent``.

    Kept as a plain dataclass (not Pydantic) to avoid importing
    ``sentinel_api.config.Settings`` from the agent package — that would
    create a circular dependency since the API package depends on the agent.
    The API's ``deps.py`` bridges the two by constructing an ``AgentSettings``
    from the API's ``Settings`` object.

    Attributes:
        anthropic_api_key: Anthropic API key.  Must not be empty.
        agent_model: Anthropic model ID to use for analysis.
            Defaults to ``"claude-opus-4-6"``.
        agent_max_tokens: Maximum tokens in a single Claude response turn.
            Defaults to 4096 — sufficient for full analysis XML with IaC.
    """

    anthropic_api_key: str
    agent_model: str = "claude-opus-4-6"
    agent_max_tokens: int = 4096
    enable_thinking: bool = False
    thinking_budget_tokens: int = 8000


# ── XML parsing helpers ────────────────────────────────────────────────────────


def _extract_xml_tag(text: str, tag: str) -> str:
    """
    Extract the inner text of a single XML tag (non-greedy, ``DOTALL``).

    Args:
        text: The XML string to search within.
        tag: The element name (without angle brackets).

    Returns:
        Stripped inner text, or ``""`` if the tag is absent.
    """
    pattern = rf"<{tag}>(.*?)</{tag}>"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else ""


def _parse_remediation_steps(xml_text: str) -> list[RemediationStep]:
    """
    Parse all ``<step number="N">…</step>`` blocks from a ``<remediation_steps>``
    XML fragment.

    Each step block is expected to contain ``<title>``, ``<description>``, and
    optionally ``<iac_snippet>`` child elements.  Markdown code fences
    (````hcl … `````) are stripped from the IaC snippet before storage so the
    frontend can render the code directly.

    Args:
        xml_text: The inner content of the ``<remediation_steps>`` element.

    Returns:
        List of :class:`~sentinel_agent.models.RemediationStep` objects,
        sorted by ``step_number`` ascending.
    """
    step_pattern = re.compile(
        r'<step\s+number="(\d+)">(.*?)</step>',
        re.DOTALL,
    )
    steps: list[RemediationStep] = []
    for match in step_pattern.finditer(xml_text):
        number = int(match.group(1))
        inner = match.group(2)
        title = _extract_xml_tag(inner, "title")
        description = _extract_xml_tag(inner, "description")
        iac_raw = _extract_xml_tag(inner, "iac_snippet")
        # Strip opening ````hcl` / ````terraform` and closing ` ``` ` fences
        iac_clean = re.sub(r"^```\w*\n?|```$", "", iac_raw.strip(), flags=re.MULTILINE).strip()
        steps.append(
            RemediationStep(
                step_number=number,
                title=title or f"Step {number}",
                description=description,
                iac_snippet=iac_clean,
            )
        )
    return sorted(steps, key=lambda s: s.step_number)


def _parse_analysis_xml(node_id: str, text: str, model: str) -> AnalysisResult | None:
    """
    Parse Claude's ``<analysis>…</analysis>`` XML block into an AnalysisResult.

    Extraction strategy:
    1. Find the outermost ``<analysis>`` … ``</analysis>`` block (non-greedy).
    2. Extract each child element with ``_extract_xml_tag()``.
    3. Clamp ``priority_score`` to [1, 10]; default to 5 on parse failure.
    4. Delegate remediation step parsing to ``_parse_remediation_steps()``.

    Args:
        node_id: Identifier to stamp on the result (``AnalysisResult.node_id``).
        text: The full accumulated assistant response text.
        model: Anthropic model ID used for this run.

    Returns:
        Parsed ``AnalysisResult``, or ``None`` if no ``<analysis>`` block was
        found (the caller should create a fallback result in that case).
    """
    analysis_match = re.search(r"<analysis>(.*?)</analysis>", text, re.DOTALL)
    if not analysis_match:
        logger.warning("No <analysis> block found in LLM response for node %s", node_id)
        return None

    inner = analysis_match.group(1)

    risk_narrative = _extract_xml_tag(inner, "risk_narrative")
    priority_rationale = _extract_xml_tag(inner, "priority_rationale")
    attack_paths_summary = _extract_xml_tag(inner, "attack_paths_summary")

    score_str = _extract_xml_tag(inner, "priority_score")
    try:
        # Clamp to valid range; guard against "10/10" or other non-integer text
        priority_score = max(1, min(10, int(score_str)))
    except (ValueError, TypeError):
        logger.warning("Could not parse priority_score %r — defaulting to 5", score_str)
        priority_score = 5

    remediation_xml = _extract_xml_tag(inner, "remediation_steps")
    steps = _parse_remediation_steps(remediation_xml)

    return AnalysisResult(
        node_id=node_id,
        risk_narrative=risk_narrative,
        priority_score=priority_score,
        priority_rationale=priority_rationale,
        remediation_steps=steps,
        attack_paths_summary=attack_paths_summary,
        model=model,
    )


# ── SentinelAgent ──────────────────────────────────────────────────────────────


class SentinelAgent:
    """
    Streaming cloud security analysis agent powered by Claude.

    Instantiated once per request (via ``deps.get_sentinel_agent()``) because
    each analysis is a stateful conversation.  The ``Neo4jClient`` and
    Anthropic client are injected so tests can substitute mocks.

    Example usage in a FastAPI route::

        async def analyze(node_id: str, agent: AgentDep, neo4j: Neo4jDep):
            async def gen():
                async for event in agent.analyze_finding(node_id, account_id):
                    yield event.to_sse().encode()
            return StreamingResponse(gen(), media_type="text/event-stream")

    Args:
        neo4j_client: Connected ``Neo4jClient`` — used for both tool queries
            and caching the result back to the graph.
        settings: ``AgentSettings`` carrying the Anthropic key and model config.
    """

    #: Maximum number of tool-use round-trips before the loop is aborted.
    #: Prevents runaway agents in edge cases (e.g. Claude stuck in a loop).
    _MAX_TOOL_ROUNDS = 8

    def __init__(self, neo4j_client: Neo4jClient, settings: AgentSettings) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._model = settings.agent_model
        self._max_tokens = settings.agent_max_tokens
        self._enable_thinking = settings.enable_thinking
        self._thinking_budget_tokens = settings.thinking_budget_tokens
        self._tools = AgentTools(neo4j_client)
        self._neo4j = neo4j_client

    async def analyze_finding(
        self, node_id: str, account_id: str, *, enable_thinking: bool | None = None
    ) -> AsyncIterator[SSEEvent]:
        """
        Stream a complete security analysis for a single finding node.

        This is the primary entry point called by
        ``POST /api/v1/agent/findings/{node_id}/analyze``.

        Yields events in this order:

        1. ``TextDeltaEvent`` — streamed tokens as Claude reasons (may include
           intermediate thinking text before the ``<analysis>`` XML block).
        2. ``ToolUseEvent`` — one per tool call, emitted *after* the tool
           result is available so the summary is accurate.
        3. ``AnalysisCompleteEvent`` — the final parsed ``AnalysisResult``.
           Always emitted, even if XML parsing falls back to a minimal result.
        4. ``ErrorEvent`` — emitted *instead of* all the above if the node
           does not exist in the graph.

        Side effect: writes ``agent_analysis`` and ``agent_analyzed_at``
        properties to the Neo4j node via ``_cache_result()``.

        Args:
            node_id: The unique graph node ID of the resource to analyse.
            account_id: The AWS account that owns the resource (used in the
                prompt; resolved from the node by the router before calling).

        Yields:
            :class:`~sentinel_agent.models.SSEEvent` objects.
        """
        # Pre-flight: confirm the node exists and grab initial metadata for the prompt
        resource = await self._tools.get_resource(node_id)
        if resource is None:
            yield ErrorEvent(message=f"Node '{node_id}' not found in graph")
            return

        resource_type = resource.get("resource_type", "Unknown")
        posture_flags = resource.get("posture_flags", []) or []
        region = resource.get("region", "unknown")

        initial_message = build_finding_message(
            node_id=node_id,
            resource_type=resource_type,
            posture_flags=posture_flags,
            account_id=account_id,
            region=region,
        )

        messages: list[dict[str, Any]] = [{"role": "user", "content": initial_message}]
        full_response_text = ""
        use_thinking = self._enable_thinking if enable_thinking is None else enable_thinking

        # Stream the tool-use loop; accumulate all text for XML parsing at the end
        async for event in self._run_tool_loop(messages, enable_thinking=use_thinking):
            if isinstance(event, TextDeltaEvent):
                full_response_text += event.text
            yield event

        # Parse the final <analysis> XML block from the accumulated text
        result = _parse_analysis_xml(node_id, full_response_text, self._model)
        if result is None:
            # Graceful fallback: keep whatever free-text Claude produced
            logger.warning("XML parse failed for %s — using fallback AnalysisResult", node_id)
            result = AnalysisResult(
                node_id=node_id,
                risk_narrative=(
                    full_response_text[:2000] if full_response_text else "Analysis unavailable."
                ),
                priority_score=5,
                priority_rationale="Automated scoring unavailable — review manually.",
                remediation_steps=[],
                model=self._model,
            )

        # Cache to Neo4j so subsequent GET requests don't re-run the agent
        await self._cache_result(node_id, result)
        yield AnalysisCompleteEvent(result=result)

    async def generate_brief(
        self, account_id: str, top_n: int = 5, *, enable_thinking: bool | None = None
    ) -> AsyncIterator[SSEEvent]:
        """
        Stream an executive security brief covering the top-N findings.

        Called by ``POST /api/v1/agent/brief``.  Fetches the ``top_n`` most
        severe nodes with posture flags from Neo4j (CRITICAL > HIGH > MEDIUM >
        LOW ordering), builds a multi-finding prompt, and runs the same
        tool-use loop as ``analyze_finding``.

        The resulting ``AnalysisResult.node_id`` is set to ``account_id``
        (since this is an account-level view, not tied to a single node).  The
        result is *not* cached on any Neo4j node — the brief is stateless.

        Args:
            account_id: AWS account ID to scope the brief to.
            top_n: Maximum number of findings to include.  Clamped to [1, 20]
                by the router.

        Yields:
            :class:`~sentinel_agent.models.SSEEvent` objects.
        """
        # Fetch top-N findings ordered by severity (CRITICAL=4, HIGH=3, …)
        cypher = """
        MATCH (n:GraphNode)
        WHERE size(n.posture_flags) > 0
        AND n.account_id = $account_id
        RETURN
            n.node_id AS node_id,
            n.resource_type AS resource_type,
            n.posture_flags AS posture_flags,
            CASE
                WHEN 'CRITICAL' IN n.posture_flags THEN 4
                WHEN 'HIGH' IN n.posture_flags THEN 3
                WHEN 'MEDIUM' IN n.posture_flags THEN 2
                ELSE 1
            END AS severity_rank
        ORDER BY severity_rank DESC
        LIMIT $top_n
        """
        findings = await self._neo4j.query(cypher, {"account_id": account_id, "top_n": top_n})

        if not findings:
            yield ErrorEvent(message=f"No findings found for account '{account_id}'")
            return

        initial_message = build_brief_message(
            findings=[dict(f) for f in findings],
            account_id=account_id,
        )
        messages: list[dict[str, Any]] = [{"role": "user", "content": initial_message}]
        full_response_text = ""
        use_thinking = self._enable_thinking if enable_thinking is None else enable_thinking

        async for event in self._run_tool_loop(messages, enable_thinking=use_thinking):
            if isinstance(event, TextDeltaEvent):
                full_response_text += event.text
            yield event

        # Parse XML; fall back gracefully on failure
        result = _parse_analysis_xml(account_id, full_response_text, self._model)
        if result is None:
            result = AnalysisResult(
                node_id=account_id,
                risk_narrative=(
                    full_response_text[:2000] if full_response_text else "Brief unavailable."
                ),
                priority_score=5,
                priority_rationale="Multi-finding brief — see narrative for details.",
                remediation_steps=[],
                model=self._model,
            )
        yield AnalysisCompleteEvent(result=result)

    async def _run_tool_loop(
        self, messages: list[dict[str, Any]], *, enable_thinking: bool = False
    ) -> AsyncIterator[SSEEvent]:
        """
        Core streaming tool-use loop (shared by both public methods).

        Each iteration:

        1. Opens a streaming request to the Anthropic API with the current
           conversation history and tool schemas.
        2. Yields ``TextDeltaEvent`` for every text token received.
        3. When ``enable_thinking=True``, also yields ``ThinkingDeltaEvent``
           for tokens inside Claude's extended thinking blocks.  The
           ``interleaved-thinking-2025-05-14`` beta is enabled automatically.
        4. After the stream closes, calls ``get_final_message()`` to retrieve
           the complete message (including any ``tool_use`` and ``thinking``
           content blocks, preserving thinking block signatures for multi-turn
           correctness).
        5. Appends the assistant turn to ``messages``.
        6. If ``stop_reason == "end_turn"`` (or no tool blocks): **break**.
        7. Otherwise: dispatches each tool, yields ``ToolUseEvent``, and
           appends a ``tool_result`` user message before the next iteration.

        The loop is bounded by ``_MAX_TOOL_ROUNDS``.  If exhausted, a warning
        is logged and the loop exits naturally (the accumulated text is used
        for XML parsing by the caller).

        Args:
            messages: Mutable conversation history list.  Modified in-place
                (new assistant and user turns are appended each round).
            enable_thinking: When ``True``, enable extended thinking mode.
                Adds the ``thinking`` parameter and ``interleaved-thinking``
                beta header to the API call.  ``max_tokens`` is automatically
                raised to ``thinking_budget_tokens + 2048`` if needed.

        Yields:
            ``TextDeltaEvent``, ``ThinkingDeltaEvent``, and ``ToolUseEvent``
            objects.
        """
        for _round_num in range(self._MAX_TOOL_ROUNDS):
            tool_use_blocks: list[dict[str, Any]] = []

            # Build the API call parameters; add thinking params when opted in.
            # max_tokens must exceed budget_tokens — raise it automatically.
            effective_max_tokens = self._max_tokens
            api_kwargs: dict[str, Any] = {
                "model": self._model,
                "system": SYSTEM_PROMPT,
                "tools": TOOL_SCHEMAS,
                "messages": messages,
            }
            if enable_thinking:
                effective_max_tokens = max(self._max_tokens, self._thinking_budget_tokens + 2048)
                api_kwargs["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": self._thinking_budget_tokens,
                }
                api_kwargs["betas"] = ["interleaved-thinking-2025-05-14"]
            api_kwargs["max_tokens"] = effective_max_tokens

            async with self._client.messages.stream(**api_kwargs) as stream:
                # Stream individual tokens to the client in real time.
                # Thinking deltas (type "thinking_delta") are emitted separately
                # so the frontend can render them in a collapsible panel.
                async for chunk in stream:
                    if chunk.type == "content_block_delta":
                        delta = chunk.delta
                        if delta.type == "text_delta":
                            yield TextDeltaEvent(text=delta.text)
                        elif enable_thinking and delta.type == "thinking_delta":
                            yield ThinkingDeltaEvent(thinking=delta.thinking)

                # Get the complete final message to read stop_reason and all
                # content blocks (text, thinking + signature, tool_use).
                final_message = await stream.get_final_message()
                stop_reason = final_message.stop_reason

            # Reconstruct the full assistant content block list for the message
            # history.  The Anthropic API requires that all block types (thinking,
            # text, tool_use) appear together in a single assistant message and
            # that thinking blocks carry their original ``signature`` field.
            assistant_content: list[dict[str, Any]] = []
            for block in final_message.content:
                if block.type == "thinking":
                    # Preserve the signature — required for multi-turn thinking
                    assistant_content.append(
                        {
                            "type": "thinking",
                            "thinking": block.thinking,
                            "signature": block.signature,
                        }
                    )
                elif block.type == "text":
                    if block.text:
                        assistant_content.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    tool_use_blocks.append(
                        {"id": block.id, "name": block.name, "input": block.input}
                    )
                    assistant_content.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )
            messages.append({"role": "assistant", "content": assistant_content})

            # If Claude is done (or produced no tool calls), exit the loop
            if stop_reason == "end_turn" or not tool_use_blocks:
                break

            # Dispatch each tool call and collect results for the next turn
            tool_results: list[dict[str, Any]] = []
            for tb in tool_use_blocks:
                raw_result = await self._tools.dispatch(tb["name"], tb["input"])

                # Build a concise human-readable summary for the ToolUseEvent
                try:
                    parsed = json.loads(raw_result)
                    if isinstance(parsed, list):
                        summary = f"Returned {len(parsed)} item(s)"
                    elif isinstance(parsed, dict) and "error" in parsed:
                        summary = f"Error: {parsed['error']}"
                    elif parsed is None:
                        summary = "No result found"
                    else:
                        summary = f"Returned resource: {parsed.get('resource_type', 'node')}"
                except Exception:
                    summary = "Result received"

                yield ToolUseEvent(
                    tool_name=tb["name"],
                    tool_input=tb["input"],
                    tool_result_summary=summary,
                )
                # Append the tool result for the next Anthropic API call
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb["id"],
                        "content": raw_result,
                    }
                )

            # The tool results are returned as the next user turn
            messages.append({"role": "user", "content": tool_results})

        else:
            # for…else fires only when the loop was *not* broken by a normal exit
            logger.warning(
                "Agent reached max tool rounds (%d) for conversation of %d messages",
                self._MAX_TOOL_ROUNDS,
                len(messages),
            )

    async def _cache_result(self, node_id: str, result: AnalysisResult) -> None:
        """
        Persist the ``AnalysisResult`` to the corresponding Neo4j node.

        Writes two properties atomically with a single ``SET`` statement:

        - ``agent_analysis`` — full ``model_dump()`` JSON string
        - ``agent_analyzed_at`` — ISO 8601 UTC timestamp

        A subsequent ``GET /agent/findings/{node_id}/analysis`` call reads
        ``agent_analysis`` and calls ``AnalysisResult.model_validate()`` to
        reconstruct the typed object without re-running the agent.

        Args:
            node_id: The node to update.  Must already exist in the graph
                (the pre-flight check in ``analyze_finding`` guarantees this).
            result: The completed ``AnalysisResult`` to persist.
        """
        props = result.to_neo4j_props()
        cypher = """
        MATCH (n {node_id: $node_id})
        SET n.agent_analysis = $agent_analysis,
            n.agent_analyzed_at = $agent_analyzed_at
        """
        await self._neo4j.execute(
            cypher,
            {
                "node_id": node_id,
                "agent_analysis": props["agent_analysis"],
                "agent_analyzed_at": props["agent_analyzed_at"],
            },
        )
        logger.info(
            "Cached analysis (score=%d, steps=%d) for node %s",
            result.priority_score,
            len(result.remediation_steps),
            node_id,
        )
