"""
Agent router: LLM-powered security analysis endpoints.

This router bridges the FastAPI HTTP layer and the ``SentinelAgent`` streaming
core.  It handles three concerns that the agent itself doesn't touch:

1. **HTTP I/O** — accepts requests, validates path/query parameters, returns
   ``StreamingResponse`` or JSON, raises ``HTTPException`` on errors.
2. **SSE framing** — ``_stream_events()`` consumes the agent's async iterator
   of ``SSEEvent`` objects and encodes them as ``text/event-stream`` bytes,
   appending the mandatory ``data: [DONE]\\n\\n`` sentinel when the iterator
   is exhausted.
3. **Cache reads** — ``GET /analysis`` reads ``n.agent_analysis`` from Neo4j
   directly (no agent involved) and validates it back into an ``AnalysisResult``
   Pydantic model for typed JSON serialisation.

Endpoints
---------
``POST /api/v1/agent/findings/{node_id}/analyze``
    Triggers a new agent analysis.  Resolves the node's ``account_id`` from
    Neo4j, then streams SSE events until the agent yields
    ``AnalysisCompleteEvent``.  The result is automatically cached by the
    agent on the Neo4j node.

``GET /api/v1/agent/findings/{node_id}/analysis``
    Returns the most recently cached ``AnalysisResult`` for a node as JSON.
    Returns HTTP 404 if no analysis has ever been run for this node.

``POST /api/v1/agent/brief``
    Streams an executive security brief across the top-N findings for an
    account.  Accepts optional ``account_id`` and ``top_n`` query parameters.
    Falls back to the first account found in the graph if ``account_id`` is
    omitted.

SSE wire format
---------------
Every event line follows the ``text/event-stream`` spec::

    data: {"event": "text_delta", "text": "..."}\n\n
    data: {"event": "tool_use", "tool_name": "...", ...}\n\n
    data: {"event": "analysis_complete", "result": {...}}\n\n
    data: [DONE]\n\n

The ``X-Accel-Buffering: no`` header disables response buffering in nginx
proxies, ensuring tokens reach the browser immediately.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from sentinel_agent.models import AnalysisResult
from sentinel_api.deps import AgentDep, Neo4jDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

# Headers required for a well-behaved SSE response:
# - Content-Type: text/event-stream — tells the browser this is an event stream
# - Cache-Control: no-cache — prevents intermediaries from caching partial streams
# - X-Accel-Buffering: no — disables nginx proxy buffering so tokens flow immediately
_SSE_HEADERS = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
}


async def _stream_events(agent_gen) -> AsyncGenerator[bytes, None]:
    """
    Adapt an ``SSEEvent`` async iterator into raw SSE bytes.

    Wraps the agent generator so that:
    - Normal events are encoded via their ``to_sse()`` method.
    - Any exception that escapes the generator is caught, logged, and emitted
      as an ``{"event": "error"}`` line rather than crashing the HTTP response
      mid-stream (which would leave the client hanging).
    - The ``data: [DONE]\\n\\n`` sentinel is always emitted last, regardless
      of success or failure, so the client's ``ReadableStream`` terminates.

    Args:
        agent_gen: An async iterator of ``SSEEvent`` objects from
            ``SentinelAgent.analyze_finding()`` or ``generate_brief()``.

    Yields:
        Raw bytes for each SSE event line.
    """
    try:
        async for event in agent_gen:
            yield event.to_sse().encode()
    except Exception as e:
        logger.exception("Agent stream error")
        error_data = json.dumps({"event": "error", "message": str(e)})
        yield f"data: {error_data}\n\n".encode()
    finally:
        # Always close the stream cleanly so the client's event-source terminates
        yield b"data: [DONE]\n\n"


@router.post(
    "/findings/{node_id}/analyze",
    summary="Analyze a finding with AI",
    description=(
        "Trigger a streaming LLM security analysis for a specific finding node.\n\n"
        "The agent autonomously queries the graph (blast radius, attack paths, resource "
        "configuration) and streams back its reasoning token-by-token via Server-Sent Events.\n\n"
        "**SSE event types emitted:**\n"
        "- `text_delta` — streamed text tokens from Claude\n"
        "- `tool_use` — graph tool invocation with result summary\n"
        "- `analysis_complete` — final structured AnalysisResult\n"
        "- `error` — non-recoverable failure\n\n"
        "The analysis result is cached on the Neo4j node so subsequent `GET /analysis` "
        "requests do not re-run the agent.\n\n"
        "Pass `?thinking=true` to enable extended thinking mode — Claude will emit its "
        "internal reasoning as `thinking_delta` SSE events before producing the analysis."
    ),
)
async def analyze_finding(
    node_id: str,
    agent: AgentDep,
    neo4j: Neo4jDep,
    thinking: bool = False,
) -> StreamingResponse:
    """
    Start an AI analysis for a security finding and stream the result.

    Args:
        node_id: URL path parameter — the unique graph node identifier.
        agent: Injected ``SentinelAgent`` instance (via ``AgentDep``).
        neo4j: Injected ``Neo4jClient`` used to resolve the node's account.

    Returns:
        ``StreamingResponse`` with ``Content-Type: text/event-stream``.

    Raises:
        HTTPException 404: If the ``node_id`` is not present in the graph.
    """
    # Resolve account_id from the node — the agent prompt needs it but the
    # router receives only node_id from the URL path.
    result = await neo4j.query(
        "MATCH (n {node_id: $node_id}) RETURN n.account_id AS account_id LIMIT 1",
        {"node_id": node_id},
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    account_id = result[0].get("account_id") or "unknown"

    return StreamingResponse(
        _stream_events(agent.analyze_finding(node_id, account_id, enable_thinking=thinking)),
        headers=_SSE_HEADERS,
    )


@router.get(
    "/findings/{node_id}/analysis",
    response_model=AnalysisResult,
    summary="Get cached AI analysis",
    description=(
        "Return the most recently cached `AnalysisResult` for a finding node.\n\n"
        "Returns HTTP **404** if no analysis has been run yet for this node — "
        "use `POST /agent/findings/{node_id}/analyze` to trigger one.\n\n"
        "The cached result is read from the `agent_analysis` property stored on the "
        "Neo4j node during the last agent run."
    ),
)
async def get_cached_analysis(
    node_id: str,
    neo4j: Neo4jDep,
) -> AnalysisResult:
    """
    Return the cached AnalysisResult for a node, or 404 if none exists.

    Args:
        node_id: URL path parameter — the unique graph node identifier.
        neo4j: Injected ``Neo4jClient`` for the cache read query.

    Returns:
        Validated ``AnalysisResult`` Pydantic model.

    Raises:
        HTTPException 404: Node not found or no analysis cached yet.
        HTTPException 500: Cached JSON is present but fails validation.
    """
    result = await neo4j.query(
        "MATCH (n {node_id: $node_id}) RETURN n.agent_analysis AS analysis LIMIT 1",
        {"node_id": node_id},
    )
    if not result or not result[0].get("analysis"):
        raise HTTPException(
            status_code=404,
            detail=(
                f"No analysis cached for node '{node_id}'. "
                f"Run POST /agent/findings/{node_id}/analyze first."
            ),
        )

    raw = result[0]["analysis"]
    try:
        # The value may already be a dict (Neo4j JSON type) or a JSON string
        data = json.loads(raw) if isinstance(raw, str) else raw
        return AnalysisResult.model_validate(data)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse cached analysis: {e}",
        ) from e


@router.post(
    "/brief",
    summary="Generate executive security brief",
    description=(
        "Stream an AI-generated executive security brief covering the top-N most severe "
        "findings for an AWS account.\n\n"
        "Accepts optional query parameters:\n"
        "- `account_id` — scopes the brief to a specific account; defaults to the first "
        "account found in the graph\n"
        "- `top_n` — number of findings to include (1–20, default 5)\n\n"
        "Uses the same SSE event format as `POST /agent/findings/{node_id}/analyze`.\n\n"
        "**Note:** Brief results are not cached — each call triggers a new agent run."
    ),
)
async def generate_brief(
    agent: AgentDep,
    neo4j: Neo4jDep,
    account_id: str | None = None,
    top_n: int = 5,
    thinking: bool = False,
) -> StreamingResponse:
    """
    Stream an executive security brief for an account's top-N findings.

    Args:
        agent: Injected ``SentinelAgent`` instance.
        neo4j: Injected ``Neo4jClient`` used to resolve the default account.
        account_id: Optional query parameter.  If omitted, the first account
            found in the graph is used.
        top_n: Number of findings to include in the brief (clamped to [1, 20]).

    Returns:
        ``StreamingResponse`` with ``Content-Type: text/event-stream``.

    Raises:
        HTTPException 404: No accounts found in the graph (scan has not run).
    """
    if not account_id:
        # Discover the first account present in the graph as a sensible default
        result = await neo4j.query(
            "MATCH (n:GraphNode) WHERE n.account_id IS NOT NULL "
            "RETURN n.account_id AS account_id LIMIT 1"
        )
        if not result:
            raise HTTPException(
                status_code=404,
                detail="No accounts found in graph. Run a scan first.",
            )
        account_id = result[0]["account_id"]

    # Verify findings exist for the account before starting the stream
    findings_check = await neo4j.query(
        "MATCH (n:GraphNode) WHERE n.account_id = $account_id AND size(n.posture_flags) > 0 "
        "RETURN count(n) AS cnt",
        {"account_id": account_id},
    )
    if not findings_check or findings_check[0].get("cnt", 0) == 0:
        raise HTTPException(
            status_code=404,
            detail=f"No findings for account '{account_id}'. Run a scan first.",
        )

    # Guard against unreasonably large briefs that would time out
    top_n = max(1, min(top_n, 20))

    return StreamingResponse(
        _stream_events(agent.generate_brief(account_id, top_n, enable_thinking=thinking)),
        headers=_SSE_HEADERS,
    )
