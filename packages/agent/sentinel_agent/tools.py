"""
AgentTools: Graph query tools exposed to the LLM.

This module provides the four Cypher-backed tools that ``SentinelAgent``
makes available to Claude during a tool-use loop, plus the Anthropic JSON
schema definitions (``TOOL_SCHEMAS``) that describe those tools to the API.

Tool inventory
--------------
.. list-table::
   :header-rows: 1

   * - Tool
     - Purpose
     - Typical use
   * - ``get_resource``
     - Fetch all properties of one node by ``node_id``
     - First call in every analysis — understand the flagged resource
   * - ``get_neighbors``
     - Walk the graph up to *depth* hops from a node
     - Blast-radius assessment: what else could be compromised?
   * - ``find_attack_paths``
     - Run three targeted attack-path queries in parallel
     - Exploitability: open SGs, public exposure, IAM escalation
   * - ``query_graph``
     - Execute an arbitrary read-only Cypher query
     - Custom analysis not covered by the above three

Cypher safety guard
-------------------
``query_graph`` accepts free-form Cypher from the LLM, so it applies a
two-stage guard before executing anything:

1. **Whitelist** (``_ALLOWED_KEYWORDS``) — the query must begin with
   ``MATCH``, ``WITH``, ``RETURN``, ``CALL``, ``UNWIND``, or
   ``OPTIONAL MATCH``.  Anything else (``CREATE``, ``DROP`` …) is rejected
   before the blacklist is even checked.

2. **Blacklist** (``_WRITE_KEYWORDS``) — even if the query starts correctly,
   any occurrence of ``CREATE / MERGE / SET / DELETE / DETACH / DROP /
   REMOVE / FOREACH`` anywhere in the string is blocked.

3. **Auto-LIMIT** — if no ``LIMIT N`` clause is present the guard appends
   ``LIMIT 50`` so the agent can never pull an unbounded result set.

These checks are deliberately conservative.  The agent is told to only write
``MATCH … RETURN …`` queries; the guard is a defence-in-depth measure.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from sentinel_core.graph.client import Neo4jClient

logger = logging.getLogger(__name__)

# ── Cypher safety guard ────────────────────────────────────────────────────────

# Stage 1: the first non-whitespace word must be one of these read-only keywords.
_ALLOWED_KEYWORDS = re.compile(
    r"^\s*(MATCH|WITH|RETURN|CALL|UNWIND|OPTIONAL\s+MATCH|EXPLAIN|PROFILE)",
    re.IGNORECASE | re.MULTILINE,
)

# Stage 2: none of these write keywords may appear anywhere in the query.
_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH|DROP|REMOVE|FOREACH)\b",
    re.IGNORECASE,
)

# Used to detect whether the query already has an explicit LIMIT clause.
_LIMIT_PATTERN = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)


def _safe_cypher(cypher: str) -> str:
    """
    Validate a Cypher query and inject ``LIMIT 50`` if missing.

    This is the single entry point for all LLM-supplied Cypher.  It applies
    the whitelist → blacklist → auto-LIMIT pipeline described in the module
    docstring.

    Args:
        cypher: The raw Cypher string received from the LLM.

    Returns:
        The (potentially modified) Cypher string, safe to execute.

    Raises:
        ValueError: If the query does not start with an allowed read keyword,
            or if it contains any write keyword.

    Examples::

        # Valid — passes both checks; LIMIT injected
        _safe_cypher("MATCH (n:S3Bucket) RETURN n")
        # → "MATCH (n:S3Bucket) RETURN n\\nLIMIT 50"

        # Invalid start keyword
        _safe_cypher("CREATE (n) RETURN n")
        # → ValueError: "Query must start with a read keyword …"

        # Sneaky write inside a MATCH
        _safe_cypher("MATCH (n) SET n.x = 1 RETURN n")
        # → ValueError: "Write operations … are not permitted …"
    """
    stripped = cypher.strip()

    # Stage 1: whitelist
    if not _ALLOWED_KEYWORDS.match(stripped):
        raise ValueError(
            f"Query must start with a read keyword (MATCH/WITH/RETURN/CALL/UNWIND). "
            f"Got: {stripped[:60]!r}"
        )

    # Stage 2: blacklist
    if _WRITE_KEYWORDS.search(stripped):
        raise ValueError(
            "Write operations (CREATE/MERGE/SET/DELETE/DETACH/DROP/REMOVE/FOREACH) "
            "are not permitted in agent queries."
        )

    # Auto-LIMIT: strip trailing semicolons first, then append
    if not _LIMIT_PATTERN.search(stripped):
        stripped = stripped.rstrip(";").rstrip()
        stripped = stripped + "\nLIMIT 50"

    return stripped


# ── Tool implementations ───────────────────────────────────────────────────────


class AgentTools:
    """
    Graph query tools available to the LLM agent during a tool-use loop.

    Each public method corresponds to one entry in ``TOOL_SCHEMAS``.  The
    ``dispatch()`` method routes incoming ``tool_use`` blocks from Claude to
    the correct method by name and serialises the return value to JSON.

    All methods return plain Python dicts or lists — no Neo4j driver objects —
    so they can be JSON-serialised and passed back to Claude as
    ``tool_result`` content blocks.

    Args:
        client: Connected ``Neo4jClient`` instance, injected by the agent.
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client

    async def get_resource(self, node_id: str) -> dict[str, Any] | None:
        """
        Fetch the full property set of a single graph node.

        Intended as the first tool call in every analysis run — gives Claude
        the raw configuration data (region, account, resource-specific fields,
        posture flags) for the node under investigation.

        Args:
            node_id: The unique ``node_id`` property stored on the node.

        Returns:
            A plain dict of all node properties, or ``None`` if the node does
            not exist in the graph.
        """
        cypher = "MATCH (n {node_id: $node_id}) RETURN n LIMIT 1"
        results = await self._client.query(cypher, {"node_id": node_id})
        if not results:
            return None
        row = results[0]
        # The Neo4j driver wraps the node under the RETURN alias 'n'.
        # Fall back to the whole row dict if the alias is absent.
        node_data = row.get("n", row)
        return dict(node_data)

    async def get_neighbors(self, node_id: str, depth: int = 2) -> list[dict[str, Any]]:
        """
        Return all nodes reachable within ``depth`` hops from the given node.

        Useful for blast-radius assessment: if this resource is compromised,
        what else could an attacker reach?  Results include each neighbour's
        ``node_id``, ``resource_type``, ``posture_flags``, and the list of
        relationship types traversed to reach it.

        Args:
            node_id: The unique ``node_id`` of the starting node.
            depth: Number of hops to traverse.  Clamped to the range [1, 4]
                to prevent queries that walk the entire graph.

        Returns:
            List of neighbour dicts, at most 50 rows.
        """
        # Hard clamp prevents runaway variable-length path traversals
        depth = max(1, min(depth, 4))
        cypher = f"""
        MATCH path = (start {{node_id: $node_id}})-[*1..{depth}]-(neighbor)
        RETURN
            neighbor.node_id AS node_id,
            neighbor.resource_type AS resource_type,
            neighbor.posture_flags AS posture_flags,
            [r IN relationships(path) | type(r)] AS relationship_types
        LIMIT 50
        """
        results = await self._client.query(cypher, {"node_id": node_id})
        return [dict(r) for r in results]

    async def find_attack_paths(self, node_id: str) -> list[dict[str, Any]]:
        """
        Identify potential attack paths involving this node.

        Runs three separate Cypher queries in sequence and combines results:

        1. **Open-ingress security groups** — finds any ``SecurityGroup``
           connected via ``MEMBER_OF_SG`` that carries ``SG_OPEN_SSH``,
           ``SG_OPEN_RDP``, or ``SG_OPEN_ALL_INGRESS`` posture flags.
           These represent direct internet exposure of the compute/data tier.

        2. **Public exposure** — checks whether the node itself is flagged
           ``publicly_accessible = true`` or ``is_public = true``.  Applies
           to RDS instances, S3 buckets, and similar.

        3. **IAM privilege escalation** — follows ``CAN_ASSUME`` chains up to
           3 hops to find ``IAMRole`` nodes with ``IAM_STAR_POLICY``.  A
           compromised resource that can assume a wildcard-policy role gives
           an attacker full account-level blast radius.

        Args:
            node_id: The unique ``node_id`` of the resource to analyse.

        Returns:
            Combined list of attack-path result dicts.  Each dict includes a
            ``path_type`` discriminator field (``"open_ingress"``,
            ``"public_exposure"``, or ``"privilege_escalation"``).
        """
        results: list[dict[str, Any]] = []

        # --- Attack path 1: Open ingress security groups ---
        # Any SG with a wide-open inbound rule that is attached to this node
        # creates a direct internet → node exposure path.
        sg_cypher = """
        MATCH (n {node_id: $node_id})-[:MEMBER_OF_SG]->(sg:SecurityGroup)
        WHERE any(flag IN sg.posture_flags WHERE flag IN [
            'SG_OPEN_SSH', 'SG_OPEN_RDP', 'SG_OPEN_ALL_INGRESS'
        ])
        RETURN
            'open_ingress' AS path_type,
            sg.node_id AS sg_node_id,
            sg.group_id AS sg_id,
            sg.posture_flags AS flags
        LIMIT 10
        """
        sg_results = await self._client.query(sg_cypher, {"node_id": node_id})
        results.extend([dict(r) for r in sg_results])

        # --- Attack path 2: Direct public exposure ---
        # Some resources (RDS, S3) carry an explicit public-accessibility flag.
        # If set, the resource is reachable without traversing a security group.
        public_cypher = """
        MATCH (n {node_id: $node_id})
        WHERE n.publicly_accessible = true OR n.is_public = true
        RETURN
            'public_exposure' AS path_type,
            n.node_id AS exposed_node_id,
            n.resource_type AS resource_type,
            n.posture_flags AS flags
        LIMIT 5
        """
        public_results = await self._client.query(public_cypher, {"node_id": node_id})
        results.extend([dict(r) for r in public_results])

        # --- Attack path 3: IAM privilege escalation ---
        # A CAN_ASSUME chain to a role with wildcard actions means any entity
        # that can assume this node's role (directly or transitively) can
        # escalate to full account control.
        iam_cypher = """
        MATCH path = (n {node_id: $node_id})-[:CAN_ASSUME*1..3]->(target:IAMRole)
        WHERE 'IAM_STAR_POLICY' IN target.posture_flags
        RETURN
            'privilege_escalation' AS path_type,
            target.node_id AS target_node_id,
            target.role_name AS role_name,
            length(path) AS hops
        LIMIT 10
        """
        iam_results = await self._client.query(iam_cypher, {"node_id": node_id})
        results.extend([dict(r) for r in iam_results])

        return results

    async def query_graph(
        self, cypher: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute a custom read-only Cypher query against the security graph.

        This is the most powerful tool available to the agent — it allows
        arbitrary graph traversal for analysis scenarios not covered by the
        three dedicated methods above.  However, the Cypher safety guard in
        ``_safe_cypher()`` enforces read-only access: write keywords are
        blocked and a ``LIMIT 50`` is auto-injected if absent.

        Neo4j node objects in the result are flattened to plain dicts before
        returning, so the result is always directly JSON-serialisable.

        Args:
            cypher: A read-only Cypher query string.
            params: Optional named parameters (``$name`` style).

        Returns:
            List of record dicts, at most 50 rows.

        Raises:
            ValueError: If ``cypher`` fails the safety guard checks.
        """
        safe = _safe_cypher(cypher)
        logger.debug("Agent query_graph: %s", safe[:120])
        results = await self._client.query(safe, params or {})

        # Flatten any Neo4j node/relationship objects to plain dicts.
        # The driver may return rich objects with a ``_properties`` attribute
        # rather than bare dicts, depending on the query return shape.
        flat: list[dict[str, Any]] = []
        for row in results:
            flat_row: dict[str, Any] = {}
            for k, v in row.items():
                if hasattr(v, "_properties"):
                    flat_row[k] = dict(v._properties)
                elif hasattr(v, "items"):
                    flat_row[k] = dict(v)
                else:
                    flat_row[k] = v
            flat.append(flat_row)
        return flat

    async def dispatch(self, name: str, tool_input: dict[str, Any]) -> str:
        """
        Route a ``tool_use`` block from Claude to the correct method.

        Called by ``SentinelAgent._run_tool_loop()`` for every ``tool_use``
        content block in Claude's response.  Returns a JSON string suitable
        for use as the ``content`` field of a ``tool_result`` message block.

        All exceptions are caught and serialised as ``{"error": "..."}`` so
        the agent loop never raises — Claude sees the error text and can
        decide how to proceed.

        Args:
            name: Tool name matching one of the four ``TOOL_SCHEMAS`` entries.
            tool_input: The ``input`` dict extracted from Claude's tool block.

        Returns:
            JSON string.  On success: the serialised tool result.
            On failure: ``'{"error": "..."}'``.
        """
        try:
            if name == "get_resource":
                result = await self.get_resource(tool_input["node_id"])
                return json.dumps(result)
            elif name == "get_neighbors":
                result = await self.get_neighbors(
                    tool_input["node_id"],
                    depth=tool_input.get("depth", 2),
                )
                return json.dumps(result)
            elif name == "find_attack_paths":
                result = await self.find_attack_paths(tool_input["node_id"])
                return json.dumps(result)
            elif name == "query_graph":
                result = await self.query_graph(
                    tool_input["cypher"],
                    tool_input.get("params"),
                )
                return json.dumps(result)
            else:
                return json.dumps({"error": f"Unknown tool: {name}"})
        except ValueError as e:
            # Safety guard violations — return as error, do not raise
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.exception("Tool %s failed", name)
            return json.dumps({"error": f"Tool execution failed: {e}"})


# ── Anthropic tool schemas ─────────────────────────────────────────────────────

#: Anthropic-format tool schemas passed directly to ``client.messages.stream(tools=…)``.
#:
#: Each entry follows the ``{"name", "description", "input_schema"}`` shape
#: required by the Anthropic tool-use API.  The description text is shown to
#: Claude to help it decide *when* to call each tool; the ``input_schema``
#: (JSON Schema) validates the tool's input at the API level.
TOOL_SCHEMAS: list[dict] = [
    {
        "name": "get_resource",
        "description": (
            "Fetch the full properties of a single AWS resource node from the security graph "
            "by its node_id. Returns resource type, posture flags, configuration attributes, "
            "region, account ID, and all other stored properties."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {
                    "type": "string",
                    "description": "The unique node_id of the resource to fetch.",
                }
            },
            "required": ["node_id"],
        },
    },
    {
        "name": "get_neighbors",
        "description": (
            "Return all nodes connected to the given resource within `depth` hops. "
            "Use this to understand the blast radius of a finding — what other resources "
            "could be affected if this node is compromised."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {
                    "type": "string",
                    "description": "The unique node_id of the starting resource.",
                },
                "depth": {
                    "type": "integer",
                    "description": "Number of hops to traverse (1-4, default 2).",
                    "minimum": 1,
                    "maximum": 4,
                    "default": 2,
                },
            },
            "required": ["node_id"],
        },
    },
    {
        "name": "find_attack_paths",
        "description": (
            "Find potential attack paths involving this node: open-ingress security groups, "
            "public exposure, and IAM privilege escalation chains. "
            "Use this to assess exploitability and real-world risk."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {
                    "type": "string",
                    "description": "The unique node_id of the resource to analyze.",
                }
            },
            "required": ["node_id"],
        },
    },
    {
        "name": "query_graph",
        "description": (
            "Execute a custom read-only Cypher query against the security graph. "
            "Only MATCH/WITH/RETURN/CALL/UNWIND statements are permitted. "
            "A LIMIT 50 is automatically applied. Use this for custom analysis "
            "not covered by the other tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": "A read-only Cypher query (MATCH ... RETURN ...).",
                },
                "params": {
                    "type": "object",
                    "description": "Optional named parameters for the query ($param style).",
                },
            },
            "required": ["cypher"],
        },
    },
]
