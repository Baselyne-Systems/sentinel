"""
Unit tests for ``sentinel_agent.tools``.

Coverage
--------
``TestSafeCypher``
    Validates the two-stage Cypher safety guard in ``_safe_cypher()``:

    - Whitelist stage: queries must begin with a read keyword
      (MATCH / WITH / RETURN / CALL / UNWIND / OPTIONAL MATCH).
      Queries starting with write keywords (CREATE, DROP, FOREACH …) are
      rejected with ``ValueError("Query must start with a read keyword …")``.

    - Blacklist stage: even valid-starting queries are rejected if they contain
      any write keyword (SET, MERGE, DELETE, DETACH, REMOVE …) anywhere in
      the string.  Raises ``ValueError("Write operations … are not permitted")``.

    - Auto-LIMIT: a ``LIMIT 50`` clause is appended when the query has no
      existing ``LIMIT N``.  Trailing semicolons are stripped before appending.

``TestGetResource``
    Verifies that ``AgentTools.get_resource()`` correctly unwraps the ``"n"``
    alias key returned by the Neo4j driver and returns ``None`` for missing nodes.

``TestGetNeighbors``
    Verifies depth clamping ([1, 4]) and that the clamped depth is embedded in
    the Cypher string passed to the driver.

``TestFindAttackPaths``
    Verifies that the three sub-queries (open SG, public exposure, IAM
    escalation) are combined in a single result list and classified correctly
    via the ``path_type`` discriminator.

``TestQueryGraph``
    Confirms that valid read queries execute and that write queries (passing
    the whitelist but failing the blacklist) raise ``ValueError``.

``TestDispatch``
    Confirms that ``dispatch()`` routes by name, serialises results as JSON,
    and returns ``{"error": …}`` for unknown tools or safety violations.

``TestToolSchemas``
    Structural check: exactly 4 tools, each with ``name``, ``description``,
    and ``input_schema``.

All tests use ``AsyncMock`` for the Neo4j client — no real database required.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel_agent.tools import AgentTools, _safe_cypher, TOOL_SCHEMAS


# ── Cypher safety guard tests ──────────────────────────────────────────────────


class TestSafeCypher:
    def test_valid_match_query_passes(self):
        q = "MATCH (n:S3Bucket) RETURN n"
        result = _safe_cypher(q)
        assert "MATCH" in result

    def test_auto_limit_injected_when_missing(self):
        q = "MATCH (n) RETURN n"
        result = _safe_cypher(q)
        assert "LIMIT 50" in result

    def test_existing_limit_not_doubled(self):
        q = "MATCH (n) RETURN n LIMIT 10"
        result = _safe_cypher(q)
        assert result.count("LIMIT") == 1
        assert "LIMIT 10" in result

    def test_create_blocked(self):
        # CREATE doesn't start with a read keyword → fails whitelist check
        with pytest.raises(ValueError, match="must start with a read keyword"):
            _safe_cypher("CREATE (n:Test {x: 1}) RETURN n")

    def test_merge_blocked(self):
        with pytest.raises(ValueError, match="Write operations"):
            _safe_cypher("MATCH (n) MERGE (n)-[:R]->(m) RETURN n")

    def test_set_blocked(self):
        with pytest.raises(ValueError, match="Write operations"):
            _safe_cypher("MATCH (n {node_id: 'x'}) SET n.flag = true")

    def test_delete_blocked(self):
        with pytest.raises(ValueError, match="Write operations"):
            _safe_cypher("MATCH (n) DELETE n")

    def test_detach_delete_blocked(self):
        with pytest.raises(ValueError, match="Write operations"):
            _safe_cypher("MATCH (n) DETACH DELETE n")

    def test_drop_blocked(self):
        # DROP doesn't start with a read keyword → fails whitelist check
        with pytest.raises(ValueError, match="must start with a read keyword"):
            _safe_cypher("DROP INDEX node_id_idx")

    def test_query_not_starting_with_match_blocked(self):
        # Something that clearly starts with no allowed keyword
        with pytest.raises(ValueError, match="must start with a read keyword"):
            _safe_cypher("FOREACH (x IN [1,2,3] | CREATE (n:Test))")

    def test_with_return_allowed(self):
        q = "MATCH (n) WITH n RETURN n"
        result = _safe_cypher(q)
        assert "LIMIT 50" in result

    def test_optional_match_allowed(self):
        q = "OPTIONAL MATCH (n) RETURN n"
        result = _safe_cypher(q)
        assert "LIMIT 50" in result

    def test_semicolon_stripped_before_limit(self):
        q = "MATCH (n) RETURN n;"
        result = _safe_cypher(q)
        assert result.endswith("LIMIT 50")
        assert ";" not in result


# ── AgentTools tests ───────────────────────────────────────────────────────────


def _make_mock_client(query_return=None, execute_return=None):
    """Build a mock Neo4jClient."""
    client = MagicMock()
    client.query = AsyncMock(return_value=query_return or [])
    client.execute = AsyncMock(return_value=execute_return)
    return client


class TestGetResource:
    @pytest.mark.asyncio
    async def test_returns_node_dict_when_found(self):
        node_data = {"resource_type": "S3Bucket", "node_id": "s3-test", "posture_flags": ["S3_PUBLIC_ACL"]}
        client = _make_mock_client(query_return=[{"n": node_data}])
        tools = AgentTools(client)
        result = await tools.get_resource("s3-test")
        assert result is not None
        assert result.get("resource_type") == "S3Bucket" or result == node_data

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        client = _make_mock_client(query_return=[])
        tools = AgentTools(client)
        result = await tools.get_resource("nonexistent")
        assert result is None


class TestGetNeighbors:
    @pytest.mark.asyncio
    async def test_returns_list_of_neighbors(self):
        rows = [
            {"node_id": "sg-1", "resource_type": "SecurityGroup", "posture_flags": [], "relationship_types": ["MEMBER_OF_SG"]},
        ]
        client = _make_mock_client(query_return=rows)
        tools = AgentTools(client)
        result = await tools.get_neighbors("ec2-1", depth=2)
        assert len(result) == 1
        assert result[0]["node_id"] == "sg-1"

    @pytest.mark.asyncio
    async def test_depth_clamped_to_max_4(self):
        client = _make_mock_client(query_return=[])
        tools = AgentTools(client)
        # Should not raise even with excessive depth
        await tools.get_neighbors("node", depth=100)
        call_args = client.query.call_args[0][0]
        # The Cypher should have depth clamped to 4
        assert "*1..4" in call_args

    @pytest.mark.asyncio
    async def test_depth_clamped_to_min_1(self):
        client = _make_mock_client(query_return=[])
        tools = AgentTools(client)
        await tools.get_neighbors("node", depth=0)
        call_args = client.query.call_args[0][0]
        assert "*1..1" in call_args


class TestFindAttackPaths:
    @pytest.mark.asyncio
    async def test_returns_combined_results(self):
        # First call (open SG), second call (public exposure), third call (IAM)
        client = _make_mock_client()
        client.query = AsyncMock(
            side_effect=[
                [{"path_type": "open_ingress", "sg_node_id": "sg-1", "flags": ["SG_OPEN_SSH"]}],
                [{"path_type": "public_exposure", "exposed_node_id": "rds-1"}],
                [],
            ]
        )
        tools = AgentTools(client)
        result = await tools.find_attack_paths("rds-1")
        assert len(result) == 2
        path_types = {r["path_type"] for r in result}
        assert "open_ingress" in path_types
        assert "public_exposure" in path_types


class TestQueryGraph:
    @pytest.mark.asyncio
    async def test_valid_query_executes(self):
        rows = [{"n": {"node_id": "x"}}]
        client = _make_mock_client(query_return=rows)
        tools = AgentTools(client)
        result = await tools.query_graph("MATCH (n) RETURN n")
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_write_query_raises_value_error(self):
        # A SET inside a MATCH trips the blacklist (passes whitelist)
        client = _make_mock_client()
        tools = AgentTools(client)
        with pytest.raises(ValueError, match="Write operations"):
            await tools.query_graph("MATCH (n) SET n.x = 1 RETURN n")


class TestDispatch:
    @pytest.mark.asyncio
    async def test_dispatch_get_resource(self):
        client = _make_mock_client(query_return=[{"n": {"resource_type": "EC2Instance", "node_id": "i-1"}}])
        tools = AgentTools(client)
        raw = await tools.dispatch("get_resource", {"node_id": "i-1"})
        data = json.loads(raw)
        assert data is not None

    @pytest.mark.asyncio
    async def test_dispatch_unknown_tool_returns_error(self):
        client = _make_mock_client()
        tools = AgentTools(client)
        raw = await tools.dispatch("nonexistent_tool", {})
        data = json.loads(raw)
        assert "error" in data
        assert "Unknown tool" in data["error"]

    @pytest.mark.asyncio
    async def test_dispatch_query_graph_with_write_returns_error(self):
        client = _make_mock_client()
        tools = AgentTools(client)
        raw = await tools.dispatch("query_graph", {"cypher": "MERGE (n:Test) RETURN n"})
        data = json.loads(raw)
        assert "error" in data


# ── TOOL_SCHEMAS shape test ────────────────────────────────────────────────────


class TestToolSchemas:
    def test_four_tools_defined(self):
        assert len(TOOL_SCHEMAS) == 4

    def test_all_have_required_fields(self):
        for schema in TOOL_SCHEMAS:
            assert "name" in schema
            assert "description" in schema
            assert "input_schema" in schema

    def test_tool_names(self):
        names = {s["name"] for s in TOOL_SCHEMAS}
        assert names == {"get_resource", "get_neighbors", "find_attack_paths", "query_graph"}
