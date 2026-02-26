"""
Async Neo4j driver wrapper for SENTINEL.

Provides a thin, application-specific layer over the ``neo4j`` Python async driver.
All graph writes go through this client — the rest of the codebase never touches
the driver directly.

Design decisions:
- **MERGE on node_id**: all upserts use ``MERGE (n {node_id: $node_id}) SET n += $props``
  so re-running a scan is safe and idempotent.
- **No ORM**: direct Cypher strings. The graph schema is simple and explicit Cypher
  is easier to reason about than a DSL.
- **Module-level singleton**: the ``Neo4jClient`` instance is held by ``sentinel_api.deps``
  and injected via FastAPI's dependency system. Tests substitute a mock.
- **Bounded concurrency**: callers (GraphBuilder) use ``asyncio.Semaphore`` when
  writing many nodes/edges in parallel to avoid overwhelming the driver.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession

from sentinel_core.models.edges import GraphEdge
from sentinel_core.models.nodes import GraphNode

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Async wrapper around the Neo4j Python async driver.

    Manages a single driver instance and exposes high-level methods for
    node/edge upserts, arbitrary Cypher queries, and administrative operations
    like index creation and account-level data clearing.

    Usage — explicit lifecycle::

        client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="...")
        await client.connect()
        await client.upsert_node(node)
        await client.close()

    Usage — async context manager::

        async with Neo4jClient("bolt://localhost:7687", "neo4j", "pass") as client:
            await client.upsert_node(node)
            results = await client.query("MATCH (n) RETURN count(n) AS n")

    Args:
        uri: Neo4j Bolt URI, e.g. ``bolt://localhost:7687``.
        user: Neo4j username.
        password: Neo4j password.
    """

    def __init__(self, uri: str, user: str, password: str) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Open the Neo4j driver and verify connectivity.

        Raises:
            neo4j.exceptions.ServiceUnavailable: if Neo4j is not reachable.
            neo4j.exceptions.AuthError: if credentials are invalid.
        """
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
        )
        await self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self._uri)

    async def close(self) -> None:
        """Close the driver and release all connections.

        Safe to call even if ``connect()`` was never called.
        """
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    async def __aenter__(self) -> Neo4jClient:
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        """Yield a Neo4j async session.

        Raises:
            RuntimeError: if ``connect()`` has not been called.
        """
        if self._driver is None:
            raise RuntimeError("Neo4jClient not connected. Call connect() first.")
        async with self._driver.session() as session:
            yield session

    # ── Core operations ────────────────────────────────────────────────────────

    async def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a read Cypher query and return all records as dicts.

        Args:
            cypher: A valid Cypher query string.
            params: Named parameters for the query (``$name`` style).

        Returns:
            List of record dicts. Each key corresponds to a ``RETURN`` alias.
            Returns an empty list if no records match.

        Example::

            records = await client.query(
                "MATCH (n:S3Bucket {is_public: $pub}) RETURN n",
                {"pub": True},
            )
        """
        params = params or {}
        async with self._session() as session:
            result = await session.run(cypher, params)
            records = await result.data()
            return records

    async def execute(self, cypher: str, params: dict[str, Any] | None = None) -> None:
        """Execute a write Cypher statement (no return value needed).

        Use this for ``SET``, ``DETACH DELETE``, ``CREATE INDEX``, etc.

        Args:
            cypher: A valid Cypher write statement.
            params: Named parameters for the statement.
        """
        params = params or {}
        async with self._session() as session:
            await session.run(cypher, params)

    async def upsert_node(self, node: GraphNode) -> None:
        """MERGE a node into Neo4j, updating all properties.

        Uses ``MERGE`` on ``node_id`` as the unique key, so this method is
        safe to call multiple times for the same resource — it will update
        rather than duplicate.

        The node's ``neo4j_labels()`` are applied as Neo4j labels.
        All properties from ``to_neo4j_props()`` are set atomically.

        Args:
            node: Any ``GraphNode`` subclass instance to persist.

        Example::

            bucket = S3Bucket(node_id="s3-my-bucket", account_id="123", ...)
            await client.upsert_node(bucket)
        """
        props = node.to_neo4j_props()
        labels = ":".join(node.neo4j_labels())

        cypher = f"""
        MERGE (n:{labels} {{node_id: $node_id}})
        SET n += $props
        """
        async with self._session() as session:
            await session.run(cypher, {"node_id": node.node_id, "props": props})

    async def upsert_edge(self, edge: GraphEdge) -> None:
        """MERGE a directed relationship between two existing nodes.

        Both nodes must already exist (identified by ``node_id``). If either
        node is missing the relationship is silently skipped (logged at DEBUG).

        The relationship type is determined by ``edge.edge_type``.
        All properties from ``edge.to_neo4j_props()`` are set on the relationship.

        Args:
            edge: Any ``GraphEdge`` subclass instance to persist.

        Example::

            edge = InVPC(from_node_id="i-12345", to_node_id="vpc-67890", account_id="123")
            await client.upsert_edge(edge)
        """
        props = edge.to_neo4j_props()
        rel_type = str(edge.edge_type)

        cypher = f"""
        MATCH (a {{node_id: $from_id}})
        MATCH (b {{node_id: $to_id}})
        MERGE (a)-[r:{rel_type}]->(b)
        SET r += $props
        """
        async with self._session() as session:
            result = await session.run(
                cypher,
                {
                    "from_id": edge.from_node_id,
                    "to_id": edge.to_node_id,
                    "props": props,
                },
            )
            summary = await result.consume()
            if summary.counters.relationships_created == 0 and summary.counters.properties_set == 0:
                logger.debug(
                    "Edge %s → %s [%s]: nodes not found or already exists",
                    edge.from_node_id,
                    edge.to_node_id,
                    rel_type,
                )

    async def set_posture_flags(self, node_id: str, flags: list[str]) -> None:
        """Overwrite the ``posture_flags`` property on an existing node.

        Used by the ``PostureEvaluator`` to stamp CIS violations after a scan.
        Replaces the entire list — callers should pass the full desired flag set.

        Args:
            node_id: Unique identifier of the target node.
            flags: Complete list of flag strings to set.
        """
        cypher = """
        MATCH (n {node_id: $node_id})
        SET n.posture_flags = $flags
        """
        async with self._session() as session:
            await session.run(cypher, {"node_id": node_id, "flags": flags})

    async def clear_account(self, account_id: str) -> None:
        """Delete all nodes and their edges for a given AWS account.

        Used before full re-scans when ``clear_first=True`` is set.
        This is a destructive operation — use with care.

        Args:
            account_id: The AWS account ID whose data should be removed.

        Warning:
            This permanently deletes all graph data for the account.
            It cannot be undone without re-running a scan.
        """
        cypher = """
        MATCH (n {account_id: $account_id})
        DETACH DELETE n
        """
        async with self._session() as session:
            await session.run(cypher, {"account_id": account_id})
        logger.info("Cleared all nodes for account %s", account_id)

    async def ensure_indexes(self) -> None:
        """Create Neo4j indexes for common lookup patterns.

        This method is idempotent — safe to call on every startup.
        Creates the following indexes if they don't already exist:

        - ``GraphNode.node_id`` — used for all MERGE/MATCH by ID
        - ``GraphNode.account_id`` — used for account-scoped queries
        - ``GraphNode.resource_type`` — used for type-filtered listings
        - ``GraphNode.posture_flags`` — used for findings queries

        Args:
            None

        Raises:
            neo4j.exceptions.ClientError: if index creation syntax is rejected
                (shouldn't happen with Neo4j 5.x).
        """
        statements = [
            "CREATE INDEX node_id_idx IF NOT EXISTS FOR (n:GraphNode) ON (n.node_id)",
            "CREATE INDEX account_id_idx IF NOT EXISTS FOR (n:GraphNode) ON (n.account_id)",
            "CREATE INDEX resource_type_idx IF NOT EXISTS FOR (n:GraphNode) ON (n.resource_type)",
            "CREATE INDEX posture_flags_idx IF NOT EXISTS FOR (n:GraphNode) ON (n.posture_flags)",
        ]
        async with self._session() as session:
            for stmt in statements:
                await session.run(stmt)
        logger.info("Neo4j indexes ensured")
