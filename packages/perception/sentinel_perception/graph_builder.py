"""
GraphBuilder — orchestrates all AWS discovery and writes to Neo4j.

This is the central orchestration module of the perception engine.
It coordinates:

1. Per-region parallel discovery (EC2, Lambda, RDS)
2. Global service discovery (IAM, S3)
3. Cross-connector edge resolution (Lambda → IAMRole)
4. Bulk Neo4j writes with bounded concurrency
5. Posture evaluation (CIS rule stamping)

Architecture notes:
    All connectors return ``(nodes, edges)`` tuples. The builder accumulates
    these, resolves cross-connector references, then writes everything to
    Neo4j in two passes (nodes first, then edges — so MERGE targets exist).

    boto3 is synchronous; ``asyncio.to_thread`` wraps session creation.
    Connector coroutines use ``run_sync`` internally for their boto3 calls.

    A ``Semaphore(20)`` bounds concurrent Neo4j writes to avoid overwhelming
    the driver's connection pool.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import boto3
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.knowledge.evaluator import Finding, PostureEvaluator
from sentinel_core.models.edges import ExecutesAs, GraphEdge, HasResource
from sentinel_core.models.nodes import AWSAccount, GraphNode, IAMRole, LambdaFunction

from sentinel_perception.connectors.aws import ec2, iam, lambda_, rds, s3
from sentinel_perception.connectors.aws.base import get_session

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Summary of a completed scan job.

    Attributes:
        account_id: AWS account that was scanned.
        regions: List of regions included in the scan.
        nodes_written: Total graph nodes upserted to Neo4j.
        edges_written: Total graph edges upserted to Neo4j.
        findings_count: Number of CIS rule violations found.
        duration_seconds: Wall-clock time for the full scan.
        errors: Non-fatal per-region or per-connector errors encountered.
        findings: Full list of ``Finding`` objects from posture evaluation.
    """

    account_id: str
    regions: list[str]
    nodes_written: int = 0
    edges_written: int = 0
    findings_count: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for the API response.

        Returns:
            Dict with scalar fields only (``findings`` list is excluded
            to keep the response payload small).
        """
        return {
            "account_id": self.account_id,
            "regions": self.regions,
            "nodes_written": self.nodes_written,
            "edges_written": self.edges_written,
            "findings_count": self.findings_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "errors": self.errors,
        }


class GraphBuilder:
    """Orchestrates full and targeted AWS environment discovery.

    Coordinates all AWS connectors, writes results to Neo4j, and triggers
    posture evaluation. Designed to be instantiated once per scan job and
    discarded afterward.

    Args:
        client: Connected ``Neo4jClient`` instance. The caller owns the
            connection lifecycle; ``GraphBuilder`` does not close it.

    Example::

        builder = GraphBuilder(neo4j_client)
        result = await builder.full_scan(
            account_id="123456789012",
            regions=["us-east-1", "us-west-2"],
        )
        print(f"Discovered {result.nodes_written} nodes, {result.findings_count} findings")
    """

    def __init__(self, client: Neo4jClient) -> None:
        self._client = client
        self._evaluator = PostureEvaluator(client)

    async def full_scan(
        self,
        account_id: str,
        regions: list[str],
        assume_role_arn: str | None = None,
        clear_first: bool = False,
    ) -> ScanResult:
        """Run a complete discovery scan for an AWS account.

        Discovery steps (in order):
        1. Optionally clear existing account data from Neo4j
        2. Ensure Neo4j indexes exist
        3. Build boto3 session (with optional cross-account assume-role)
        4. Upsert the ``AWSAccount`` root node
        5. Run per-region connectors (EC2, Lambda, RDS) in parallel
        6. Run global connectors (IAM, S3)
        7. Resolve cross-connector edges (Lambda EXECUTES_AS IAMRole)
        8. Write all nodes then all edges to Neo4j (bounded concurrency)
        9. Run ``PostureEvaluator`` to stamp CIS findings on violating nodes

        Args:
            account_id: 12-digit AWS account ID to scan.
            regions: List of AWS region names, e.g. ``["us-east-1", "eu-west-1"]``.
            assume_role_arn: Optional IAM Role ARN for cross-account access.
            clear_first: If ``True``, delete all existing account data before
                scanning. Use for a clean re-scan. Default is incremental.

        Returns:
            ``ScanResult`` with node/edge counts, finding count, timing,
            and any non-fatal errors.

        Raises:
            Does not raise. All connector errors are caught and added to
            ``ScanResult.errors``. The evaluator is best-effort too.
        """
        start = time.monotonic()
        result = ScanResult(account_id=account_id, regions=regions)

        if clear_first:
            await self._client.clear_account(account_id)
            logger.info("Cleared account %s for fresh scan", account_id)

        await self._client.ensure_indexes()

        session = await asyncio.to_thread(
            get_session,
            regions[0] if regions else "us-east-1",
            assume_role_arn,
        )

        # Root account node
        account_node = AWSAccount(
            node_id=account_id,
            account_id=account_id,
            regions=regions,
        )
        await self._client.upsert_node(account_node)
        result.nodes_written += 1

        # ── Per-region discovery ───────────────────────────────────────────────
        all_nodes: list[GraphNode] = []
        all_edges: list[GraphEdge] = []

        region_tasks = [
            self._scan_region(session, account_id, region, result) for region in regions
        ]
        region_results = await asyncio.gather(*region_tasks, return_exceptions=True)

        for region, region_result in zip(regions, region_results, strict=False):
            if isinstance(region_result, Exception):
                error = f"Region {region} scan failed: {region_result}"
                logger.error(error)
                result.errors.append(error)
                continue
            assert not isinstance(region_result, BaseException)
            r_nodes, r_edges = region_result
            all_nodes.extend(r_nodes)
            all_edges.extend(r_edges)

        # ── IAM (global) ──────────────────────────────────────────────────────
        try:
            iam_nodes, iam_edges = await iam.discover(session, account_id)
            all_nodes.extend(iam_nodes)
            all_edges.extend(iam_edges)
        except Exception as exc:
            error = f"IAM discovery failed: {exc}"
            logger.error(error)
            result.errors.append(error)
            iam_nodes = []

        # ── S3 (global) ───────────────────────────────────────────────────────
        try:
            s3_nodes, s3_edges = await s3.discover(session, account_id)
            all_nodes.extend(s3_nodes)
            all_edges.extend(s3_edges)
        except Exception as exc:
            error = f"S3 discovery failed: {exc}"
            logger.error(error)
            result.errors.append(error)

        # Account → Region edges
        for region in regions:
            region_node_id = f"region-{account_id}-{region}"
            all_edges.append(
                HasResource(
                    from_node_id=account_id,
                    to_node_id=region_node_id,
                    account_id=account_id,
                )
            )

        # ── Resolve Lambda → IAMRole edges ────────────────────────────────────
        # IAM connector uses role_id (from ListRoles) as node_id; Lambda stores
        # the role ARN. We build a lookup here to bridge the two.
        iam_role_by_arn = {n.arn: n.role_id for n in all_nodes if isinstance(n, IAMRole)}
        for node in all_nodes:
            if isinstance(node, LambdaFunction) and node.role_arn:
                target_id = iam_role_by_arn.get(node.role_arn)
                if target_id:
                    all_edges.append(
                        ExecutesAs(
                            from_node_id=node.node_id,
                            to_node_id=target_id,
                            account_id=account_id,
                        )
                    )

        # ── Write to Neo4j ─────────────────────────────────────────────────────
        write_start = time.monotonic()
        await self._write_nodes(all_nodes)
        await self._write_edges(all_edges)
        logger.info(
            "Graph write complete in %.2fs: %d nodes, %d edges",
            time.monotonic() - write_start,
            len(all_nodes),
            len(all_edges),
        )

        result.nodes_written += len(all_nodes)
        result.edges_written += len(all_edges)

        # ── Posture evaluation ────────────────────────────────────────────────
        try:
            findings = await self._evaluator.evaluate(account_id)
            result.findings = findings
            result.findings_count = len(findings)
        except Exception as exc:
            error = f"Posture evaluation failed: {exc}"
            logger.error(error)
            result.errors.append(error)

        result.duration_seconds = time.monotonic() - start
        logger.info(
            "Full scan complete for account %s: %d nodes, %d edges, %d findings in %.2fs",
            account_id,
            result.nodes_written,
            result.edges_written,
            result.findings_count,
            result.duration_seconds,
        )
        return result

    async def _scan_region(
        self,
        session: boto3.Session,
        account_id: str,
        region: str,
        result: ScanResult,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Run EC2, Lambda, and RDS connectors for a single region.

        Args:
            session: boto3 session to use (may be cross-account).
            account_id: AWS account ID.
            region: AWS region name.
            result: Mutable ``ScanResult`` to append per-connector errors to.

        Returns:
            Tuple of ``(nodes, edges)`` from all regional connectors combined.
        """
        from sentinel_core.models.nodes import Region

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        region_node_id = f"region-{account_id}-{region}"
        region_node = Region(
            node_id=region_node_id,
            account_id=account_id,
            region=region,
            name=region,
        )
        nodes.append(region_node)

        connector_tasks = [
            ec2.discover(session, account_id, region),
            lambda_.discover(session, account_id, region),
            rds.discover(session, account_id, region),
        ]
        connector_results = await asyncio.gather(*connector_tasks, return_exceptions=True)

        connector_names = ["EC2", "Lambda", "RDS"]
        for name, connector_result in zip(connector_names, connector_results, strict=False):
            if isinstance(connector_result, Exception):
                error = f"{name} connector [{region}] failed: {connector_result}"
                logger.error(error)
                result.errors.append(error)
                continue
            assert not isinstance(connector_result, BaseException)
            c_nodes, c_edges = connector_result
            nodes.extend(c_nodes)
            edges.extend(c_edges)

            # Region → resource edges (skip the region node itself)
            for node in c_nodes:
                if node.node_id != region_node_id:
                    edges.append(
                        HasResource(
                            from_node_id=region_node_id,
                            to_node_id=node.node_id,
                            account_id=account_id,
                        )
                    )

        return nodes, edges

    async def _write_nodes(self, nodes: list[GraphNode]) -> None:
        """Write all nodes to Neo4j with bounded parallelism.

        Uses a semaphore of 20 to avoid overwhelming Neo4j's connection pool
        when hundreds of nodes are upserted concurrently.

        Args:
            nodes: List of graph nodes to upsert.
        """
        semaphore = asyncio.Semaphore(20)

        async def _upsert(node: GraphNode) -> None:
            async with semaphore:
                try:
                    await self._client.upsert_node(node)
                except Exception as exc:
                    logger.warning("Failed to upsert node %s: %s", node.node_id, exc)

        await asyncio.gather(*[_upsert(n) for n in nodes])

    async def _write_edges(self, edges: list[GraphEdge]) -> None:
        """Write all edges to Neo4j with bounded parallelism.

        Nodes must already exist before edges are written — call
        ``_write_nodes`` first.

        Args:
            edges: List of graph edges to upsert.
        """
        semaphore = asyncio.Semaphore(20)

        async def _upsert(edge: GraphEdge) -> None:
            async with semaphore:
                try:
                    await self._client.upsert_edge(edge)
                except Exception as exc:
                    logger.warning(
                        "Failed to upsert edge %s → %s: %s",
                        edge.from_node_id,
                        edge.to_node_id,
                        exc,
                    )

        await asyncio.gather(*[_upsert(e) for e in edges])

    async def targeted_scan(
        self,
        account_id: str,
        resource_id: str,
        resource_type: str,
        region: str,
        assume_role_arn: str | None = None,
    ) -> ScanResult:
        """Re-scan a single resource type in response to a CloudTrail event.

        Runs the full connector for the affected service (not just the one
        resource) because boto3 doesn't support single-resource describe for
        all services. The result is filtered to the specific resource before
        writing.

        Used by ``CloudTrailPoller`` to keep the graph up-to-date without
        a full account scan.

        Args:
            account_id: AWS account ID.
            resource_id: The specific resource's node_id (or AWS ID).
            resource_type: ``ResourceType`` string, e.g. ``"EC2Instance"``.
            region: AWS region where the resource lives.
            assume_role_arn: Optional assume-role ARN for cross-account access.

        Returns:
            ``ScanResult`` with write counts for the targeted update.
        """
        result = ScanResult(account_id=account_id, regions=[region])
        session = await asyncio.to_thread(get_session, region, assume_role_arn)

        connector_map = {
            "EC2Instance": lambda: ec2.discover(session, account_id, region),
            "S3Bucket": lambda: s3.discover(session, account_id),
            "LambdaFunction": lambda: lambda_.discover(session, account_id, region),
            "RDSInstance": lambda: rds.discover(session, account_id, region),
            "IAMRole": lambda: iam.discover(session, account_id),
            "IAMUser": lambda: iam.discover(session, account_id),
            "IAMPolicy": lambda: iam.discover(session, account_id),
        }

        discover_fn = connector_map.get(resource_type)
        if not discover_fn:
            logger.warning("No targeted scan connector for type %s", resource_type)
            return result

        try:
            nodes, edges = await discover_fn()
            nodes = [n for n in nodes if n.node_id == resource_id]
            await self._write_nodes(nodes)
            await self._write_edges(edges)
            result.nodes_written = len(nodes)
            result.edges_written = len(edges)
        except Exception as exc:
            result.errors.append(str(exc))

        return result
