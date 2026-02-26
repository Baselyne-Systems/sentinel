"""
Benchmarks: Neo4j graph query latency.

Measures how fast SENTINEL can execute the queries used in the UI:

- ``find_public_s3`` — finds all S3 buckets with is_public=true (used by /posture/findings)
- ``neighbor_depth_1`` — BFS 1 hop from a node (used by the graph explorer)
- ``neighbor_depth_2`` — BFS 2 hops
- ``findings_with_flags`` — nodes with non-empty posture_flags list (used by /posture/findings)

A graph of ~200 nodes with edges is seeded once per test.  Queries are run
against this static dataset so timings reflect pure query performance, not
write overhead.

Run::

    make bench
    # or: pytest tests/benchmarks/test_graph_queries.py -v --benchmark-sort=mean
"""

from __future__ import annotations

import pytest
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.models.edges import InVPC, MemberOfSG
from sentinel_core.models.nodes import VPC, EC2Instance, S3Bucket, SecurityGroup

pytestmark = pytest.mark.benchmark

_ACCOUNT = "qbench"
_N_NODES = 200


# ── Graph seed fixture ─────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def seeded_graph(neo4j_client: Neo4jClient, event_loop):
    """
    Write ~200 nodes and edges once for the entire query benchmark module.
    Wiped after the module exits.
    """

    async def _seed():
        # 1 VPC
        vpc = VPC(
            node_id="qbench-vpc",
            account_id=_ACCOUNT,
            region="us-east-1",
            vpc_id="vpc-qbench",
        )
        await neo4j_client.upsert_node(vpc)

        # 1 Security Group
        sg = SecurityGroup(
            node_id="qbench-sg",
            account_id=_ACCOUNT,
            region="us-east-1",
            group_id="sg-qbench",
            name="qbench-sg",
            vpc_id="vpc-qbench",
            posture_flags=["SG_OPEN_SSH"],
        )
        await neo4j_client.upsert_node(sg)

        # S3 buckets — half public
        for i in range(100):
            b = S3Bucket(
                node_id=f"qbench-s3-{i}",
                account_id=_ACCOUNT,
                region="us-east-1",
                name=f"qbench-bucket-{i}",
                is_public=(i % 2 == 0),
                posture_flags=["S3_PUBLIC_ACCESS"] if i % 2 == 0 else [],
            )
            await neo4j_client.upsert_node(b)

        # EC2 instances in VPC + SG
        for i in range(100):
            ec2 = EC2Instance(
                node_id=f"qbench-ec2-{i}",
                account_id=_ACCOUNT,
                region="us-east-1",
                instance_id=f"i-qbench{i:07x}",
                vpc_id="vpc-qbench",
                posture_flags=["EBS_UNENCRYPTED"] if i % 10 == 0 else [],
            )
            await neo4j_client.upsert_node(ec2)
            await neo4j_client.upsert_edge(InVPC(from_node_id=ec2.node_id, to_node_id="qbench-vpc"))
            await neo4j_client.upsert_edge(
                MemberOfSG(from_node_id=ec2.node_id, to_node_id="qbench-sg")
            )

    event_loop.run_until_complete(_seed())
    yield neo4j_client

    async def _teardown():
        await neo4j_client.execute(
            "MATCH (n) WHERE n.account_id = $a DETACH DELETE n",
            {"a": _ACCOUNT},
        )

    event_loop.run_until_complete(_teardown())


# ── Query benchmarks ───────────────────────────────────────────────────────────


@pytest.mark.timeout(60)
def test_query_public_s3_buckets(benchmark, seeded_graph, event_loop):
    """Find all is_public=true S3 buckets (50 results in seeded graph)."""

    def run():
        async def _q():
            return await seeded_graph.query(
                "MATCH (n:S3Bucket {is_public: true}) WHERE n.account_id = $a RETURN n",
                {"a": _ACCOUNT},
            )

        return event_loop.run_until_complete(_q())

    benchmark(run)
    actual = run()
    print(
        f"\n  public S3 query → {benchmark.stats['mean'] * 1000:.1f} ms/round, {len(actual)} rows"
    )
    assert benchmark.stats["mean"] < 5.0, "Query should complete in <5s"


@pytest.mark.timeout(60)
def test_query_findings_with_posture_flags(benchmark, seeded_graph, event_loop):
    """Enumerate all nodes that have non-empty posture_flags."""

    def run():
        async def _q():
            return await seeded_graph.query(
                """
                MATCH (n)
                WHERE n.account_id = $a AND size(n.posture_flags) > 0
                RETURN n.node_id AS id, n.posture_flags AS flags
                """,
                {"a": _ACCOUNT},
            )

        return event_loop.run_until_complete(_q())

    benchmark(run)
    results = run()
    print(
        f"\n  findings query → {benchmark.stats['mean'] * 1000:.1f} ms/round, {len(results)} flagged nodes"
    )
    assert len(results) > 0
    assert benchmark.stats["mean"] < 5.0


@pytest.mark.timeout(60)
def test_bfs_depth_1_from_sg(benchmark, seeded_graph, event_loop):
    """BFS 1 hop from a SecurityGroup (100 EC2 instances expected)."""

    def run():
        async def _q():
            return await seeded_graph.query(
                """
                MATCH (start {node_id: $nid})-[*1..1]-(neighbor)
                RETURN neighbor.node_id AS id
                LIMIT 200
                """,
                {"nid": "qbench-sg"},
            )

        return event_loop.run_until_complete(_q())

    benchmark(run)
    results = run()
    print(
        f"\n  BFS depth-1 → {benchmark.stats['mean'] * 1000:.1f} ms/round, {len(results)} neighbors"
    )
    assert len(results) > 0
    assert benchmark.stats["mean"] < 5.0


@pytest.mark.timeout(60)
def test_bfs_depth_2_from_sg(benchmark, seeded_graph, event_loop):
    """BFS 2 hops from a SecurityGroup (EC2 → VPC expansion)."""

    def run():
        async def _q():
            return await seeded_graph.query(
                """
                MATCH (start {node_id: $nid})-[*1..2]-(neighbor)
                RETURN DISTINCT neighbor.node_id AS id
                LIMIT 300
                """,
                {"nid": "qbench-sg"},
            )

        return event_loop.run_until_complete(_q())

    benchmark(run)
    results = run()
    print(
        f"\n  BFS depth-2 → {benchmark.stats['mean'] * 1000:.1f} ms/round, {len(results)} neighbors"
    )
    assert len(results) > 0
    assert benchmark.stats["mean"] < 10.0


@pytest.mark.timeout(60)
def test_posture_summary_count(benchmark, seeded_graph, event_loop):
    """Count findings grouped by posture_flag (used by /posture/summary)."""

    def run():
        async def _q():
            return await seeded_graph.query(
                """
                MATCH (n)
                WHERE n.account_id = $a AND size(n.posture_flags) > 0
                UNWIND n.posture_flags AS flag
                RETURN flag, count(n) AS cnt
                ORDER BY cnt DESC
                """,
                {"a": _ACCOUNT},
            )

        return event_loop.run_until_complete(_q())

    benchmark(run)
    results = run()
    print(
        f"\n  posture summary → {benchmark.stats['mean'] * 1000:.1f} ms/round, {len(results)} flag types"
    )
    assert len(results) > 0
    assert benchmark.stats["mean"] < 5.0
