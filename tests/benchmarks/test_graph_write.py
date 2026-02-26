"""
Benchmarks: Neo4j graph write throughput.

Measures how fast SENTINEL can upsert nodes across small (10), medium (100),
and large (500) batches.  Each test is timed by pytest-benchmark across
multiple rounds; the mean is used to compute nodes/sec.

Thresholds are conservative — they should pass on any developer laptop and
catch catastrophic regressions (10× slowdown) rather than minor noise.

Run::

    make bench
    # or: pytest tests/benchmarks/ -v --benchmark-sort=mean
"""

from __future__ import annotations

import pytest
from sentinel_core.models.nodes import EC2Instance, IAMRole, RDSInstance, S3Bucket, SecurityGroup

pytestmark = pytest.mark.benchmark

_ACCOUNT = "bench-account"


# ── Node factories ─────────────────────────────────────────────────────────────


def _s3_nodes(n: int) -> list:
    return [
        S3Bucket(
            node_id=f"bench-s3-{i}",
            account_id=_ACCOUNT,
            region="us-east-1",
            name=f"bench-bucket-{i}",
            is_public=(i % 3 == 0),
            versioning=(i % 5 != 0),
        )
        for i in range(n)
    ]


def _mixed_nodes(n: int) -> list:
    nodes: list = []
    for i in range(n):
        k = i % 5
        if k == 0:
            nodes.append(
                S3Bucket(
                    node_id=f"bmix-s3-{i}", account_id=_ACCOUNT, region="us-east-1", name=f"b-{i}"
                )
            )
        elif k == 1:
            nodes.append(
                SecurityGroup(
                    node_id=f"bmix-sg-{i}",
                    account_id=_ACCOUNT,
                    region="us-east-1",
                    group_id=f"sg-{i}",
                    name=f"sg-{i}",
                    vpc_id="vpc-b",
                )
            )
        elif k == 2:
            nodes.append(
                RDSInstance(
                    node_id=f"bmix-rds-{i}",
                    account_id=_ACCOUNT,
                    region="us-east-1",
                    db_id=f"db-{i}",
                    engine="postgres",
                )
            )
        elif k == 3:
            nodes.append(
                EC2Instance(
                    node_id=f"bmix-ec2-{i}",
                    account_id=_ACCOUNT,
                    region="us-east-1",
                    instance_id=f"i-{i:017x}",
                )
            )
        else:
            nodes.append(
                IAMRole(
                    node_id=f"bmix-role-{i}",
                    account_id=_ACCOUNT,
                    region="global",
                    role_id=f"role-id-{i}",
                    name=f"role-{i}",
                    arn=f"arn:aws:iam::{_ACCOUNT}:role/role-{i}",
                )
            )
    return nodes


# ── Benchmark tests ────────────────────────────────────────────────────────────


@pytest.mark.timeout(60)
def test_upsert_10_nodes(benchmark, clean_graph, event_loop):
    """Baseline write latency: 10 nodes per round."""
    nodes = _s3_nodes(10)

    def run():
        async def _w():
            await clean_graph.execute(
                "MATCH (n) WHERE n.node_id STARTS WITH 'bench-' DETACH DELETE n"
            )
            for node in nodes:
                await clean_graph.upsert_node(node)

        event_loop.run_until_complete(_w())

    benchmark(run)
    throughput = 10 / benchmark.stats["mean"]
    print(
        f"\n  10 nodes → {benchmark.stats['mean'] * 1000:.1f} ms/round → {throughput:.0f} nodes/sec"
    )
    assert throughput > 2


@pytest.mark.timeout(180)
def test_upsert_100_s3_nodes(benchmark, clean_graph, event_loop):
    """Medium write load: 100 S3 bucket upserts per round."""
    nodes = _s3_nodes(100)

    def run():
        async def _w():
            await clean_graph.execute(
                "MATCH (n) WHERE n.node_id STARTS WITH 'bench-' DETACH DELETE n"
            )
            for node in nodes:
                await clean_graph.upsert_node(node)

        event_loop.run_until_complete(_w())

    benchmark.pedantic(run, rounds=3, warmup_rounds=1)
    throughput = 100 / benchmark.stats["mean"]
    print(
        f"\n  100 nodes → {benchmark.stats['mean'] * 1000:.0f} ms/round → {throughput:.0f} nodes/sec"
    )
    assert throughput > 5


@pytest.mark.timeout(300)
def test_upsert_500_mixed_nodes(benchmark, clean_graph, event_loop):
    """Large write load: 500 mixed-type nodes — representative of a real scan."""
    nodes = _mixed_nodes(500)

    def run():
        async def _w():
            await clean_graph.execute(
                "MATCH (n) WHERE n.node_id STARTS WITH 'bmix-' OR n.node_id STARTS WITH 'bench-' DETACH DELETE n"
            )
            for node in nodes:
                await clean_graph.upsert_node(node)

        event_loop.run_until_complete(_w())

    benchmark.pedantic(run, rounds=2, warmup_rounds=1)
    throughput = 500 / benchmark.stats["mean"]
    print(
        f"\n  500 mixed nodes → {benchmark.stats['mean'] * 1000:.0f} ms/round → {throughput:.0f} nodes/sec"
    )
    assert throughput > 5


@pytest.mark.timeout(120)
def test_merge_idempotency_50_nodes_twice(clean_graph, event_loop):
    """
    Write 50 nodes twice (MERGE semantics).  Second write should not create
    duplicates and the node count must remain exactly 50.

    Not a benchmark.pedantic test — just a correctness + basic performance check.
    """
    import time

    nodes = _s3_nodes(50)

    async def _run():
        for n in nodes:
            await clean_graph.upsert_node(n)
        for n in nodes:
            await clean_graph.upsert_node(n)
        result = await clean_graph.query(
            "MATCH (n) WHERE n.node_id STARTS WITH 'bench-s3-' RETURN count(n) AS c"
        )
        return result[0]["c"]

    start = time.perf_counter()
    count = event_loop.run_until_complete(_run())
    elapsed = time.perf_counter() - start

    assert count == 50, f"MERGE created duplicates: expected 50, got {count}"
    ops_per_sec = 100 / elapsed
    print(f"\n  50 nodes × 2 (MERGE) → {elapsed * 1000:.0f} ms → {ops_per_sec:.0f} ops/sec")
    assert ops_per_sec > 5
