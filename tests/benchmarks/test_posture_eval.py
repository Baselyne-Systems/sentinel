"""
Benchmarks: CIS posture evaluation speed.

Measures how long PostureEvaluator takes to stamp posture_flags on N nodes
that all violate CIS rules:

- 10 nodes  — baseline / dev-machine sanity
- 100 nodes — representative scan (typical AWS account)
- 250 nodes — larger account

Each test writes nodes first, then times just the evaluation step so
write overhead is excluded.

Run::

    make bench
    # or: pytest tests/benchmarks/test_posture_eval.py -v
"""

from __future__ import annotations

import pytest
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.knowledge.evaluator import PostureEvaluator
from sentinel_core.models.nodes import RDSInstance, S3Bucket, SecurityGroup

pytestmark = pytest.mark.benchmark

_ACCOUNT = "pbench"


# ── Seed helpers ───────────────────────────────────────────────────────────────


async def _seed_violating_nodes(client: Neo4jClient, n: int) -> None:
    """Write n nodes that each violate at least one CIS rule."""
    third = n // 3

    # S3 buckets — public, no versioning, no encryption
    for i in range(third):
        await client.upsert_node(
            S3Bucket(
                node_id=f"pbench-s3-{i}",
                account_id=_ACCOUNT,
                region="us-east-1",
                name=f"pbench-bucket-{i}",
                is_public=True,
                versioning=False,
                encryption=False,
                logging=False,
            )
        )

    # Security groups — open SSH (inbound 0.0.0.0/0 on port 22 is stamped by evaluator)
    for i in range(third):
        await client.upsert_node(
            SecurityGroup(
                node_id=f"pbench-sg-{i}",
                account_id=_ACCOUNT,
                region="us-east-1",
                group_id=f"sg-pbench-{i}",
                name=f"open-sg-{i}",
                vpc_id="vpc-pbench",
                inbound_rules=[{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}],
            )
        )

    # RDS instances — public, unencrypted
    remainder = n - 2 * third
    for i in range(remainder):
        await client.upsert_node(
            RDSInstance(
                node_id=f"pbench-rds-{i}",
                account_id=_ACCOUNT,
                region="us-east-1",
                db_id=f"pbench-db-{i}",
                engine="postgres",
                publicly_accessible=True,
                encrypted=False,
                multi_az=False,
            )
        )


async def _clear(client: Neo4jClient) -> None:
    await client.execute(
        "MATCH (n) WHERE n.account_id = $a DETACH DELETE n",
        {"a": _ACCOUNT},
    )


# ── Benchmark tests ────────────────────────────────────────────────────────────


@pytest.mark.timeout(60)
def test_evaluate_10_nodes(benchmark, clean_graph, event_loop):
    """Baseline: CIS evaluation for 10 violating nodes."""
    event_loop.run_until_complete(_seed_violating_nodes(clean_graph, 10))
    evaluator = PostureEvaluator(clean_graph)

    def run():
        event_loop.run_until_complete(evaluator.evaluate(account_id=_ACCOUNT))

    benchmark(run)

    async def _count_flagged():
        r = await clean_graph.query(
            "MATCH (n) WHERE n.account_id = $a AND size(n.posture_flags) > 0 RETURN count(n) AS c",
            {"a": _ACCOUNT},
        )
        return r[0]["c"]

    flagged = event_loop.run_until_complete(_count_flagged())
    sec = benchmark.stats["mean"]
    print(f"\n  10 nodes → {sec*1000:.0f} ms/round, {flagged} flagged")
    assert flagged > 0, "Expected some flagged nodes"
    assert sec < 30.0


@pytest.mark.timeout(120)
def test_evaluate_100_nodes(benchmark, clean_graph, event_loop):
    """Typical scan: CIS evaluation for 100 violating nodes."""
    event_loop.run_until_complete(_seed_violating_nodes(clean_graph, 100))
    evaluator = PostureEvaluator(clean_graph)

    def run():
        event_loop.run_until_complete(evaluator.evaluate(account_id=_ACCOUNT))

    benchmark.pedantic(run, rounds=3, warmup_rounds=1)
    sec = benchmark.stats["mean"]
    print(f"\n  100 nodes → {sec*1000:.0f} ms/round")
    assert sec < 60.0


@pytest.mark.timeout(300)
def test_evaluate_250_nodes(benchmark, clean_graph, event_loop):
    """Larger account: CIS evaluation for 250 violating nodes."""
    event_loop.run_until_complete(_seed_violating_nodes(clean_graph, 250))
    evaluator = PostureEvaluator(clean_graph)

    def run():
        event_loop.run_until_complete(evaluator.evaluate(account_id=_ACCOUNT))

    benchmark.pedantic(run, rounds=2, warmup_rounds=1)
    sec = benchmark.stats["mean"]
    print(f"\n  250 nodes → {sec*1000:.0f} ms/round")
    assert sec < 120.0
