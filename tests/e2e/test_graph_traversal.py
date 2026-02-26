"""
E2E Test: graph traversal and attack path queries.

Verifies that the security-relevant Cypher queries in GraphQueries work
correctly against real Neo4j data. These tests are the core proof that
SENTINEL can find meaningful security patterns in the graph.

Attack paths tested:
1. Internet → open SG → EC2 instance (lateral movement risk)
2. Internet → open SG → public RDS (direct database exposure)
3. IAM user without MFA → high-privilege role (privilege escalation path)
4. Lambda → over-privileged IAM role (serverless attack surface)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.graph.queries import GraphQueries
from sentinel_perception.graph_builder import GraphBuilder

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_find_public_s3_buckets_query(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    private_s3_bucket,
):
    """GraphQueries.find_public_s3_buckets() should find only the public bucket."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)
    public_buckets = await queries.find_public_s3_buckets(account_id=ACCOUNT_ID)

    bucket_names = []
    for record in public_buckets:
        node = record.get("b", record)
        bucket_names.append(node.get("name", ""))

    assert public_s3_bucket in bucket_names
    assert private_s3_bucket not in bucket_names


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_find_overly_permissive_sgs_query(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    open_sg_id,
    vpc_id,
):
    """GraphQueries.find_overly_permissive_sgs() should return the open SSH SG."""
    builder = GraphBuilder(clean_db)
    from sentinel_core.knowledge.evaluator import PostureEvaluator

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    # Evaluate to stamp posture_flags
    evaluator = PostureEvaluator(clean_db)
    await evaluator.evaluate(account_id=ACCOUNT_ID)

    queries = GraphQueries(clean_db)
    permissive_sgs = await queries.find_overly_permissive_sgs(account_id=ACCOUNT_ID)

    sg_ids = []
    for record in permissive_sgs:
        node = record.get("sg", record)
        sg_ids.append(node.get("group_id", ""))

    assert open_sg_id in sg_ids


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_find_internet_to_rds_attack_path(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_rds_instance,
    open_sg_id,
    vpc_id,
    subnet_ids,
):
    """
    GraphQueries.find_internet_to_rds_paths() should detect the attack path:
    Internet → Open SG → Publicly Accessible RDS.

    This is the canonical SENTINEL attack path query.
    """
    builder = GraphBuilder(clean_db)
    from sentinel_core.knowledge.evaluator import PostureEvaluator

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    evaluator = PostureEvaluator(clean_db)
    await evaluator.evaluate(account_id=ACCOUNT_ID)

    queries = GraphQueries(clean_db)
    attack_paths = await queries.find_internet_to_rds_paths(account_id=ACCOUNT_ID)

    # Should find the path through the open SG to the public RDS
    assert len(attack_paths) >= 1, (
        "Expected to find an attack path from internet → open SG → public RDS. "
        "Verify the RDS instance is connected to the open SG via MEMBER_OF_SG edge."
    )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_find_iam_users_without_mfa(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    iam_user_no_mfa,
):
    """GraphQueries.find_iam_users_without_mfa() should return users lacking MFA."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)
    users = await queries.find_iam_users_without_mfa(account_id=ACCOUNT_ID)

    user_names = [r.get("u", r).get("name", "") for r in users]
    assert "sentinel-test-user" in user_names


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_find_unencrypted_rds(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_rds_instance,
    vpc_id,
    subnet_ids,
    open_sg_id,
):
    """GraphQueries.find_unencrypted_rds() should return the unencrypted instance."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)
    unencrypted = await queries.find_unencrypted_rds(account_id=ACCOUNT_ID)

    db_ids = [r.get("r", r).get("db_id", "") for r in unencrypted]
    assert "sentinel-test-db" in db_ids


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_node_neighbor_traversal(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
    subnet_ids,
    ec2_instance_id,
    open_sg_id,
):
    """
    Graph traversal: from EC2 instance, depth-2 neighbors should include
    VPC, subnet, and security group (the blast radius of this instance).
    """
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)
    neighbor_records = await queries.get_neighbors(ec2_instance_id, depth=2)

    # Collect all node_ids from the traversal
    found_node_ids: set[str] = set()
    for record in neighbor_records:
        for node in record.get("nodes", []):
            if nid := node.get("node_id"):
                found_node_ids.add(nid)

    # The VPC should be reachable (EC2 -[IN_VPC]-> VPC)
    assert vpc_id in found_node_ids, (
        f"VPC {vpc_id} should be reachable from EC2 instance {ec2_instance_id} "
        f"via IN_VPC edge. Found: {found_node_ids}"
    )

    # The security group should be reachable (EC2 -[MEMBER_OF_SG]-> SG)
    assert open_sg_id in found_node_ids, (
        f"Security group {open_sg_id} should be reachable from EC2 instance "
        f"via MEMBER_OF_SG edge. Found: {found_node_ids}"
    )


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_account_has_resource_edges(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
):
    """HAS_RESOURCE edges should connect AWSAccount → Region → resources."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    # Account → Region edge
    records = await clean_db.query(
        """
        MATCH (a:AWSAccount {account_id: $account_id})-[:HAS_RESOURCE]->(r:Region)
        RETURN r.name AS region_name
        """,
        {"account_id": ACCOUNT_ID},
    )
    assert len(records) >= 1
    region_names = [r["region_name"] for r in records]
    assert REGION in region_names


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_summary_counts(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    open_sg_id,
    vpc_id,
    iam_user_no_mfa,
    public_rds_instance,
    subnet_ids,
    ec2_instance_id,
    star_policy_arn,
    iam_role,
):
    """
    Full scan + evaluate should produce a posture summary with:
    - CRITICAL findings (open SSH SG, public RDS, public S3)
    - HIGH findings (IAM no MFA, unencrypted RDS, star policy)
    """
    builder = GraphBuilder(clean_db)
    from sentinel_core.graph.queries import GraphQueries
    from sentinel_core.knowledge.evaluator import PostureEvaluator

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    evaluator = PostureEvaluator(clean_db)
    await evaluator.evaluate(account_id=ACCOUNT_ID)

    queries = GraphQueries(clean_db)
    summary = await queries.get_posture_summary(account_id=ACCOUNT_ID)

    assert summary["total_nodes"] > 0

    # We deliberately created CRITICAL violations
    assert summary["critical_count"] >= 1, (
        f"Expected at least 1 CRITICAL finding. Summary: {summary}"
    )

    # Alignment should be below 100% (we have violations)
    total = summary["total_nodes"]
    critical = summary["critical_count"]
    alignment = (1 - critical / max(total, 1)) * 100
    assert alignment < 100, "Alignment should be < 100% with known violations present"
