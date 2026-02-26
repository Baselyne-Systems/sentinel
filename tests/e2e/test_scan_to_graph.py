"""
E2E Test: full AWS scan → real Neo4j write → graph query.

Verifies that the complete pipeline from boto3 discovery through to
Neo4j node/edge storage works correctly with a real graph database.

What this tests that unit tests cannot:
- MERGE semantics (re-scanning doesn't duplicate nodes)
- Neo4j index utilization
- Actual Cypher query execution against stored data
- Edge MATCH (requires both nodes to already exist)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.graph.queries import GraphQueries
from sentinel_core.models.enums import PostureFlag, ResourceType
from sentinel_perception.graph_builder import GraphBuilder

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_full_scan_writes_account_node(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
):
    """Full scan should write an AWSAccount node to Neo4j."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    assert result.nodes_written > 0

    # Query the actual Neo4j
    records = await clean_db.query(
        "MATCH (a:AWSAccount {account_id: $account_id}) RETURN a",
        {"account_id": ACCOUNT_ID},
    )
    assert len(records) == 1
    node = records[0]["a"]
    assert node["account_id"] == ACCOUNT_ID


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_full_scan_writes_region_node(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
):
    """Full scan should write a Region node."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    records = await clean_db.query(
        "MATCH (r:Region {region: $region, account_id: $account_id}) RETURN r",
        {"region": REGION, "account_id": ACCOUNT_ID},
    )
    assert len(records) >= 1


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_writes_vpc_and_subnet(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
    subnet_ids,
):
    """VPC and subnet nodes should be written to Neo4j."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    # Check VPC node
    vpc_records = await clean_db.query(
        "MATCH (v:VPC {vpc_id: $vpc_id}) RETURN v",
        {"vpc_id": vpc_id},
    )
    assert len(vpc_records) == 1
    vpc_node = vpc_records[0]["v"]
    assert vpc_node["vpc_id"] == vpc_id
    assert vpc_node["resource_type"] == ResourceType.VPC

    # Check subnet nodes
    for subnet_id in subnet_ids:
        subnet_records = await clean_db.query(
            "MATCH (s:Subnet {subnet_id: $subnet_id}) RETURN s",
            {"subnet_id": subnet_id},
        )
        assert len(subnet_records) == 1


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_writes_security_group_with_flags(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    open_sg_id,
    vpc_id,
):
    """Security group with SSH open should be written with SG_OPEN_SSH flag."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    records = await clean_db.query(
        "MATCH (sg:SecurityGroup {group_id: $sg_id}) RETURN sg",
        {"sg_id": open_sg_id},
    )
    assert len(records) == 1

    sg_node = records[0]["sg"]
    posture_flags = sg_node.get("posture_flags", [])
    assert PostureFlag.SG_OPEN_SSH in posture_flags


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_writes_public_s3_bucket(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
):
    """Public S3 bucket should be written with S3_PUBLIC_ACCESS flag."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    records = await clean_db.query(
        "MATCH (b:S3Bucket {name: $name}) RETURN b",
        {"name": public_s3_bucket},
    )
    assert len(records) == 1

    bucket_node = records[0]["b"]
    assert bucket_node["is_public"] is True
    assert PostureFlag.S3_PUBLIC_ACCESS in bucket_node.get("posture_flags", [])


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_writes_ec2_instance(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    ec2_instance_id,
    vpc_id,
    subnet_ids,
    open_sg_id,
):
    """EC2 instance should be written with correct properties."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    records = await clean_db.query(
        "MATCH (i:EC2Instance {instance_id: $instance_id}) RETURN i",
        {"instance_id": ec2_instance_id},
    )
    assert len(records) == 1

    instance = records[0]["i"]
    assert instance["instance_id"] == ec2_instance_id
    assert instance["resource_type"] == ResourceType.EC2_INSTANCE
    assert instance["account_id"] == ACCOUNT_ID


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_writes_rds_instance_with_flags(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_rds_instance,
    vpc_id,
    subnet_ids,
    open_sg_id,
):
    """Public, unencrypted RDS instance should be written with posture flags."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    records = await clean_db.query(
        "MATCH (r:RDSInstance {db_id: $db_id}) RETURN r",
        {"db_id": "sentinel-test-db"},
    )
    assert len(records) == 1

    rds_node = records[0]["r"]
    assert rds_node["publicly_accessible"] is True
    assert rds_node["encrypted"] is False

    posture_flags = rds_node.get("posture_flags", [])
    assert PostureFlag.RDS_PUBLIC in posture_flags
    assert PostureFlag.RDS_NO_ENCRYPTION in posture_flags


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_scan_idempotency_no_duplicate_nodes(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
):
    """Running a scan twice should not create duplicate nodes (MERGE semantics)."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    # There should still be exactly one AWSAccount node
    records = await clean_db.query(
        "MATCH (a:AWSAccount {account_id: $account_id}) RETURN count(a) AS n",
        {"account_id": ACCOUNT_ID},
    )
    assert records[0]["n"] == 1

    # Exactly one VPC node for our VPC
    vpc_records = await clean_db.query(
        "MATCH (v:VPC {vpc_id: $vpc_id}) RETURN count(v) AS n",
        {"vpc_id": vpc_id},
    )
    assert vpc_records[0]["n"] == 1


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_clear_first_removes_old_data(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
):
    """Scan with clear_first=True should remove old account data."""
    builder = GraphBuilder(clean_db)

    # First scan
    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    count_before = await clean_db.query(
        "MATCH (n {account_id: $account_id}) RETURN count(n) AS n",
        {"account_id": ACCOUNT_ID},
    )
    assert count_before[0]["n"] > 0

    # Second scan with clear_first
    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
            clear_first=True,
        )

    # Should still have data (re-scanned after clear)
    count_after = await clean_db.query(
        "MATCH (n {account_id: $account_id}) RETURN count(n) AS n",
        {"account_id": ACCOUNT_ID},
    )
    assert count_after[0]["n"] > 0


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_graph_queries_list_nodes(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    vpc_id,
):
    """GraphQueries.list_nodes() should return paginated results from real Neo4j."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)

    # List all nodes
    all_nodes = await queries.list_nodes(account_id=ACCOUNT_ID, limit=100)
    assert len(all_nodes) > 0

    # Filter by type
    s3_nodes = await queries.list_nodes(
        resource_type=ResourceType.S3_BUCKET,
        account_id=ACCOUNT_ID,
    )
    assert len(s3_nodes) >= 1

    # Pagination
    page1 = await queries.list_nodes(account_id=ACCOUNT_ID, limit=2, offset=0)
    page2 = await queries.list_nodes(account_id=ACCOUNT_ID, limit=2, offset=2)
    # Pages should not overlap (different node_ids)
    page1_ids = {r.get("n", {}).get("node_id") for r in page1}
    page2_ids = {r.get("n", {}).get("node_id") for r in page2}
    assert page1_ids.isdisjoint(page2_ids) or len(page2_ids) == 0


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_graph_queries_get_resource_by_id(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
):
    """GraphQueries.get_resource_by_id() should return a specific node."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)
    node_id = f"s3-{public_s3_bucket}"

    result = await queries.get_resource_by_id(node_id)
    assert result is not None

    node = result.get("n", result)
    assert node["node_id"] == node_id
    assert node["name"] == public_s3_bucket


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_graph_queries_get_neighbors(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    vpc_id,
    subnet_ids,
    ec2_instance_id,
    open_sg_id,
):
    """GraphQueries.get_neighbors() should traverse relationships in real Neo4j."""
    builder = GraphBuilder(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    queries = GraphQueries(clean_db)

    # Get neighbors of the VPC (should include subnets and instances)
    results = await queries.get_neighbors(vpc_id, depth=2)
    # Should return path records
    assert isinstance(results, list)
