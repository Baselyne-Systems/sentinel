"""Unit tests for GraphBuilder with mocked Neo4j client."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from sentinel_core.models.nodes import AWSAccount, EC2Instance, S3Bucket, SecurityGroup
from sentinel_perception.graph_builder import GraphBuilder, ScanResult

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.mark.asyncio
async def test_full_scan_creates_account_node(
    aws_session, mock_neo4j_client, mocked_aws, vpc_id, subnet_ids
):
    """full_scan should upsert an AWSAccount node."""
    builder = GraphBuilder(mock_neo4j_client)

    with patch(
        "sentinel_perception.graph_builder.get_session", return_value=aws_session
    ):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    assert isinstance(result, ScanResult)
    assert result.account_id == ACCOUNT_ID

    # Account node should be first upserted
    upserted_types = {type(n).__name__ for n in mock_neo4j_client.nodes}
    assert "AWSAccount" in upserted_types


@pytest.mark.asyncio
async def test_full_scan_returns_scan_result(
    aws_session, mock_neo4j_client, mocked_aws
):
    """full_scan should return a ScanResult with timing info."""
    builder = GraphBuilder(mock_neo4j_client)

    with patch(
        "sentinel_perception.graph_builder.get_session", return_value=aws_session
    ):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    assert result.duration_seconds > 0
    assert result.nodes_written >= 1  # At least the account node
    assert isinstance(result.errors, list)


@pytest.mark.asyncio
async def test_full_scan_discovers_s3_buckets(
    aws_session, mock_neo4j_client, mocked_aws, public_s3_bucket
):
    """full_scan should discover and write S3 bucket nodes."""
    builder = GraphBuilder(mock_neo4j_client)

    with patch(
        "sentinel_perception.graph_builder.get_session", return_value=aws_session
    ):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    s3_nodes = [n for n in mock_neo4j_client.nodes if isinstance(n, S3Bucket)]
    assert len(s3_nodes) >= 1
    public_buckets = [n for n in s3_nodes if n.is_public]
    assert len(public_buckets) >= 1


@pytest.mark.asyncio
async def test_full_scan_discovers_security_groups(
    aws_session, mock_neo4j_client, mocked_aws, open_sg_id, vpc_id
):
    """full_scan should discover security groups with posture flags."""
    builder = GraphBuilder(mock_neo4j_client)

    with patch(
        "sentinel_perception.graph_builder.get_session", return_value=aws_session
    ):
        await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    sg_nodes = [n for n in mock_neo4j_client.nodes if isinstance(n, SecurityGroup)]
    assert len(sg_nodes) >= 1
    open_sgs = [n for n in sg_nodes if n.group_id == open_sg_id]
    assert len(open_sgs) >= 1
    from sentinel_core.models.enums import PostureFlag
    assert PostureFlag.SG_OPEN_SSH in open_sgs[0].posture_flags


@pytest.mark.asyncio
async def test_full_scan_to_dict(
    aws_session, mock_neo4j_client, mocked_aws
):
    """ScanResult.to_dict() should return a serializable dict."""
    builder = GraphBuilder(mock_neo4j_client)

    with patch(
        "sentinel_perception.graph_builder.get_session", return_value=aws_session
    ):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    d = result.to_dict()
    assert d["account_id"] == ACCOUNT_ID
    assert isinstance(d["nodes_written"], int)
    assert isinstance(d["edges_written"], int)
    assert isinstance(d["duration_seconds"], float)
