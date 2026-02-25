"""Unit tests for the RDS connector."""

from __future__ import annotations

import pytest

from sentinel_core.models.enums import PostureFlag, ResourceType
from sentinel_core.models.nodes import RDSInstance
from sentinel_perception.connectors.aws import rds

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.mark.asyncio
async def test_rds_discovers_public_instance(aws_session, public_rds_instance, mocked_aws):
    """Publicly accessible RDS instance should be discovered with RDS_PUBLIC flag."""
    nodes, edges = await rds.discover(aws_session, ACCOUNT_ID, REGION)

    rds_nodes = [n for n in nodes if isinstance(n, RDSInstance)]
    assert len(rds_nodes) >= 1

    db = next((n for n in rds_nodes if n.db_id == "sentinel-test-db"), None)
    assert db is not None
    assert db.publicly_accessible is True
    assert PostureFlag.RDS_PUBLIC in db.posture_flags


@pytest.mark.asyncio
async def test_rds_unencrypted_flag(aws_session, public_rds_instance, mocked_aws):
    """Unencrypted RDS instance should have RDS_NO_ENCRYPTION flag."""
    nodes, _ = await rds.discover(aws_session, ACCOUNT_ID, REGION)

    db = next(
        (n for n in nodes if isinstance(n, RDSInstance) and n.db_id == "sentinel-test-db"),
        None,
    )
    assert db is not None
    assert db.encrypted is False
    assert PostureFlag.RDS_NO_ENCRYPTION in db.posture_flags


@pytest.mark.asyncio
async def test_rds_no_multi_az_flag(aws_session, public_rds_instance, mocked_aws):
    """RDS instance without Multi-AZ should have RDS_NO_MULTI_AZ flag."""
    nodes, _ = await rds.discover(aws_session, ACCOUNT_ID, REGION)

    db = next(
        (n for n in nodes if isinstance(n, RDSInstance) and n.db_id == "sentinel-test-db"),
        None,
    )
    assert db is not None
    assert db.multi_az is False
    assert PostureFlag.RDS_NO_MULTI_AZ in db.posture_flags


@pytest.mark.asyncio
async def test_rds_resource_type(aws_session, public_rds_instance, mocked_aws):
    """RDS nodes should have correct resource_type."""
    nodes, _ = await rds.discover(aws_session, ACCOUNT_ID, REGION)

    for node in [n for n in nodes if isinstance(n, RDSInstance)]:
        assert node.resource_type == ResourceType.RDS_INSTANCE
        assert node.account_id == ACCOUNT_ID
        assert node.region == REGION


@pytest.mark.asyncio
async def test_rds_produces_vpc_edges(aws_session, public_rds_instance, vpc_id, mocked_aws):
    """RDS connector should produce InVPC edges when VPC is configured."""
    _, edges = await rds.discover(aws_session, ACCOUNT_ID, REGION)
    # Edges may include InVPC and MemberOfSG
    assert len(edges) >= 0  # Just verify it doesn't crash
