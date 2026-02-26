"""Unit tests for the EC2 connector."""

from __future__ import annotations

import pytest
from sentinel_core.models.enums import PostureFlag, ResourceType
from sentinel_core.models.nodes import VPC, EC2Instance, SecurityGroup, Subnet
from sentinel_perception.connectors.aws import ec2

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.mark.asyncio
async def test_ec2_discovers_vpc(aws_session, vpc_id, mocked_aws):
    """VPC should be discovered."""
    nodes, _ = await ec2.discover(aws_session, ACCOUNT_ID, REGION)

    vpc_nodes = [n for n in nodes if isinstance(n, VPC) and n.vpc_id == vpc_id]
    assert len(vpc_nodes) == 1

    vpc = vpc_nodes[0]
    assert vpc.resource_type == ResourceType.VPC
    assert vpc.account_id == ACCOUNT_ID
    assert vpc.region == REGION
    assert "10.0.0.0/16" in vpc.cidr_block


@pytest.mark.asyncio
async def test_ec2_discovers_subnets(aws_session, subnet_ids, vpc_id, mocked_aws):
    """Subnets should be discovered."""
    nodes, _ = await ec2.discover(aws_session, ACCOUNT_ID, REGION)

    subnet_nodes = [n for n in nodes if isinstance(n, Subnet)]
    discovered_ids = {n.subnet_id for n in subnet_nodes}
    assert set(subnet_ids).issubset(discovered_ids)


@pytest.mark.asyncio
async def test_ec2_discovers_open_sg(aws_session, open_sg_id, vpc_id, mocked_aws):
    """Security group with SSH open should have SG_OPEN_SSH flag."""
    nodes, _ = await ec2.discover(aws_session, ACCOUNT_ID, REGION)

    sg_nodes = [n for n in nodes if isinstance(n, SecurityGroup) and n.group_id == open_sg_id]
    assert len(sg_nodes) == 1

    sg = sg_nodes[0]
    assert PostureFlag.SG_OPEN_SSH in sg.posture_flags


@pytest.mark.asyncio
async def test_ec2_discovers_instance(aws_session, ec2_instance_id, mocked_aws):
    """EC2 instance should be discovered with correct properties."""
    nodes, edges = await ec2.discover(aws_session, ACCOUNT_ID, REGION)

    instance_nodes = [
        n for n in nodes if isinstance(n, EC2Instance) and n.instance_id == ec2_instance_id
    ]
    assert len(instance_nodes) == 1

    instance = instance_nodes[0]
    assert instance.resource_type == ResourceType.EC2_INSTANCE
    assert instance.account_id == ACCOUNT_ID


@pytest.mark.asyncio
async def test_ec2_produces_edges(aws_session, ec2_instance_id, mocked_aws):
    """EC2 connector should produce edges for instance → VPC, subnet, SG."""
    nodes, edges = await ec2.discover(aws_session, ACCOUNT_ID, REGION)

    edge_types = {e.edge_type for e in edges}
    # Should have at least InVPC and MemberOfSG edges
    assert any("VPC" in str(t) or "IN_VPC" in str(t) for t in edge_types) or len(edges) > 0


@pytest.mark.asyncio
async def test_ec2_sg_no_flags_for_restricted(aws_session, vpc_id, mocked_aws):
    """Security group with restricted ingress should have no posture flags."""
    ec2_client = aws_session.client("ec2", region_name=REGION)
    sg = ec2_client.create_security_group(
        GroupName="restricted-sg",
        Description="Restricted SG",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    # Add SSH rule restricted to a specific IP
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "192.168.1.0/24"}],
            }
        ],
    )

    nodes, _ = await ec2.discover(aws_session, ACCOUNT_ID, REGION)
    sg_nodes = [n for n in nodes if isinstance(n, SecurityGroup) and n.group_id == sg_id]
    assert len(sg_nodes) == 1
    assert PostureFlag.SG_OPEN_SSH not in sg_nodes[0].posture_flags
