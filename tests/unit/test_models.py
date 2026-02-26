"""Unit tests for core Pydantic models."""

from __future__ import annotations

from datetime import datetime

from sentinel_core.models.edges import (
    HasAttachedPolicy,
    InVPC,
)
from sentinel_core.models.enums import CloudProvider, EdgeType, PostureFlag, ResourceType
from sentinel_core.models.nodes import (
    EC2Instance,
    IAMUser,
    RDSInstance,
    S3Bucket,
    SecurityGroup,
)


def test_graph_node_base_fields():
    """GraphNode subclass should have all base fields."""
    node = S3Bucket(
        node_id="s3-my-bucket",
        account_id="123456789012",
        region="us-east-1",
        name="my-bucket",
    )
    assert node.node_id == "s3-my-bucket"
    assert node.account_id == "123456789012"
    assert node.cloud_provider == CloudProvider.AWS
    assert isinstance(node.discovered_at, datetime)
    assert node.posture_flags == []


def test_s3_bucket_model():
    bucket = S3Bucket(
        node_id="s3-test",
        account_id="123",
        name="test",
        is_public=True,
        versioning=False,
        encryption=False,
        logging=False,
        posture_flags=[PostureFlag.S3_PUBLIC_ACCESS],
    )
    assert bucket.is_public is True
    assert bucket.resource_type == ResourceType.S3_BUCKET
    assert PostureFlag.S3_PUBLIC_ACCESS in bucket.posture_flags


def test_security_group_model():
    sg = SecurityGroup(
        node_id="sg-12345",
        account_id="123",
        region="us-east-1",
        group_id="sg-12345",
        name="test-sg",
        inbound_rules=[
            {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}
        ],
        posture_flags=[PostureFlag.SG_OPEN_SSH],
    )
    assert sg.resource_type == ResourceType.SECURITY_GROUP
    assert len(sg.inbound_rules) == 1
    assert PostureFlag.SG_OPEN_SSH in sg.posture_flags


def test_iam_user_model():
    user = IAMUser(
        node_id="AIDAUSER123",
        account_id="123",
        user_id="AIDAUSER123",
        name="test-user",
        arn="arn:aws:iam::123:user/test-user",
        has_mfa=False,
        has_console_access=True,
        posture_flags=[PostureFlag.IAM_NO_MFA],
    )
    assert user.has_mfa is False
    assert user.has_console_access is True
    assert user.resource_type == ResourceType.IAM_USER


def test_rds_instance_model():
    rds = RDSInstance(
        node_id="db-ABC123",
        account_id="123",
        region="us-east-1",
        db_id="my-db",
        engine="mysql",
        publicly_accessible=True,
        encrypted=False,
        posture_flags=[PostureFlag.RDS_PUBLIC, PostureFlag.RDS_NO_ENCRYPTION],
    )
    assert rds.resource_type == ResourceType.RDS_INSTANCE
    assert rds.publicly_accessible is True


def test_neo4j_props_serialization():
    """to_neo4j_props() should return a flat JSON-safe dict."""
    bucket = S3Bucket(
        node_id="s3-test",
        account_id="123",
        name="test",
        tags={"env": "prod"},
        posture_flags=[PostureFlag.S3_PUBLIC_ACCESS],
    )
    props = bucket.to_neo4j_props()
    assert props["node_id"] == "s3-test"
    assert "S3_PUBLIC_ACCESS" in props["posture_flags"]
    assert isinstance(props["posture_flags"], list)
    assert isinstance(props["discovered_at"], str)


def test_neo4j_labels():
    bucket = S3Bucket(node_id="x", account_id="123", name="x")
    labels = bucket.neo4j_labels()
    assert "GraphNode" in labels
    assert "S3Bucket" in labels


def test_edge_models():
    edge = InVPC(
        from_node_id="i-12345",
        to_node_id="vpc-67890",
        account_id="123",
    )
    assert edge.edge_type == EdgeType.IN_VPC

    edge2 = HasAttachedPolicy(
        from_node_id="role-id",
        to_node_id="policy-id",
        account_id="123",
        attachment_type="managed",
    )
    assert edge2.edge_type == EdgeType.HAS_ATTACHED_POLICY
    assert edge2.attachment_type == "managed"


def test_ec2_instance_model():
    instance = EC2Instance(
        node_id="i-12345",
        account_id="123",
        region="us-east-1",
        instance_id="i-12345",
        instance_type="t3.micro",
        state="running",
        public_ip="1.2.3.4",
        private_ip="10.0.1.5",
    )
    assert instance.resource_type == ResourceType.EC2_INSTANCE
    assert instance.state == "running"
