"""
Shared pytest fixtures for SENTINEL tests.

Creates a moto-mocked AWS environment with known-bad configurations:
- 1 VPC, 2 subnets, 1 EC2 instance (running)
- 1 public S3 bucket (deliberate CIS-2.1.5 violation)
- 1 SecurityGroup with SSH open to 0.0.0.0/0 (deliberate CIS-3.1 violation)
- 1 IAM role with overly broad policy (deliberate CIS-1.16 violation)
- 1 IAM user without MFA but with console access (deliberate CIS-1.10 violation)
- 1 RDS instance that is publicly accessible + unencrypted (deliberate CIS-2.3.2 + 2.3.1 violation)
"""

from __future__ import annotations

import json
from typing import Generator
from unittest.mock import AsyncMock, MagicMock

import boto3
import pytest
from moto import mock_aws

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


# ── AWS environment fixture ────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def aws_credentials(monkeypatch):
    """Ensure boto3 uses fake credentials with moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture(scope="function")
def mocked_aws(aws_credentials):
    """Start moto mock for all AWS services used by SENTINEL."""
    with mock_aws():
        yield


@pytest.fixture(scope="function")
def aws_session(mocked_aws):
    """Return a boto3 session pointing at moto."""
    return boto3.Session(region_name=REGION)


@pytest.fixture(scope="function")
def vpc_id(aws_session) -> str:
    ec2 = aws_session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    return vpc["Vpc"]["VpcId"]


@pytest.fixture(scope="function")
def subnet_ids(aws_session, vpc_id) -> list[str]:
    ec2 = aws_session.client("ec2", region_name=REGION)
    s1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=f"{REGION}a")
    s2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone=f"{REGION}b")
    return [s1["Subnet"]["SubnetId"], s2["Subnet"]["SubnetId"]]


@pytest.fixture(scope="function")
def open_sg_id(aws_session, vpc_id) -> str:
    """Security group with SSH open to 0.0.0.0/0 — deliberate CIS violation."""
    ec2 = aws_session.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(
        GroupName="open-ssh-sg",
        Description="Deliberately open SG for testing",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Everywhere"}],
            }
        ],
    )
    return sg_id


@pytest.fixture(scope="function")
def ec2_instance_id(aws_session, subnet_ids, open_sg_id) -> str:
    ec2 = aws_session.client("ec2", region_name=REGION)
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_ids[0],
        SecurityGroupIds=[open_sg_id],
    )
    return resp["Instances"][0]["InstanceId"]


@pytest.fixture(scope="function")
def public_s3_bucket(aws_session) -> str:
    """S3 bucket with public ACL — deliberate CIS-2.1.5 violation."""
    s3 = aws_session.client("s3", region_name=REGION)
    bucket_name = "sentinel-test-public-bucket"
    s3.create_bucket(Bucket=bucket_name)
    # Make it public by setting a public ACL
    s3.put_bucket_acl(
        Bucket=bucket_name,
        ACL="public-read",
    )
    return bucket_name


@pytest.fixture(scope="function")
def private_s3_bucket(aws_session) -> str:
    """S3 bucket with block public access — compliant."""
    s3 = aws_session.client("s3", region_name=REGION)
    bucket_name = "sentinel-test-private-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    return bucket_name


@pytest.fixture(scope="function")
def star_policy_arn(aws_session) -> str:
    """IAM policy with Action: '*' — deliberate CIS-1.16 violation."""
    iam = aws_session.client("iam", region_name=REGION)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    resp = iam.create_policy(
        PolicyName="SentinelTestStarPolicy",
        PolicyDocument=json.dumps(policy_doc),
    )
    return resp["Policy"]["Arn"]


@pytest.fixture(scope="function")
def iam_role(aws_session, star_policy_arn) -> dict:
    """IAM role with overly broad policy attached."""
    iam = aws_session.client("iam", region_name=REGION)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName="SentinelTestRole",
        AssumeRolePolicyDocument=json.dumps(trust),
    )
    iam.attach_role_policy(
        RoleName="SentinelTestRole",
        PolicyArn=star_policy_arn,
    )
    return role["Role"]


@pytest.fixture(scope="function")
def iam_user_no_mfa(aws_session) -> dict:
    """IAM user with console access but no MFA — deliberate CIS-1.10 violation."""
    iam = aws_session.client("iam", region_name=REGION)
    user = iam.create_user(UserName="sentinel-test-user")
    iam.create_login_profile(
        UserName="sentinel-test-user",
        Password="TestP@ssw0rd!",
    )
    return user["User"]


@pytest.fixture(scope="function")
def public_rds_instance(aws_session, vpc_id, subnet_ids, open_sg_id):
    """RDS instance that is publicly accessible — deliberate CIS-2.3.2 violation."""
    ec2 = aws_session.client("ec2", region_name=REGION)
    rds = aws_session.client("rds", region_name=REGION)

    # Create subnet group
    rds.create_db_subnet_group(
        DBSubnetGroupName="sentinel-test-subnet-group",
        DBSubnetGroupDescription="Test subnet group",
        SubnetIds=subnet_ids,
    )

    resp = rds.create_db_instance(
        DBInstanceIdentifier="sentinel-test-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TestP@ssw0rd!",
        PubliclyAccessible=True,
        StorageEncrypted=False,
        MultiAZ=False,
        DBSubnetGroupName="sentinel-test-subnet-group",
        VpcSecurityGroupIds=[open_sg_id],
    )
    return resp["DBInstance"]


# ── Mock Neo4j client fixture ──────────────────────────────────────────────────

@pytest.fixture
def mock_neo4j_client():
    """A mock Neo4jClient that captures upserted nodes/edges."""
    client = AsyncMock()
    client.nodes: list = []
    client.edges: list = []

    async def _upsert_node(node):
        client.nodes.append(node)

    async def _upsert_edge(edge):
        client.edges.append(edge)

    client.upsert_node = AsyncMock(side_effect=_upsert_node)
    client.upsert_edge = AsyncMock(side_effect=_upsert_edge)
    client.query = AsyncMock(return_value=[])
    client.execute = AsyncMock()
    client.ensure_indexes = AsyncMock()
    client.clear_account = AsyncMock()

    return client
