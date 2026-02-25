"""Unit tests for the S3 connector."""

from __future__ import annotations

import pytest

from sentinel_core.models.enums import PostureFlag, ResourceType
from sentinel_core.models.nodes import S3Bucket
from sentinel_perception.connectors.aws import s3

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.mark.asyncio
async def test_s3_discovers_public_bucket(aws_session, public_s3_bucket, mocked_aws):
    """Public S3 bucket should be discovered with S3_PUBLIC_ACCESS flag."""
    nodes, edges = await s3.discover(aws_session, ACCOUNT_ID)

    bucket_nodes = [n for n in nodes if isinstance(n, S3Bucket) and n.name == public_s3_bucket]
    assert len(bucket_nodes) == 1

    bucket = bucket_nodes[0]
    assert bucket.is_public is True
    assert PostureFlag.S3_PUBLIC_ACCESS in bucket.posture_flags


@pytest.mark.asyncio
async def test_s3_discovers_private_bucket(aws_session, private_s3_bucket, mocked_aws):
    """Private S3 bucket should be discovered without S3_PUBLIC_ACCESS flag."""
    nodes, _ = await s3.discover(aws_session, ACCOUNT_ID)

    bucket_nodes = [n for n in nodes if isinstance(n, S3Bucket) and n.name == private_s3_bucket]
    assert len(bucket_nodes) == 1

    bucket = bucket_nodes[0]
    assert bucket.is_public is False
    assert PostureFlag.S3_PUBLIC_ACCESS not in bucket.posture_flags
    assert bucket.versioning is True
    assert bucket.encryption is True


@pytest.mark.asyncio
async def test_s3_node_has_correct_resource_type(aws_session, public_s3_bucket, mocked_aws):
    """S3Bucket nodes should have the correct resource_type."""
    nodes, _ = await s3.discover(aws_session, ACCOUNT_ID)

    for node in nodes:
        assert isinstance(node, S3Bucket)
        assert node.resource_type == ResourceType.S3_BUCKET
        assert node.account_id == ACCOUNT_ID


@pytest.mark.asyncio
async def test_s3_no_versioning_flag(aws_session, public_s3_bucket, mocked_aws):
    """S3 buckets without versioning should have S3_NO_VERSIONING flag."""
    nodes, _ = await s3.discover(aws_session, ACCOUNT_ID)

    bucket = next(n for n in nodes if isinstance(n, S3Bucket) and n.name == public_s3_bucket)
    assert PostureFlag.S3_NO_VERSIONING in bucket.posture_flags


@pytest.mark.asyncio
async def test_s3_no_logging_flag(aws_session, public_s3_bucket, mocked_aws):
    """S3 buckets without logging should have S3_NO_LOGGING flag."""
    nodes, _ = await s3.discover(aws_session, ACCOUNT_ID)

    bucket = next(n for n in nodes if isinstance(n, S3Bucket) and n.name == public_s3_bucket)
    assert PostureFlag.S3_NO_LOGGING in bucket.posture_flags
