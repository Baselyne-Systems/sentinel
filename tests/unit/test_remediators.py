"""
Unit tests for individual remediator functions.

Each remediator is tested with a mocked boto3 session to verify:
- The correct boto3 API method is called.
- The correct parameters are passed.
- The returned summary dict has the expected structure.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel_remediation.remediators import cloudtrail, ec2, rds, s3


# ── Helpers ────────────────────────────────────────────────────────────────────


def _mock_session() -> MagicMock:
    """Return a MagicMock that behaves like a boto3.Session."""
    return MagicMock()


# ── S3 remediators ─────────────────────────────────────────────────────────────


def test_s3_block_public_access_calls_put_public_access_block():
    session = _mock_session()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    result = s3.block_public_access({"bucket_name": "my-bucket"}, session)

    session.client.assert_called_once_with("s3")
    s3_client.put_public_access_block.assert_called_once_with(
        Bucket="my-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert result["bucket_name"] == "my-bucket"
    assert result["public_access_blocked"] is True


def test_s3_enable_versioning_calls_put_bucket_versioning():
    session = _mock_session()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    result = s3.enable_versioning({"bucket_name": "my-bucket"}, session)

    s3_client.put_bucket_versioning.assert_called_once_with(
        Bucket="my-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    assert result["versioning_status"] == "Enabled"


def test_s3_enable_sse_calls_put_bucket_encryption():
    session = _mock_session()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    result = s3.enable_sse({"bucket_name": "my-bucket"}, session)

    s3_client.put_bucket_encryption.assert_called_once()
    call_kwargs = s3_client.put_bucket_encryption.call_args.kwargs
    assert call_kwargs["Bucket"] == "my-bucket"
    rules = call_kwargs["ServerSideEncryptionConfiguration"]["Rules"]
    assert rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    assert result["encryption"] == "AES256"


def test_s3_enable_logging_default_target():
    session = _mock_session()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    result = s3.enable_logging({"bucket_name": "my-bucket"}, session)

    s3_client.put_bucket_logging.assert_called_once()
    call_kwargs = s3_client.put_bucket_logging.call_args.kwargs
    assert call_kwargs["Bucket"] == "my-bucket"
    logging_cfg = call_kwargs["BucketLoggingStatus"]["LoggingEnabled"]
    # Default target is the bucket itself
    assert logging_cfg["TargetBucket"] == "my-bucket"
    assert logging_cfg["TargetPrefix"] == "logs/"
    assert result["logging_enabled"] is True


def test_s3_enable_logging_custom_target():
    session = _mock_session()
    s3_client = MagicMock()
    session.client.return_value = s3_client

    result = s3.enable_logging(
        {"bucket_name": "my-bucket", "target_bucket": "log-bucket", "target_prefix": "s3-logs/"},
        session,
    )

    call_kwargs = s3_client.put_bucket_logging.call_args.kwargs
    logging_cfg = call_kwargs["BucketLoggingStatus"]["LoggingEnabled"]
    assert logging_cfg["TargetBucket"] == "log-bucket"
    assert logging_cfg["TargetPrefix"] == "s3-logs/"
    assert result["target_bucket"] == "log-bucket"


# ── EC2 remediators ────────────────────────────────────────────────────────────


def test_ec2_enable_ebs_encryption_calls_enable_ebs_encryption_by_default():
    session = _mock_session()
    ec2_client = MagicMock()
    session.client.return_value = ec2_client

    result = ec2.enable_ebs_encryption({"region": "us-east-1"}, session)

    session.client.assert_called_once_with("ec2", region_name="us-east-1")
    ec2_client.enable_ebs_encryption_by_default.assert_called_once()
    assert result["region"] == "us-east-1"
    assert result["ebs_encryption_by_default"] is True


# ── CloudTrail remediators ─────────────────────────────────────────────────────


def test_cloudtrail_enable_log_validation():
    session = _mock_session()
    ct_client = MagicMock()
    session.client.return_value = ct_client

    result = cloudtrail.enable_log_validation(
        {"trail_name": "my-trail", "region": "us-east-1"},
        session,
    )

    session.client.assert_called_once_with("cloudtrail", region_name="us-east-1")
    ct_client.update_trail.assert_called_once_with(
        Name="my-trail", EnableLogFileValidation=True
    )
    assert result["trail_name"] == "my-trail"
    assert result["log_file_validation_enabled"] is True


def test_cloudtrail_enable_trail_creates_trail_and_starts_logging():
    """Test enable_trail when no trail exists yet."""
    session = _mock_session()
    ct_client = MagicMock()
    s3_client = MagicMock()

    # First call to session.client("cloudtrail") returns ct_client,
    # subsequent call to session.client("s3") returns s3_client.
    def _client_factory(service, **kwargs):
        if service == "cloudtrail":
            return ct_client
        return s3_client

    session.client.side_effect = _client_factory

    # No existing trail
    ct_client.describe_trails.return_value = {"trailList": []}
    ct_client.create_trail.return_value = {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/sentinel-trail"
    }

    result = cloudtrail.enable_trail(
        {"account_id": "123456789012", "region": "us-east-1"},
        session,
    )

    ct_client.create_trail.assert_called_once()
    ct_client.start_logging.assert_called_once()
    assert result["logging_started"] is True
    assert result["trail_name"] == "sentinel-trail"


def test_cloudtrail_enable_trail_starts_logging_on_existing_trail():
    """Test enable_trail when a trail already exists."""
    session = _mock_session()
    ct_client = MagicMock()
    session.client.return_value = ct_client

    ct_client.describe_trails.return_value = {
        "trailList": [{"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/sentinel-trail"}]
    }

    result = cloudtrail.enable_trail(
        {"account_id": "123456789012", "region": "us-east-1"},
        session,
    )

    # Should NOT call create_trail — trail already exists
    ct_client.create_trail.assert_not_called()
    ct_client.start_logging.assert_called_once_with(
        Name="arn:aws:cloudtrail:us-east-1:123:trail/sentinel-trail"
    )
    assert result["logging_started"] is True


# ── RDS remediators ────────────────────────────────────────────────────────────


def test_rds_disable_public_access_calls_modify_db_instance():
    session = _mock_session()
    rds_client = MagicMock()
    session.client.return_value = rds_client

    result = rds.disable_public_access(
        {"db_id": "my-postgres-db", "region": "us-west-2"},
        session,
    )

    session.client.assert_called_once_with("rds", region_name="us-west-2")
    rds_client.modify_db_instance.assert_called_once_with(
        DBInstanceIdentifier="my-postgres-db",
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    assert result["db_id"] == "my-postgres-db"
    assert result["publicly_accessible"] is False
