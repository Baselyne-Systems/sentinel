"""
S3 remediators — four safe, reversible S3 hardening actions.

Each function follows the remediator interface:

    def execute(params: dict, session: boto3.Session) -> dict

Called via ``asyncio.to_thread()`` from the async executor layer.
``params`` is the ``RemediationProposal.params`` dict built by the planner.

All actions are reversible:
  - Block Public Access  → can be disabled via put_public_access_block
  - Enable Versioning    → can be suspended (not deleted)
  - Enable SSE           → can be reconfigured
  - Enable Logging       → can be disabled via put_bucket_logging({})
"""

from __future__ import annotations


def block_public_access(params: dict, session) -> dict:
    """Enable S3 Block Public Access on a bucket.

    Blocks all four public-access vectors (ACL and policy based).

    Required params:
        bucket_name: Name of the S3 bucket.

    Returns:
        Summary dict with bucket_name and enabled flag.
    """
    bucket_name: str = params["bucket_name"]
    s3 = session.client("s3")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return {"bucket_name": bucket_name, "public_access_blocked": True}


def enable_versioning(params: dict, session) -> dict:
    """Enable object versioning on an S3 bucket.

    Required params:
        bucket_name: Name of the S3 bucket.

    Returns:
        Summary dict with bucket_name and versioning_status.
    """
    bucket_name: str = params["bucket_name"]
    s3 = session.client("s3")
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    return {"bucket_name": bucket_name, "versioning_status": "Enabled"}


def enable_sse(params: dict, session) -> dict:
    """Enable server-side encryption (AES-256) on an S3 bucket.

    Required params:
        bucket_name: Name of the S3 bucket.

    Returns:
        Summary dict with bucket_name and encryption rule applied.
    """
    bucket_name: str = params["bucket_name"]
    s3 = session.client("s3")
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
    return {"bucket_name": bucket_name, "encryption": "AES256"}


def enable_logging(params: dict, session) -> dict:
    """Enable S3 access logging, writing logs to a target bucket.

    If no ``target_bucket`` is provided in params, logs are written to
    the same bucket under the ``logs/`` prefix (self-logging).

    Required params:
        bucket_name:   Name of the S3 bucket to enable logging on.
    Optional params:
        target_bucket: Destination bucket for logs (defaults to bucket_name).
        target_prefix: Log object key prefix (defaults to "logs/").

    Returns:
        Summary dict with bucket_name, target_bucket, target_prefix.
    """
    bucket_name: str = params["bucket_name"]
    target_bucket: str = params.get("target_bucket", bucket_name)
    target_prefix: str = params.get("target_prefix", "logs/")
    s3 = session.client("s3")
    s3.put_bucket_logging(
        Bucket=bucket_name,
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": target_bucket,
                "TargetPrefix": target_prefix,
            }
        },
    )
    return {
        "bucket_name": bucket_name,
        "target_bucket": target_bucket,
        "target_prefix": target_prefix,
        "logging_enabled": True,
    }
