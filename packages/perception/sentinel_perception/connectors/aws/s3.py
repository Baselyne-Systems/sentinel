"""
S3 connector — discovers S3 buckets and their security properties.

S3 is global; we use the bucket's region to stamp the node.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import GraphNode, S3Bucket

from sentinel_perception.connectors.aws.base import run_sync, safe_get

logger = logging.getLogger(__name__)


def _is_acl_public(acl: dict) -> bool:
    """Return True if the ACL grants public (AllUsers/AuthenticatedUsers) access."""
    public_grantees = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in public_grantees:
            return True
    return False


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str = "",
) -> tuple[list[GraphNode], list[Any]]:
    """
    Discover all S3 buckets and their security configuration.

    Note: S3 ListBuckets is global; we use us-east-1 for the initial listing
    then check each bucket's region.
    """
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    s3 = await run_sync(lambda: session.client("s3", region_name="us-east-1"))

    raw_buckets_resp = await run_sync(s3.list_buckets)
    raw_buckets = raw_buckets_resp.get("Buckets", [])

    for raw in raw_buckets:
        name = raw["Name"]
        creation_date = raw.get("CreationDate")

        # Determine bucket region
        location = await run_sync(safe_get, s3, "get_bucket_location", default={}, Bucket=name)
        bucket_region = location.get("LocationConstraint") or "us-east-1"

        # Filter by requested region if provided
        if region and bucket_region != region:
            continue

        # ── Security properties ────────────────────────────────────────────────
        # Public access block
        pab = await run_sync(safe_get, s3, "get_public_access_block", default={}, Bucket=name)
        pab_config = pab.get("PublicAccessBlockConfiguration", {})
        block_all_public = (
            pab_config.get("BlockPublicAcls", False)
            and pab_config.get("BlockPublicPolicy", False)
            and pab_config.get("IgnorePublicAcls", False)
            and pab_config.get("RestrictPublicBuckets", False)
        )

        # ACL
        acl = await run_sync(safe_get, s3, "get_bucket_acl", default={}, Bucket=name)
        acl_public = _is_acl_public(acl)

        # Bucket policy
        policy_raw = await run_sync(safe_get, s3, "get_bucket_policy", default=None, Bucket=name)
        policy_exists = policy_raw is not None and "Policy" in policy_raw

        # Encryption
        enc = await run_sync(safe_get, s3, "get_bucket_encryption", default=None, Bucket=name)
        has_encryption = enc is not None and "ServerSideEncryptionConfiguration" in enc

        # Versioning
        ver = await run_sync(safe_get, s3, "get_bucket_versioning", default={}, Bucket=name)
        has_versioning = ver.get("Status") == "Enabled"

        # Logging
        log = await run_sync(safe_get, s3, "get_bucket_logging", default={}, Bucket=name)
        has_logging = "LoggingEnabled" in log

        # Determine public: no block AND (acl_public OR no policy)
        is_public = not block_all_public and (acl_public or not policy_exists)

        # Posture flags
        posture_flags: list[PostureFlag] = []
        if is_public:
            posture_flags.append(PostureFlag.S3_PUBLIC_ACCESS)
        if not has_versioning:
            posture_flags.append(PostureFlag.S3_NO_VERSIONING)
        if not has_encryption:
            posture_flags.append(PostureFlag.S3_NO_ENCRYPTION)
        if not has_logging:
            posture_flags.append(PostureFlag.S3_NO_LOGGING)

        bucket = S3Bucket(
            node_id=f"s3-{name}",
            account_id=account_id,
            region=bucket_region,
            name=name,
            is_public=is_public,
            versioning=has_versioning,
            encryption=has_encryption,
            logging=has_logging,
            public_access_block=block_all_public,
            creation_date=creation_date,
            policy_exists=policy_exists,
            acl_public=acl_public,
            posture_flags=posture_flags,
        )
        nodes.append(bucket)

    logger.info("S3 discovery: %d buckets", len(nodes))
    return nodes, edges
