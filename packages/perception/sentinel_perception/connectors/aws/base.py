"""
Base utilities shared by all AWS connectors.

This module provides:
- ``get_session``: Create a boto3 session, optionally assuming a cross-account role
- ``paginate``: Collect all pages from a paginated boto3 API call
- ``run_sync``: Wrap synchronous boto3 calls for use in async code
- ``safe_get``: Call a boto3 method, returning a default on ClientError

Design note on async:
    boto3 is synchronous. All network I/O in the connectors runs via
    ``asyncio.to_thread()`` (wrapped by ``run_sync``), which places the
    blocking call on a thread pool executor. This keeps the event loop free
    while AWS API calls are in flight and allows multiple regions/services
    to be scanned concurrently via ``asyncio.gather()``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TypeVar

import boto3
import botocore.exceptions

logger = logging.getLogger(__name__)

T = TypeVar("T")


def get_session(region: str, assume_role_arn: str | None = None) -> boto3.Session:
    """Create a boto3 Session, optionally assuming a cross-account IAM role.

    This function is synchronous and should be called via ``asyncio.to_thread()``
    in async contexts (see ``graph_builder.py`` for examples).

    Args:
        region: AWS region name, e.g. ``"us-east-1"``.
        assume_role_arn: Optional IAM Role ARN to assume via STS. When provided,
            returns a session with temporary credentials scoped to that role.
            Required for cross-account scanning.

    Returns:
        A configured ``boto3.Session`` pointing at the specified region.

    Raises:
        botocore.exceptions.ClientError: if STS AssumeRole fails (e.g. role
            doesn't exist, insufficient permissions).

    Example::

        session = get_session("us-east-1")
        session_xaccount = get_session(
            "us-east-1",
            assume_role_arn="arn:aws:iam::123456789012:role/SentinelReadOnly",
        )
    """
    if assume_role_arn:
        sts = boto3.client("sts", region_name=region)
        creds = sts.assume_role(
            RoleArn=assume_role_arn,
            RoleSessionName="sentinel-discovery",
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    return boto3.Session(region_name=region)


def paginate(client: Any, method: str, key: str, **kwargs: Any) -> list[dict]:
    """Collect all pages from a paginated boto3 API call.

    Uses the boto3 paginator API to automatically handle ``NextToken`` /
    ``NextMarker`` pagination.

    Args:
        client: A boto3 service client (e.g. from ``session.client("ec2")``).
        method: Paginator name, e.g. ``"describe_instances"``.
        key: The key in each page response that holds the items list,
            e.g. ``"Reservations"`` for describe_instances.
        **kwargs: Additional keyword arguments passed to the paginator.

    Returns:
        Flat list of all items across all pages.

    Raises:
        botocore.exceptions.OperationNotPageableError: if the method doesn't
            support pagination. Use ``safe_get`` for non-paginated calls.

    Example::

        roles = paginate(iam_client, "list_roles", "Roles")
        instances = paginate(ec2_client, "describe_instances", "Reservations",
                             Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
    """
    paginator = client.get_paginator(method)
    items = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


async def run_sync(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a synchronous callable in a thread pool executor.

    This is the standard way to call boto3 (synchronous) from async code
    in SENTINEL. Under the hood it uses ``asyncio.to_thread()``, which
    runs ``fn(*args, **kwargs)`` on the default ThreadPoolExecutor.

    Args:
        fn: Any synchronous callable (typically a boto3 method or ``paginate``).
        *args: Positional arguments forwarded to ``fn``.
        **kwargs: Keyword arguments forwarded to ``fn``.

    Returns:
        The return value of ``fn(*args, **kwargs)``.

    Example::

        roles = await run_sync(paginate, iam_client, "list_roles", "Roles")
        response = await run_sync(s3_client.list_buckets)
    """
    return await asyncio.to_thread(fn, *args, **kwargs)


def safe_get(client: Any, method: str, default: Any = None, **kwargs: Any) -> Any:
    """Call a boto3 method and return ``default`` on ``ClientError``.

    Many S3/IAM/RDS properties are optional and boto3 raises ``ClientError``
    (e.g. ``NoSuchBucketPolicy``, ``NoSuchEntity``) when they aren't set.
    This helper avoids ``try/except`` boilerplate throughout connectors.

    Args:
        client: A boto3 service client.
        method: Method name to call on the client, e.g. ``"get_bucket_policy"``.
        default: Value to return on ``ClientError``. Defaults to ``None``.
        **kwargs: Keyword arguments passed to the boto3 method.

    Returns:
        The response from the boto3 call, or ``default`` on any ``ClientError``.

    Example::

        # Returns None if no policy exists
        policy = safe_get(s3_client, "get_bucket_policy", default=None, Bucket=name)

        # Returns {"MFADevices": []} if call fails
        mfa = safe_get(iam_client, "list_mfa_devices",
                       default={"MFADevices": []}, UserName=username)
    """
    try:
        return getattr(client, method)(**kwargs)
    except botocore.exceptions.ClientError as e:
        logger.debug("boto3 %s failed: %s", method, e)
        return default
