# Adding a New AWS Connector

This guide walks through adding a connector for a new AWS service (e.g. CloudFront, EKS, Route 53).

## Overview

Each connector is a single Python file in:
```
packages/perception/sentinel_perception/connectors/aws/<service>.py
```

A connector must implement one async function:
```python
async def discover(
    session: boto3.Session,
    account_id: str,
    region: str,
) -> tuple[list[GraphNode], list[Any]]:
    ...
```

It returns **(nodes, edges)** — Pydantic models from `sentinel_core`.

---

## Step 1: Add a node model

Add your resource type to `packages/core/sentinel_core/models/nodes.py`:

```python
class CloudFrontDistribution(GraphNode):
    resource_type: ResourceType = ResourceType.CLOUDFRONT_DISTRIBUTION
    distribution_id: str
    domain_name: str
    enabled: bool = True
    is_public: bool = True
    # ... other fields
```

And add the enum value to `models/enums.py`:

```python
class ResourceType(StrEnum):
    # ... existing values
    CLOUDFRONT_DISTRIBUTION = "CloudFrontDistribution"
```

---

## Step 2: Write the connector

Create `packages/perception/sentinel_perception/connectors/aws/cloudfront.py`:

```python
"""CloudFront connector — discovers CloudFront distributions."""

from __future__ import annotations

import logging
from typing import Any

import boto3

from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import CloudFrontDistribution, GraphNode
from sentinel_perception.connectors.aws.base import paginate, run_sync

logger = logging.getLogger(__name__)


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str = "us-east-1",  # CloudFront is global, use us-east-1
) -> tuple[list[GraphNode], list[Any]]:
    """Discover all CloudFront distributions.

    Args:
        session: boto3 session (may be cross-account).
        account_id: AWS account ID.
        region: Ignored for CloudFront (global service), kept for interface consistency.

    Returns:
        Tuple of (nodes, edges).
    """
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    cf = await run_sync(lambda: session.client("cloudfront", region_name="us-east-1"))

    raw_dists = await run_sync(
        paginate, cf, "list_distributions", "DistributionList.Items"
    )

    for raw in raw_dists:
        dist_id = raw["Id"]
        posture_flags = []

        # Example: flag distributions without HTTPS
        if raw.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy") == "allow-all":
            posture_flags.append(PostureFlag.CLOUDFRONT_NO_HTTPS)  # add to enums too

        dist = CloudFrontDistribution(
            node_id=dist_id,
            account_id=account_id,
            region="global",
            distribution_id=dist_id,
            domain_name=raw.get("DomainName", ""),
            enabled=raw.get("Enabled", True),
            posture_flags=posture_flags,
        )
        nodes.append(dist)

    logger.info("CloudFront discovery: %d distributions", len(nodes))
    return nodes, edges
```

Key rules:
- Use `await run_sync(...)` for all boto3 calls
- Use `paginate()` for paginated APIs, `safe_get()` for optional properties
- Set `posture_flags` during discovery when possible (before Neo4j writes)
- Log a summary at INFO level

---

## Step 3: Register in GraphBuilder

Add your connector to `packages/perception/sentinel_perception/graph_builder.py`:

```python
# In _scan_region():
from sentinel_perception.connectors.aws import cloudfront  # add import

connector_tasks = [
    ec2.discover(session, account_id, region),
    lambda_.discover(session, account_id, region),
    rds.discover(session, account_id, region),
    cloudfront.discover(session, account_id),  # <-- add here
]
connector_names = ["EC2", "Lambda", "RDS", "CloudFront"]  # <-- add name
```

For global services (like CloudFront, IAM, S3), add them in `full_scan()` alongside
the existing IAM and S3 blocks rather than inside `_scan_region()`.

---

## Step 4: Add CIS rules (optional)

If your service has CIS benchmark rules, add them to:
`packages/core/sentinel_core/knowledge/rules.py`

See [cis-rules.md](cis-rules.md) for instructions.

---

## Step 5: Write tests

Add a test file at `tests/unit/connectors/test_cloudfront.py`:

```python
"""Unit tests for the CloudFront connector."""

import pytest
from moto import mock_aws

from sentinel_perception.connectors.aws import cloudfront

@pytest.mark.asyncio
async def test_cloudfront_discovers_distributions(aws_session, mocked_aws):
    """CloudFront distributions should be discovered."""
    # Set up moto fixtures here
    nodes, edges = await cloudfront.discover(aws_session, "123456789012")
    assert len(nodes) >= 0  # no crash
```

Use the `mocked_aws` fixture from `tests/conftest.py` for moto context.

---

## Checklist

- [ ] Node model added to `models/nodes.py`
- [ ] ResourceType enum value added to `models/enums.py`
- [ ] Connector file created in `connectors/aws/`
- [ ] Connector registered in `graph_builder.py`
- [ ] PostureFlags for the service added (if applicable)
- [ ] CIS rules added (if applicable)
- [ ] Unit tests written
- [ ] `make test` passes
- [ ] `make lint` passes
