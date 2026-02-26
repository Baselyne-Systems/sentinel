"""
Lambda connector — discovers Lambda functions and their security properties.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from sentinel_core.models.edges import InVPC, MemberOfSG
from sentinel_core.models.nodes import GraphNode, LambdaFunction

from sentinel_perception.connectors.aws.base import paginate, run_sync

logger = logging.getLogger(__name__)


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str,
) -> tuple[list[GraphNode], list[Any]]:
    """Discover all Lambda functions in the region."""
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    lmb = await run_sync(lambda: session.client("lambda", region_name=region))

    raw_functions = await run_sync(paginate, lmb, "list_functions", "Functions")

    for raw in raw_functions:
        arn = raw["FunctionArn"]
        function_name = raw["FunctionName"]
        # Use ARN as node_id for uniqueness across regions
        node_id = arn

        vpc_config = raw.get("VpcConfig") or {}
        sg_ids = vpc_config.get("SecurityGroupIds", [])
        vpc_id = vpc_config.get("VpcId")

        env_vars = raw.get("Environment", {}).get("Variables", {})
        role_arn = raw.get("Role", "")

        fn = LambdaFunction(
            node_id=node_id,
            account_id=account_id,
            region=region,
            function_name=function_name,
            arn=arn,
            runtime=raw.get("Runtime", ""),
            role_arn=role_arn,
            handler=raw.get("Handler", ""),
            code_size=raw.get("CodeSize", 0),
            memory_size=raw.get("MemorySize", 128),
            timeout=raw.get("Timeout", 3),
            vpc_config=vpc_config,
            environment_variables={k: "***" for k in env_vars},  # Mask values
            last_modified=raw.get("LastModified", ""),
        )
        nodes.append(fn)

        # Edge: Lambda → VPC
        if vpc_id:
            edges.append(InVPC(from_node_id=node_id, to_node_id=vpc_id, account_id=account_id))

        # Edge: Lambda → SecurityGroups
        for sg_id in sg_ids:
            edges.append(MemberOfSG(from_node_id=node_id, to_node_id=sg_id, account_id=account_id))

        # Edge: Lambda → IAMRole (ExecutesAs)
        if role_arn:
            # Derive role_id from ARN: arn:aws:iam::123456789012:role/MyRole → role name
            # We'll use the ARN itself as the from_node_id and the role ARN as to_node_id
            # The IAM connector uses role_id (from ListRoles) as the node_id
            # We store role_arn on the function for later resolution
            pass  # Resolved in graph_builder after IAM nodes are available

    logger.info(
        "Lambda discovery [%s]: %d functions",
        region,
        len(nodes),
    )
    return nodes, edges
