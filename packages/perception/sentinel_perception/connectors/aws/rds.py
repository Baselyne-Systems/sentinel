"""
RDS connector — discovers RDS instances and their security properties.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from sentinel_core.models.edges import InVPC, MemberOfSG
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import GraphNode, RDSInstance

from sentinel_perception.connectors.aws.base import paginate, run_sync

logger = logging.getLogger(__name__)


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str,
) -> tuple[list[GraphNode], list[Any]]:
    """Discover all RDS instances in the region."""
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    rds = await run_sync(lambda: session.client("rds", region_name=region))

    raw_instances = await run_sync(paginate, rds, "describe_db_instances", "DBInstances")

    for raw in raw_instances:
        db_id = raw["DBInstanceIdentifier"]
        node_id = raw.get("DbiResourceId", db_id)

        sg_ids = [sg["VpcSecurityGroupId"] for sg in raw.get("VpcSecurityGroups", [])]
        vpc_id = raw.get("DBSubnetGroup", {}).get("VpcId")

        endpoint = raw.get("Endpoint", {})
        endpoint_addr = endpoint.get("Address") if endpoint else None
        port = endpoint.get("Port") if endpoint else None

        publicly_accessible = raw.get("PubliclyAccessible", False)
        encrypted = raw.get("StorageEncrypted", False)
        multi_az = raw.get("MultiAZ", False)
        deletion_protection = raw.get("DeletionProtection", False)

        posture_flags: list[PostureFlag] = []
        if publicly_accessible:
            posture_flags.append(PostureFlag.RDS_PUBLIC)
        if not encrypted:
            posture_flags.append(PostureFlag.RDS_NO_ENCRYPTION)
        if not multi_az:
            posture_flags.append(PostureFlag.RDS_NO_MULTI_AZ)

        instance = RDSInstance(
            node_id=node_id,
            account_id=account_id,
            region=region,
            db_id=db_id,
            engine=raw.get("Engine", ""),
            engine_version=raw.get("EngineVersion", ""),
            instance_class=raw.get("DBInstanceClass", ""),
            publicly_accessible=publicly_accessible,
            encrypted=encrypted,
            multi_az=multi_az,
            db_subnet_group=raw.get("DBSubnetGroup", {}).get("DBSubnetGroupName", ""),
            security_group_ids=sg_ids,
            vpc_id=vpc_id,
            endpoint=endpoint_addr,
            port=port,
            status=raw.get("DBInstanceStatus", ""),
            deletion_protection=deletion_protection,
            tags={t["Key"]: t["Value"] for t in raw.get("TagList", [])},
            posture_flags=posture_flags,
        )
        nodes.append(instance)

        # Edge: RDS → VPC
        if vpc_id:
            edges.append(
                InVPC(from_node_id=node_id, to_node_id=vpc_id, account_id=account_id)
            )

        # Edges: RDS → SecurityGroups
        for sg_id in sg_ids:
            edges.append(
                MemberOfSG(from_node_id=node_id, to_node_id=sg_id, account_id=account_id)
            )

    logger.info(
        "RDS discovery [%s]: %d instances",
        region,
        len(nodes),
    )
    return nodes, edges
