"""
EC2 connector — discovers EC2 instances, security groups, VPCs, and subnets.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from sentinel_core.models.edges import InSubnet, InVPC, MemberOfSG
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import VPC, EC2Instance, GraphNode, SecurityGroup, Subnet

from sentinel_perception.connectors.aws.base import paginate, run_sync

logger = logging.getLogger(__name__)

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _sg_flags(inbound_rules: list[dict]) -> list[PostureFlag]:
    """Detect open ingress violations in security group rules."""
    flags: list[PostureFlag] = []
    for rule in inbound_rules:
        cidr = rule.get("cidr", "") or rule.get("cidr_ipv6", "")
        if cidr not in _OPEN_CIDRS:
            continue
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        proto = rule.get("ip_protocol", "-1")

        if proto == "-1" or (from_port == -1 and to_port == -1):
            if PostureFlag.SG_OPEN_ALL_INGRESS not in flags:
                flags.append(PostureFlag.SG_OPEN_ALL_INGRESS)
        elif from_port is not None and to_port is not None:
            if from_port <= 22 <= to_port and PostureFlag.SG_OPEN_SSH not in flags:
                flags.append(PostureFlag.SG_OPEN_SSH)
            if from_port <= 3389 <= to_port and PostureFlag.SG_OPEN_RDP not in flags:
                flags.append(PostureFlag.SG_OPEN_RDP)

    return flags


def _parse_ip_permissions(permissions: list[dict]) -> list[dict]:
    """Normalize boto3 IpPermissions into a flat list of rule dicts."""
    rules = []
    for perm in permissions:
        proto = perm.get("IpProtocol", "-1")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for ip_range in perm.get("IpRanges", []):
            rules.append(
                {
                    "ip_protocol": proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": ip_range.get("CidrIp", ""),
                    "description": ip_range.get("Description", ""),
                }
            )
        for ip_range in perm.get("Ipv6Ranges", []):
            rules.append(
                {
                    "ip_protocol": proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr_ipv6": ip_range.get("CidrIpv6", ""),
                    "description": ip_range.get("Description", ""),
                }
            )
        # SG-to-SG references (no CIDR)
        for sg_ref in perm.get("UserIdGroupPairs", []):
            rules.append(
                {
                    "ip_protocol": proto,
                    "from_port": from_port,
                    "to_port": to_port,
                    "source_sg": sg_ref.get("GroupId", ""),
                }
            )
    return rules


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str,
) -> tuple[list[GraphNode], list[Any]]:
    """Discover EC2 instances, security groups, VPCs, and subnets."""
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    ec2 = await run_sync(lambda: session.client("ec2", region_name=region))

    # ── VPCs ──────────────────────────────────────────────────────────────────
    raw_vpcs = await run_sync(paginate, ec2, "describe_vpcs", "Vpcs")
    vpc_map: dict[str, VPC] = {}

    for raw in raw_vpcs:
        vpc_id = raw["VpcId"]
        tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}
        vpc = VPC(
            node_id=vpc_id,
            account_id=account_id,
            region=region,
            vpc_id=vpc_id,
            cidr_block=raw.get("CidrBlock", ""),
            is_default=raw.get("IsDefault", False),
            state=raw.get("State", ""),
            tags=tags,
        )
        nodes.append(vpc)
        vpc_map[vpc_id] = vpc

    # ── Subnets ───────────────────────────────────────────────────────────────
    raw_subnets = await run_sync(paginate, ec2, "describe_subnets", "Subnets")
    subnet_map: dict[str, Subnet] = {}

    for raw in raw_subnets:
        subnet_id = raw["SubnetId"]
        tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}
        subnet = Subnet(
            node_id=subnet_id,
            account_id=account_id,
            region=region,
            subnet_id=subnet_id,
            cidr=raw.get("CidrBlock", ""),
            az=raw.get("AvailabilityZone", ""),
            public_facing=raw.get("MapPublicIpOnLaunch", False),
            vpc_id=raw.get("VpcId"),
            available_ips=raw.get("AvailableIpAddressCount", 0),
            tags=tags,
        )
        nodes.append(subnet)
        subnet_map[subnet_id] = subnet

        # Edge: Subnet → VPC
        if subnet.vpc_id and subnet.vpc_id in vpc_map:
            edges.append(
                InVPC(
                    from_node_id=subnet_id,
                    to_node_id=subnet.vpc_id,
                    account_id=account_id,
                )
            )

    # ── Security Groups ───────────────────────────────────────────────────────
    raw_sgs = await run_sync(paginate, ec2, "describe_security_groups", "SecurityGroups")
    sg_map: dict[str, SecurityGroup] = {}

    for raw in raw_sgs:
        sg_id = raw["GroupId"]
        tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}

        inbound = _parse_ip_permissions(raw.get("IpPermissions", []))
        outbound = _parse_ip_permissions(raw.get("IpPermissionsEgress", []))

        posture_flags = _sg_flags(inbound)

        sg = SecurityGroup(
            node_id=sg_id,
            account_id=account_id,
            region=region,
            group_id=sg_id,
            name=raw.get("GroupName", ""),
            description=raw.get("Description", ""),
            vpc_id=raw.get("VpcId"),
            inbound_rules=inbound,
            outbound_rules=outbound,
            tags=tags,
            posture_flags=posture_flags,
        )
        nodes.append(sg)
        sg_map[sg_id] = sg

    # ── EC2 Instances ─────────────────────────────────────────────────────────
    raw_reservations = await run_sync(paginate, ec2, "describe_instances", "Reservations")

    for reservation in raw_reservations:
        for raw in reservation.get("Instances", []):
            instance_id = raw["InstanceId"]
            tags = {t["Key"]: t["Value"] for t in raw.get("Tags", [])}
            sg_ids = [sg["GroupId"] for sg in raw.get("SecurityGroups", [])]

            instance = EC2Instance(
                node_id=instance_id,
                account_id=account_id,
                region=region,
                instance_id=instance_id,
                instance_type=raw.get("InstanceType", ""),
                state=raw.get("State", {}).get("Name", ""),
                public_ip=raw.get("PublicIpAddress"),
                private_ip=raw.get("PrivateIpAddress"),
                ami_id=raw.get("ImageId", ""),
                vpc_id=raw.get("VpcId"),
                subnet_id=raw.get("SubnetId"),
                security_group_ids=sg_ids,
                key_name=raw.get("KeyName"),
                launch_time=raw.get("LaunchTime"),
                iam_instance_profile=raw.get("IamInstanceProfile", {}).get("Arn"),
                tags=tags,
            )
            nodes.append(instance)

            # Edges: instance → VPC
            if instance.vpc_id:
                edges.append(
                    InVPC(
                        from_node_id=instance_id,
                        to_node_id=instance.vpc_id,
                        account_id=account_id,
                    )
                )
            # Edges: instance → Subnet
            if instance.subnet_id:
                edges.append(
                    InSubnet(
                        from_node_id=instance_id,
                        to_node_id=instance.subnet_id,
                        account_id=account_id,
                    )
                )
            # Edges: instance → SecurityGroups
            for sg_id in sg_ids:
                edges.append(
                    MemberOfSG(
                        from_node_id=instance_id,
                        to_node_id=sg_id,
                        account_id=account_id,
                    )
                )

    logger.info(
        "EC2 discovery [%s]: %d nodes, %d edges",
        region,
        len(nodes),
        len(edges),
    )
    return nodes, edges
