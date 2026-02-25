"""
IAM connector — discovers IAM roles, users, and policies.

IAM is global (not regional), so region is typically 'us-east-1' for the API call,
but the nodes are stamped with region="" to indicate global scope.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import unquote

import boto3
import botocore.exceptions

from sentinel_core.models.edges import CanAssume, HasAttachedPolicy
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import GraphNode, IAMPolicy, IAMRole, IAMUser
from sentinel_perception.connectors.aws.base import paginate, run_sync, safe_get

logger = logging.getLogger(__name__)


def _has_star_policy(document: dict) -> bool:
    """Check if a policy document grants Action: '*' on Resource: '*'."""
    for stmt in document.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _decode_trust_policy(raw_trust: str | dict) -> dict:
    """URL-decode and parse trust policy JSON if it's a string."""
    if isinstance(raw_trust, dict):
        return raw_trust
    try:
        return json.loads(unquote(raw_trust))
    except Exception:
        return {}


async def discover(
    session: boto3.Session,
    account_id: str,
    region: str = "",
) -> tuple[list[GraphNode], list[Any]]:
    """
    Discover all IAM roles, users, and managed policies.

    Returns (nodes, edges).
    """
    nodes: list[GraphNode] = []
    edges: list[Any] = []

    iam = await run_sync(lambda: session.client("iam", region_name="us-east-1"))

    # ── Roles ─────────────────────────────────────────────────────────────────
    raw_roles = await run_sync(paginate, iam, "list_roles", "Roles")
    role_map: dict[str, IAMRole] = {}

    for raw in raw_roles:
        role_id = raw["RoleId"]
        arn = raw["Arn"]
        trust_policy = _decode_trust_policy(raw.get("AssumeRolePolicyDocument", {}))

        # Fetch attached managed policies
        attached_arns: list[str] = []
        try:
            attached = await run_sync(
                paginate,
                iam,
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=raw["RoleName"],
            )
            attached_arns = [p["PolicyArn"] for p in attached]
        except botocore.exceptions.ClientError as e:
            logger.debug("list_attached_role_policies for %s: %s", raw["RoleName"], e)

        inline_names: list[str] = []
        try:
            inline_names = await run_sync(
                paginate,
                iam,
                "list_role_policies",
                "PolicyNames",
                RoleName=raw["RoleName"],
            )
        except botocore.exceptions.ClientError as e:
            logger.debug("list_role_policies for %s: %s", raw["RoleName"], e)

        role = IAMRole(
            node_id=role_id,
            account_id=account_id,
            region="",
            role_id=role_id,
            name=raw["RoleName"],
            arn=arn,
            trust_policy=trust_policy,
            max_session=raw.get("MaxSessionDuration", 3600),
            path=raw.get("Path", "/"),
            attached_policy_arns=attached_arns,
            inline_policy_names=inline_names,
        )
        nodes.append(role)
        role_map[arn] = role

    # ── Users ─────────────────────────────────────────────────────────────────
    raw_users = await run_sync(paginate, iam, "list_users", "Users")

    for raw in raw_users:
        user_id = raw["UserId"]
        arn = raw["Arn"]

        # Check MFA
        mfa_devices = await run_sync(
            safe_get,
            iam,
            "list_mfa_devices",
            default={"MFADevices": []},
            UserName=raw["UserName"],
        )
        has_mfa = len(mfa_devices.get("MFADevices", [])) > 0

        # Check console access (login profile)
        login_profile = await run_sync(
            safe_get, iam, "get_login_profile", default=None, UserName=raw["UserName"]
        )
        has_console = login_profile is not None and "LoginProfile" in login_profile

        # Attached policies
        attached_arns: list[str] = []
        try:
            attached = await run_sync(
                paginate,
                iam,
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=raw["UserName"],
            )
            attached_arns = [p["PolicyArn"] for p in attached]
        except botocore.exceptions.ClientError:
            pass

        # Access keys
        key_list = await run_sync(
            safe_get,
            iam,
            "list_access_keys",
            default={"AccessKeyMetadata": []},
            UserName=raw["UserName"],
        )
        key_count = len(key_list.get("AccessKeyMetadata", []))

        posture_flags: list[PostureFlag] = []
        if has_console and not has_mfa:
            posture_flags.append(PostureFlag.IAM_NO_MFA)

        user = IAMUser(
            node_id=user_id,
            account_id=account_id,
            region="",
            user_id=user_id,
            name=raw["UserName"],
            arn=arn,
            has_mfa=has_mfa,
            has_console_access=has_console,
            password_last_used=raw.get("PasswordLastUsed"),
            access_key_count=key_count,
            attached_policy_arns=attached_arns,
            posture_flags=posture_flags,
        )
        nodes.append(user)

        # Edges: user → attached policies
        for policy_arn in attached_arns:
            policy_id = policy_arn.split(":")[-1].replace("policy/", "")
            edges.append(
                HasAttachedPolicy(
                    from_node_id=user_id,
                    to_node_id=policy_id,
                    account_id=account_id,
                    attachment_type="managed",
                )
            )

    # ── Managed Policies ──────────────────────────────────────────────────────
    # Only fetch customer-managed policies (not AWS managed) to keep graph focused
    raw_policies = await run_sync(
        paginate,
        iam,
        "list_policies",
        "Policies",
        Scope="Local",  # customer-managed only
        OnlyAttached=True,
    )

    for raw in raw_policies:
        policy_arn = raw["Arn"]
        policy_id = policy_arn.split(":")[-1].replace("policy/", "")

        # Fetch policy document
        document: dict = {}
        try:
            version_id = raw.get("DefaultVersionId", "v1")
            pv = await run_sync(
                iam.get_policy_version,
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            document = _decode_trust_policy(pv["PolicyVersion"].get("Document", {}))
        except botocore.exceptions.ClientError as e:
            logger.debug("get_policy_version for %s: %s", policy_arn, e)

        has_star = _has_star_policy(document)
        posture_flags: list[PostureFlag] = []
        if has_star:
            posture_flags.append(PostureFlag.IAM_STAR_POLICY)

        policy = IAMPolicy(
            node_id=policy_id,
            account_id=account_id,
            region="",
            policy_arn=policy_arn,
            name=raw["PolicyName"],
            document=document,
            is_managed=True,
            is_aws_managed=False,
            attachment_count=raw.get("AttachmentCount", 0),
            path=raw.get("Path", "/"),
            posture_flags=posture_flags,
        )
        nodes.append(policy)

    # ── Role → Policy edges + CAN_ASSUME edges ────────────────────────────────
    for role in [n for n in nodes if isinstance(n, IAMRole)]:
        for policy_arn in role.attached_policy_arns:
            policy_id = policy_arn.split(":")[-1].replace("policy/", "")
            edges.append(
                HasAttachedPolicy(
                    from_node_id=role.role_id,
                    to_node_id=policy_id,
                    account_id=account_id,
                    attachment_type="managed",
                )
            )

        # Parse trust policy for CAN_ASSUME edges
        for stmt in role.trust_policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                principal = {"AWS": principal}
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for arn in aws_principals:
                # Find the target role by ARN
                if arn in role_map:
                    target = role_map[arn]
                    edges.append(
                        CanAssume(
                            from_node_id=role.role_id,
                            to_node_id=target.role_id,
                            account_id=account_id,
                        )
                    )

    logger.info(
        "IAM discovery: %d nodes, %d edges",
        len(nodes),
        len(edges),
    )
    return nodes, edges
