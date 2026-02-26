"""Unit tests for the IAM connector."""

from __future__ import annotations

import pytest
from sentinel_core.models.enums import PostureFlag, ResourceType
from sentinel_core.models.nodes import IAMPolicy, IAMRole, IAMUser
from sentinel_perception.connectors.aws import iam

ACCOUNT_ID = "123456789012"


@pytest.mark.asyncio
async def test_iam_discovers_role(aws_session, iam_role, mocked_aws):
    """IAM role should be discovered with correct properties."""
    nodes, edges = await iam.discover(aws_session, ACCOUNT_ID)

    role_nodes = [n for n in nodes if isinstance(n, IAMRole)]
    assert len(role_nodes) >= 1

    names = {r.name for r in role_nodes}
    assert "SentinelTestRole" in names


@pytest.mark.asyncio
async def test_iam_discovers_user_without_mfa(aws_session, iam_user_no_mfa, mocked_aws):
    """IAM user with console access but no MFA should have IAM_NO_MFA flag."""
    nodes, _ = await iam.discover(aws_session, ACCOUNT_ID)

    user_nodes = [n for n in nodes if isinstance(n, IAMUser)]
    assert len(user_nodes) >= 1

    user = next((u for u in user_nodes if u.name == "sentinel-test-user"), None)
    assert user is not None
    assert user.has_console_access is True
    assert user.has_mfa is False
    assert PostureFlag.IAM_NO_MFA in user.posture_flags


@pytest.mark.asyncio
async def test_iam_discovers_star_policy(aws_session, star_policy_arn, iam_role, mocked_aws):
    """Customer-managed policy with Action:'*' should have IAM_STAR_POLICY flag."""
    nodes, _ = await iam.discover(aws_session, ACCOUNT_ID)

    policy_nodes = [n for n in nodes if isinstance(n, IAMPolicy)]
    star_policies = [p for p in policy_nodes if PostureFlag.IAM_STAR_POLICY in p.posture_flags]
    assert len(star_policies) >= 1


@pytest.mark.asyncio
async def test_iam_produces_policy_edges(aws_session, iam_role, star_policy_arn, mocked_aws):
    """IAM connector should produce HasAttachedPolicy edges for roles."""
    _, edges = await iam.discover(aws_session, ACCOUNT_ID)
    assert len(edges) >= 1


@pytest.mark.asyncio
async def test_iam_role_resource_type(aws_session, iam_role, mocked_aws):
    """IAM role node should have correct resource_type."""
    nodes, _ = await iam.discover(aws_session, ACCOUNT_ID)
    role_nodes = [n for n in nodes if isinstance(n, IAMRole)]
    for role in role_nodes:
        assert role.resource_type == ResourceType.IAM_ROLE
        assert role.account_id == ACCOUNT_ID
        assert role.region == ""  # IAM is global
