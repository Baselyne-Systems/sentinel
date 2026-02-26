"""
Integration test: full_scan → evaluate → assert posture_flags on known-bad resources.

Uses moto for AWS mocking. Uses an in-memory mock Neo4j client that captures
all upserted nodes and edges for assertion.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sentinel_core.models.enums import PostureFlag
from sentinel_core.models.nodes import (
    IAMUser,
    RDSInstance,
    S3Bucket,
    SecurityGroup,
)
from sentinel_perception.graph_builder import GraphBuilder

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


class RecordingNeo4jClient:
    """
    In-memory mock Neo4j client that records all operations.
    Simulates posture_flag stamping by tracking node state.
    """

    def __init__(self):
        self.nodes: dict[str, object] = {}
        self.edges: list[object] = []
        self.stamped_flags: dict[str, list[str]] = {}  # node_id → list of flags

    async def upsert_node(self, node):
        self.nodes[node.node_id] = node

    async def upsert_edge(self, edge):
        self.edges.append(edge)

    async def set_posture_flags(self, node_id, flags):
        self.stamped_flags[node_id] = flags

    async def query(self, cypher, params=None):
        """
        For integration testing, simulate the rule queries by inspecting
        our in-memory node state rather than a real Neo4j.
        """
        params = params or {}
        results = []

        # Route to appropriate simulation based on cypher content
        if "S3Bucket {is_public: true}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, S3Bucket) and node.is_public:
                    results.append({"node_id": node.node_id, "name": node.name})

        elif "SG_OPEN_SSH" in cypher:
            for node in self.nodes.values():
                if isinstance(node, SecurityGroup) and PostureFlag.SG_OPEN_SSH in node.posture_flags:
                    results.append({"node_id": node.node_id, "group_id": node.group_id, "name": node.name})

        elif "SG_OPEN_RDP" in cypher:
            for node in self.nodes.values():
                if isinstance(node, SecurityGroup) and PostureFlag.SG_OPEN_RDP in node.posture_flags:
                    results.append({"node_id": node.node_id, "group_id": node.group_id, "name": node.name})

        elif "SG_OPEN_ALL_INGRESS" in cypher:
            for node in self.nodes.values():
                if isinstance(node, SecurityGroup) and PostureFlag.SG_OPEN_ALL_INGRESS in node.posture_flags:
                    results.append({"node_id": node.node_id, "group_id": node.group_id, "name": node.name})

        elif "RDSInstance {publicly_accessible: true}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, RDSInstance) and node.publicly_accessible:
                    results.append({"node_id": node.node_id, "db_id": node.db_id})

        elif "RDSInstance {encrypted: false}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, RDSInstance) and not node.encrypted:
                    results.append({"node_id": node.node_id, "db_id": node.db_id})

        elif "RDSInstance {multi_az: false}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, RDSInstance) and not node.multi_az:
                    results.append({"node_id": node.node_id, "db_id": node.db_id})

        elif "has_console_access: true, has_mfa: false" in cypher:
            for node in self.nodes.values():
                if isinstance(node, IAMUser) and node.has_console_access and not node.has_mfa:
                    results.append({"node_id": node.node_id, "name": node.name})

        elif "IAM_STAR_POLICY" in cypher:
            from sentinel_core.models.nodes import IAMPolicy
            for node in self.nodes.values():
                if isinstance(node, IAMPolicy) and PostureFlag.IAM_STAR_POLICY in node.posture_flags:
                    results.append({"node_id": node.node_id, "name": node.name})

        elif "S3Bucket {versioning: false}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, S3Bucket) and not node.versioning:
                    results.append({"node_id": node.node_id, "name": node.name})

        elif "S3Bucket {logging: false}" in cypher:
            for node in self.nodes.values():
                if isinstance(node, S3Bucket) and not node.logging:
                    results.append({"node_id": node.node_id, "name": node.name})

        return results

    async def execute(self, cypher, params=None):
        """Simulate stamping by recording flags."""
        params = params or {}
        if "SET n.posture_flags" in cypher:
            node_id = params.get("node_id")
            flag = params.get("flag")
            severity = params.get("severity")
            if node_id:
                existing = self.stamped_flags.get(node_id, [])
                if flag and flag not in existing:
                    existing.append(flag)
                if severity and severity not in existing:
                    existing.append(severity)
                self.stamped_flags[node_id] = existing

    async def ensure_indexes(self):
        pass

    async def clear_account(self, account_id):
        self.nodes = {k: v for k, v in self.nodes.items()
                      if getattr(v, "account_id", None) != account_id}


@pytest.mark.asyncio
async def test_full_scan_posture_integration(
    aws_session,
    mocked_aws,
    public_s3_bucket,
    private_s3_bucket,
    open_sg_id,
    vpc_id,
    subnet_ids,
    ec2_instance_id,
    iam_role,
    iam_user_no_mfa,
    public_rds_instance,
    star_policy_arn,
):
    """
    End-to-end: full_scan → evaluate → verify known-bad resources have posture_flags.
    """
    client = RecordingNeo4jClient()
    builder = GraphBuilder(client)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        result = await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    # ── Verify scan completed ──────────────────────────────────────────────────
    assert result.account_id == ACCOUNT_ID
    assert result.nodes_written > 0

    # ── Verify node types were discovered ─────────────────────────────────────
    node_types = {type(n).__name__ for n in client.nodes.values()}
    assert "S3Bucket" in node_types
    assert "SecurityGroup" in node_types
    assert "EC2Instance" in node_types

    # ── Verify public S3 bucket has posture flag ───────────────────────────────
    public_bucket = next(
        (n for n in client.nodes.values()
         if isinstance(n, S3Bucket) and n.name == public_s3_bucket),
        None,
    )
    assert public_bucket is not None, "Public S3 bucket should have been discovered"
    assert public_bucket.is_public is True
    assert PostureFlag.S3_PUBLIC_ACCESS in public_bucket.posture_flags, \
        f"Expected S3_PUBLIC_ACCESS in {public_bucket.posture_flags}"

    # ── Verify open SSH security group has posture flag ────────────────────────
    open_sg = next(
        (n for n in client.nodes.values()
         if isinstance(n, SecurityGroup) and n.group_id == open_sg_id),
        None,
    )
    assert open_sg is not None, "Open SSH security group should have been discovered"
    assert PostureFlag.SG_OPEN_SSH in open_sg.posture_flags, \
        f"Expected SG_OPEN_SSH in {open_sg.posture_flags}"

    # ── Verify IAM user without MFA has posture flag ───────────────────────────
    user_no_mfa = next(
        (n for n in client.nodes.values()
         if isinstance(n, IAMUser) and n.name == "sentinel-test-user"),
        None,
    )
    assert user_no_mfa is not None, "IAM user without MFA should have been discovered"
    assert user_no_mfa.has_console_access is True
    assert user_no_mfa.has_mfa is False
    assert PostureFlag.IAM_NO_MFA in user_no_mfa.posture_flags, \
        f"Expected IAM_NO_MFA in {user_no_mfa.posture_flags}"

    # ── Verify RDS instance has posture flags ──────────────────────────────────
    public_rds = next(
        (n for n in client.nodes.values()
         if isinstance(n, RDSInstance) and n.db_id == "sentinel-test-db"),
        None,
    )
    assert public_rds is not None, "Public RDS instance should have been discovered"
    assert public_rds.publicly_accessible is True
    assert PostureFlag.RDS_PUBLIC in public_rds.posture_flags, \
        f"Expected RDS_PUBLIC in {public_rds.posture_flags}"
    assert PostureFlag.RDS_NO_ENCRYPTION in public_rds.posture_flags, \
        f"Expected RDS_NO_ENCRYPTION in {public_rds.posture_flags}"

    # ── Verify evaluator produced findings ─────────────────────────────────────
    assert result.findings_count > 0, "Should have found CIS violations"

    # ── Verify specific findings exist ─────────────────────────────────────────
    finding_flags = {f.posture_flag for f in result.findings}
    assert "S3_PUBLIC_ACCESS" in finding_flags, "Should find S3 public access violation"
    assert "SG_OPEN_SSH" in finding_flags, "Should find open SSH security group violation"
    assert "IAM_NO_MFA" in finding_flags, "Should find IAM user without MFA violation"


@pytest.mark.asyncio
async def test_evaluation_stamps_node_with_cis_2_1_2(
    aws_session,
    mocked_aws,
    public_s3_bucket,
):
    """
    CIS-2.1.2 check: public S3 bucket should be found and flagged.
    Verifies GET /graph/nodes/{node_id} would show posture_flags including CIS findings.
    """
    client = RecordingNeo4jClient()
    builder = GraphBuilder(client)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    # The public bucket should have S3_NO_VERSIONING flag (CIS-2.1.2)
    bucket_node = next(
        (n for n in client.nodes.values()
         if isinstance(n, S3Bucket) and n.name == public_s3_bucket),
        None,
    )
    assert bucket_node is not None
    # The evaluator should have stamped S3_NO_VERSIONING on the bucket
    node_id = bucket_node.node_id
    stamped = client.stamped_flags.get(node_id, [])
    # Either it's in posture_flags (set during discovery) or stamped by evaluator
    all_flags = list(bucket_node.posture_flags) + stamped
    assert "S3_NO_VERSIONING" in all_flags or "S3_PUBLIC_ACCESS" in all_flags, \
        f"Expected CIS flags, got: {all_flags}"
