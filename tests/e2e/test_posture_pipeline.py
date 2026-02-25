"""
E2E Test: posture evaluation pipeline against real Neo4j.

Verifies that:
1. CIS rules are evaluated correctly against real Neo4j data
2. posture_flags are stamped on violating nodes via real Cypher SET
3. Findings are correctly retrieved via GraphQueries
4. The posture summary reflects real node counts
5. The PostureEvaluator returns the right findings for known-bad resources

This tests the Cypher correctness of CIS rules — something the unit/integration
tests cannot verify (they use a mock Neo4j that simulates rule checks in Python).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sentinel_core.graph.client import Neo4jClient
from sentinel_core.graph.queries import GraphQueries
from sentinel_core.knowledge.evaluator import PostureEvaluator
from sentinel_core.knowledge.rules import RULES_BY_ID
from sentinel_core.models.enums import PostureFlag
from sentinel_perception.graph_builder import GraphBuilder

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

pytestmark = pytest.mark.e2e


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_evaluator_finds_public_s3(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
):
    """CIS-2.1.5: public S3 bucket should produce a finding."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    findings = await evaluator.evaluate(account_id=ACCOUNT_ID)

    s3_public_findings = [
        f for f in findings if f.posture_flag == "S3_PUBLIC_ACCESS"
    ]
    assert len(s3_public_findings) >= 1, "Should find at least one public S3 bucket"

    bucket_ids = {f.node_id for f in s3_public_findings}
    assert f"s3-{public_s3_bucket}" in bucket_ids


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_evaluator_finds_open_sg(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    open_sg_id,
    vpc_id,
):
    """CIS-3.1: security group with SSH open should produce a finding."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    findings = await evaluator.evaluate(account_id=ACCOUNT_ID)

    ssh_findings = [f for f in findings if f.posture_flag == "SG_OPEN_SSH"]
    assert len(ssh_findings) >= 1, "Should find open SSH security group"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_evaluator_finds_iam_no_mfa(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    iam_user_no_mfa,
):
    """CIS-1.10: IAM user without MFA should produce a finding."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    findings = await evaluator.evaluate(account_id=ACCOUNT_ID)

    mfa_findings = [f for f in findings if f.posture_flag == "IAM_NO_MFA"]
    assert len(mfa_findings) >= 1, "Should find IAM user without MFA"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_evaluator_finds_rds_public(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_rds_instance,
    vpc_id,
    subnet_ids,
    open_sg_id,
):
    """CIS-2.3.2: publicly accessible RDS should produce a finding."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    findings = await evaluator.evaluate(account_id=ACCOUNT_ID)

    rds_findings = [f for f in findings if f.posture_flag == "RDS_PUBLIC"]
    assert len(rds_findings) >= 1, "Should find publicly accessible RDS"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_flags_stamped_on_nodes(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    open_sg_id,
    vpc_id,
):
    """
    After evaluation, posture_flags should be written back to nodes in Neo4j.

    This verifies the Cypher SET statement in PostureEvaluator._stamp_node()
    actually updates the graph — the unit tests mock this away.
    """
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    await evaluator.evaluate(account_id=ACCOUNT_ID)

    # Verify posture_flags on the S3 bucket node in real Neo4j
    bucket_records = await clean_db.query(
        "MATCH (b:S3Bucket {name: $name}) RETURN b.posture_flags AS flags",
        {"name": public_s3_bucket},
    )
    assert len(bucket_records) == 1
    flags = bucket_records[0]["flags"]
    assert "S3_PUBLIC_ACCESS" in flags
    assert "CRITICAL" in flags  # severity label also stamped

    # Verify posture_flags on the security group in real Neo4j
    sg_records = await clean_db.query(
        "MATCH (sg:SecurityGroup {group_id: $sg_id}) RETURN sg.posture_flags AS flags",
        {"sg_id": open_sg_id},
    )
    assert len(sg_records) >= 1
    sg_flags = sg_records[0]["flags"]
    assert "SG_OPEN_SSH" in sg_flags or "CRITICAL" in sg_flags


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_get_findings_from_graph(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    open_sg_id,
    vpc_id,
    iam_user_no_mfa,
):
    """PostureEvaluator.get_findings_from_graph() should return correct findings."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    await evaluator.evaluate(account_id=ACCOUNT_ID)

    # Get all findings
    all_findings = await evaluator.get_findings_from_graph(account_id=ACCOUNT_ID)
    assert len(all_findings) > 0

    # Filter by CRITICAL
    critical_findings = await evaluator.get_findings_from_graph(
        account_id=ACCOUNT_ID, severity="CRITICAL"
    )
    for f in critical_findings:
        assert f["severity"] == "CRITICAL"
        assert "CRITICAL" in f["posture_flags"]

    # Filter by resource type
    s3_findings = await evaluator.get_findings_from_graph(
        account_id=ACCOUNT_ID, resource_type="S3Bucket"
    )
    for f in s3_findings:
        assert f["resource_type"] == "S3Bucket"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_posture_summary_accuracy(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    public_s3_bucket,
    open_sg_id,
    vpc_id,
):
    """GraphQueries.get_posture_summary() should reflect real node counts."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    await evaluator.evaluate(account_id=ACCOUNT_ID)

    queries = GraphQueries(clean_db)
    summary = await queries.get_posture_summary(account_id=ACCOUNT_ID)

    assert summary["total_nodes"] > 0
    # At least one CRITICAL finding (open SSH SG)
    assert summary["critical_count"] >= 1


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_cis_rules_cypher_valid(clean_db: Neo4jClient):
    """
    Every CIS rule's cypher_check should execute without syntax errors.

    This verifies that all embedded Cypher queries are valid — no unit
    test can check this because unit tests mock Neo4j.
    """
    from sentinel_core.knowledge.rules import ALL_RULES

    for rule in ALL_RULES:
        try:
            results = await clean_db.query(rule.cypher_check.strip())
            # Results may be empty (no violations in empty DB) — that's fine
            assert isinstance(results, list), f"Rule {rule.id} query should return a list"
        except Exception as e:
            pytest.fail(f"Rule {rule.id} cypher_check failed with: {e}\n\nQuery:\n{rule.cypher_check}")


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_private_s3_has_no_posture_flags(
    clean_db: Neo4jClient,
    aws_session,
    mocked_aws,
    private_s3_bucket,
):
    """Compliant S3 bucket should not have S3_PUBLIC_ACCESS flag after evaluation."""
    builder = GraphBuilder(clean_db)
    evaluator = PostureEvaluator(clean_db)

    with patch("sentinel_perception.graph_builder.get_session", return_value=aws_session):
        await builder.full_scan(account_id=ACCOUNT_ID, regions=[REGION])

    await evaluator.evaluate(account_id=ACCOUNT_ID)

    records = await clean_db.query(
        "MATCH (b:S3Bucket {name: $name}) RETURN b.posture_flags AS flags, b.is_public AS pub",
        {"name": private_s3_bucket},
    )
    assert len(records) == 1
    assert records[0]["pub"] is False
    flags = records[0]["flags"] or []
    assert "S3_PUBLIC_ACCESS" not in flags
