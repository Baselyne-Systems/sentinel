"""Unit tests for CIS rules and PostureEvaluator."""

from __future__ import annotations

from sentinel_core.knowledge.rules import ALL_RULES, RULES_BY_ID, CISRule
from sentinel_core.models.enums import ResourceType


def test_all_rules_are_cis_rule_instances():
    """All items in ALL_RULES should be CISRule instances."""
    for rule in ALL_RULES:
        assert isinstance(rule, CISRule)


def test_rules_have_required_fields():
    """All rules should have non-empty required fields."""
    for rule in ALL_RULES:
        assert rule.id, f"Rule missing ID: {rule}"
        assert rule.title, f"Rule {rule.id} missing title"
        assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), f"Invalid severity: {rule.id}"
        assert len(rule.resource_types) > 0, f"Rule {rule.id} has no resource_types"
        assert rule.cypher_check.strip(), f"Rule {rule.id} has empty cypher_check"
        assert rule.posture_flag, f"Rule {rule.id} has no posture_flag"
        assert rule.remediation_hint, f"Rule {rule.id} has no remediation_hint"


def test_rules_by_id_lookup():
    """RULES_BY_ID should contain all rules."""
    assert len(RULES_BY_ID) == len(ALL_RULES)
    for rule in ALL_RULES:
        assert rule.id in RULES_BY_ID
        assert RULES_BY_ID[rule.id] is rule


def test_key_cis_rules_present():
    """Spot-check that key CIS rules are present."""
    expected_ids = [
        "CIS-1.10",  # MFA for IAM users
        "CIS-1.16",  # No star policies
        "CIS-2.1.5", # S3 not public
        "CIS-2.3.2", # RDS not public
        "CIS-3.1",   # No open SSH
        "CIS-3.2",   # No open RDP
        "CIS-4.1",   # CloudTrail enabled
    ]
    for rule_id in expected_ids:
        assert rule_id in RULES_BY_ID, f"Missing expected rule: {rule_id}"


def test_critical_severity_rules():
    """Should have at least some CRITICAL severity rules."""
    critical = [r for r in ALL_RULES if r.severity == "CRITICAL"]
    assert len(critical) >= 3


def test_cis_1_10_targets_iam_user():
    """CIS-1.10 should target IAM users."""
    rule = RULES_BY_ID["CIS-1.10"]
    assert ResourceType.IAM_USER in rule.resource_types


def test_cis_2_1_5_targets_s3():
    """CIS-2.1.5 should target S3 buckets."""
    rule = RULES_BY_ID["CIS-2.1.5"]
    assert ResourceType.S3_BUCKET in rule.resource_types


def test_cis_3_1_targets_sg():
    """CIS-3.1 should target security groups."""
    rule = RULES_BY_ID["CIS-3.1"]
    assert ResourceType.SECURITY_GROUP in rule.resource_types


def test_posture_flags_are_strings():
    """All posture_flag values should be non-empty strings."""
    for rule in ALL_RULES:
        assert isinstance(rule.posture_flag, str)
        assert len(rule.posture_flag) > 0
