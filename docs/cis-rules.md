# Adding CIS Benchmark Rules

SENTINEL evaluates AWS environments against the **CIS AWS Foundations Benchmark v1.5**.
Rules are Python dataclasses in `packages/core/sentinel_core/knowledge/rules.py`.

## Rule anatomy

```python
@dataclass
class CISRule:
    id: str                      # "CIS-2.1.5"
    title: str                   # Human-readable title
    severity: Severity           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    resource_types: list[ResourceType]  # Which nodes this rule applies to
    cypher_check: str            # Cypher query — non-empty result = VIOLATED
    posture_flag: str            # Flag stamped on violating nodes
    remediation_hint: str        # One-sentence fix guidance
    tags: list[str]              # Categorization labels
```

The `cypher_check` is the most important field. When the evaluator runs, it
executes this query against Neo4j. Any records returned are treated as violations,
and the rule's `posture_flag` is stamped on those nodes.

---

## The cypher_check contract

- **Must return `node_id`** as a column (used to identify which node to stamp)
- Optionally return `name`, `db_id`, `instance_id` for human-readable finding names
- Should match only violating nodes (not all nodes of the type)
- If the query returns zero records → rule passes → no violation

```cypher
-- Good: returns node_id for matching (violating) nodes
MATCH (b:S3Bucket {is_public: true})
RETURN b.node_id AS node_id, b.name AS name

-- Good: matches nodes with a pre-stamped flag (set during discovery)
MATCH (sg:SecurityGroup)
WHERE 'SG_OPEN_SSH' IN sg.posture_flags
RETURN sg.node_id AS node_id, sg.group_id AS group_id, sg.name AS name
```

## Two-phase evaluation pattern

Some violations are easier to detect during discovery (when you have full boto3
context) than in a Cypher query. The pattern:

1. **Discovery phase**: set `posture_flags` on the node during `discover()` in the connector
2. **Evaluation phase**: write a Cypher check that looks for the pre-stamped flag

Example — the `SG_OPEN_SSH` flag is set by `ec2.py` when it parses inbound rules.
The CIS-3.1 Cypher check then just queries for nodes that have that flag:

```python
# ec2.py: stamps the flag during discovery
posture_flags = _sg_flags(inbound_rules)

# rules.py: Cypher check reads the pre-stamped flag
CIS_3_1 = CISRule(
    id="CIS-3.1",
    cypher_check="""
    MATCH (sg:SecurityGroup)
    WHERE 'SG_OPEN_SSH' IN sg.posture_flags
    RETURN sg.node_id AS node_id, sg.name AS name
    """,
    ...
)
```

This avoids complex Cypher list-processing for rules that are easier to evaluate
in Python during discovery.

---

## Adding a new rule

### 1. Write the rule in `rules.py`

```python
CIS_2_4_1 = CISRule(
    id="CIS-2.4.1",
    title="Ensure AWS Secrets Manager secrets are rotated within 90 days",
    severity="HIGH",
    resource_types=[ResourceType.SECRETS_MANAGER_SECRET],  # add to enums if needed
    cypher_check="""
    MATCH (s:SecretsManagerSecret)
    WHERE s.days_since_rotation > 90 OR s.rotation_enabled = false
    RETURN s.node_id AS node_id, s.name AS name
    """,
    posture_flag="SECRETS_NO_ROTATION",
    remediation_hint="Enable automatic rotation for Secrets Manager secrets via Lambda.",
    tags=["secrets-manager", "rotation"],
)
```

### 2. Add it to `ALL_RULES`

```python
ALL_RULES: list[CISRule] = [
    # ... existing rules
    CIS_2_4_1,   # <-- add here
]
```

That's it. The rule will:
- Appear in `GET /api/v1/posture/rules`
- Be evaluated on every scan
- Stamp `SECRETS_NO_ROTATION` and `HIGH` on violating nodes
- Surface violations in `GET /api/v1/posture/findings`

### 3. Write a unit test

```python
def test_cis_2_4_1_targets_secrets():
    from sentinel_core.knowledge.rules import RULES_BY_ID, ResourceType
    rule = RULES_BY_ID["CIS-2.4.1"]
    assert rule.severity == "HIGH"
    assert ResourceType.SECRETS_MANAGER_SECRET in rule.resource_types
```

---

## Rule severity guide

| Severity | Examples |
|----------|---------|
| CRITICAL | S3 bucket publicly readable, RDS publicly accessible, SSH open to 0.0.0.0/0, no CloudTrail |
| HIGH | IAM user without MFA, unencrypted EBS/RDS, star IAM policy, stale credentials |
| MEDIUM | S3 without versioning, RDS without Multi-AZ, S3 without encryption |
| LOW | S3 without access logging, Lambda not in VPC |

---

## Testing rules end-to-end

The integration test in `tests/integration/test_full_scan_posture.py` exercises
the full pipeline: moto fixtures → scan → evaluate → assert posture_flags.

After adding a rule, add a corresponding fixture and assertion there.
