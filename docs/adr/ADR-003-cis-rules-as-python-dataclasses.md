# ADR-003: CIS Rules as Python Dataclasses (Not a Database)

**Status:** Accepted
**Date:** 2026-02-25
**Deciders:** Baselyne Systems founding team

---

## Context

SENTINEL needs a machine-readable representation of CIS AWS Benchmark rules for:
- Automated evaluation against the graph
- Surfacing rules in the API (`GET /posture/rules`)
- Extensibility (adding rules without schema migrations)

Options evaluated:

1. **JSON/YAML files**: Flexible but no type checking; Cypher queries as strings
   in a file are hard to validate.

2. **Database table**: Full CRUD API, dynamic rule loading. Overkill for Phase 1;
   rules are versioned with code, not user-configurable.

3. **Python dataclasses in source code**: Type-checked at import time, co-located
   with the code that executes them, IDE-navigable, testable with standard pytest.

---

## Decision

Define CIS rules as **typed Python dataclasses** in
`packages/core/sentinel_core/knowledge/rules.py`, loaded at startup.

```python
@dataclass
class CISRule:
    id: str
    title: str
    severity: Literal["CRITICAL","HIGH","MEDIUM","LOW"]
    resource_types: list[ResourceType]
    cypher_check: str   # Cypher query; non-empty result = violation
    posture_flag: str
    remediation_hint: str
    tags: list[str]
```

All rules are collected in `ALL_RULES: list[CISRule]` and indexed by
`RULES_BY_ID: dict[str, CISRule]`.

---

## Rationale

- **Type safety**: `resource_types` uses the `ResourceType` enum, `severity`
  is a literal type — wrong values fail at import time
- **Cypher embedded in Python**: the IDE can navigate from a rule to its
  check query; tests can extract and validate the Cypher
- **No migration burden**: adding a rule is a one-line edit to `ALL_RULES`
- **Version-controlled with code**: rule changes appear in git diffs,
  are reviewable, and can be bisected
- **Fast**: rules load in microseconds (no DB query)

---

## Trade-offs accepted

| Trade-off | Mitigation |
|-----------|-----------|
| Users can't add rules without code | Phase 2: add rule import API on top of the dataclass layer |
| Rules require a deploy to update | Acceptable for Phase 1; Phase 2 adds hot-reload support |
| Cypher strings aren't syntax-checked at import | E2E tests execute every rule's Cypher against a real Neo4j |

---

## Consequences

- The rule's `cypher_check` must always return `node_id` as a column for
  the evaluator to know which node to stamp
- New rules are added to `rules.py` and `ALL_RULES` — no DB migration needed
- The `PostureEvaluator` iterates `ALL_RULES` and is rule-count agnostic;
  adding rules automatically includes them in evaluation
