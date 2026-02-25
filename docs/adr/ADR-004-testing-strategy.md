# ADR-004: Testing Strategy — moto + testcontainers

**Status:** Accepted
**Date:** 2026-02-25
**Deciders:** Baselyne Systems founding team

---

## Context

SENTINEL has two expensive external dependencies in tests:
1. **AWS APIs** — real calls cost money, need credentials, hit rate limits
2. **Neo4j** — requires a running Docker container

We need tests that are:
- Fast (no real network I/O)
- Reproducible (deterministic AWS state)
- Realistic enough to catch real bugs

---

## Decision

Three-tier test strategy:

### Tier 1: Unit tests (`tests/unit/`)

- **AWS mocking**: `moto` with `@mock_aws` decorator / `mock_aws()` context manager
- **Neo4j mocking**: `AsyncMock` with a `RecordingNeo4jClient` that stores
  upserted nodes/edges in memory
- No Docker required
- Run in milliseconds

```python
@pytest.fixture
def mock_neo4j_client():
    """In-memory Neo4j mock that captures writes."""
    client = AsyncMock()
    client.nodes = []
    async def _upsert_node(node): client.nodes.append(node)
    client.upsert_node = AsyncMock(side_effect=_upsert_node)
    return client
```

### Tier 2: Integration tests (`tests/integration/`)

- Same moto + mock Neo4j approach as unit tests
- Tests the **full pipeline**: scan → evaluate → assert posture_flags
- Tests the **API**: FastAPI `TestClient` against mock Neo4j
- No Docker required

### Tier 3: E2E tests (`tests/e2e/`)

- **AWS mocking**: moto (same as above)
- **Neo4j**: real instance via `testcontainers-python`
- Tests the full pipeline against a real graph database
- Requires Docker
- Slower (30–60s for container startup)

```python
@pytest.fixture(scope="session")
def neo4j_container():
    from testcontainers.neo4j import Neo4jContainer
    with Neo4jContainer("neo4j:5-community") as neo4j:
        yield neo4j
```

---

## Rationale

- **moto** covers 100% of the AWS APIs SENTINEL uses (EC2, IAM, S3, RDS, Lambda,
  CloudTrail) with accurate response structures
- **AsyncMock for Neo4j** in unit/integration tests: fast, no Docker dependency,
  sufficient for testing business logic
- **testcontainers for E2E**: real Cypher execution, real MERGE semantics,
  real index behavior — catches Neo4j-specific bugs that AsyncMock can't

---

## Trade-offs accepted

| Trade-off | Mitigation |
|-----------|-----------|
| E2E tests need Docker | CI pipeline runs with Docker available; local `make test` skips E2E unless explicitly requested |
| moto doesn't cover every AWS API quirk | Known gaps documented; real-world testing in staging |
| AsyncMock doesn't test Cypher correctness | E2E tests execute all Cypher via real Neo4j |

---

## Test execution

```bash
make test              # unit + integration (no Docker)
uv run pytest tests/e2e/ -m e2e   # E2E only (needs Docker)
make test-cov          # unit + integration with coverage
```

CI pipeline: unit + integration always; E2E on merge to main.
