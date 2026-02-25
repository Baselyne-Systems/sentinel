"""
End-to-end tests for SENTINEL.

These tests use:
- testcontainers to spin up a real Neo4j 5 Community instance in Docker
- moto to mock AWS APIs
- The full SENTINEL pipeline (scan → graph write → evaluate → query)

Requirements:
- Docker must be running
- Run with: pytest tests/e2e/ -m e2e --timeout=120

E2E tests are excluded from the default `make test` target (which runs only
unit and integration tests). Use `make test-e2e` or `make test-all`.
"""
