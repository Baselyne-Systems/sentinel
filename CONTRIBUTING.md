# Contributing to SENTINEL

## Development setup

```bash
git clone https://github.com/baselyne-systems/sentinel.git
cd sentinel
cp .env.example .env
uv sync          # install Python dependencies
make neo4j       # start Neo4j
make dev         # start API in watch mode
```

## Project structure

```
sentinel/
├── packages/
│   ├── core/           # sentinel-core: graph schema, Neo4j client, CIS rules
│   ├── perception/     # sentinel-perception: AWS connectors, graph builder
│   └── api/            # sentinel-api: FastAPI app
├── frontend/           # Next.js 14 app
├── tests/
│   ├── unit/           # Fast, no external dependencies
│   ├── integration/    # Uses moto + mock Neo4j
│   └── e2e/            # Uses testcontainers (requires Docker)
└── docs/
    ├── adr/            # Architecture Decision Records
    ├── adding-connectors.md
    └── cis-rules.md
```

## Running tests

```bash
make test           # full suite
make test-cov       # with coverage

# Subsets
uv run pytest tests/unit/         # no external deps
uv run pytest tests/integration/  # no external deps
uv run pytest tests/e2e/          # needs Docker
```

## Code style

```bash
make lint    # ruff + mypy
make fmt     # auto-format
```

- Line length: 100 characters
- Google-style docstrings on all public classes and methods
- Type hints everywhere (``from __future__ import annotations``)
- No bare ``except:`` — catch specific exception types

## Pull request checklist

- [ ] All existing tests pass: `make test`
- [ ] New code has tests (unit tests for connectors, integration tests for pipelines)
- [ ] Docstrings on new public APIs
- [ ] `make lint` passes with no errors
- [ ] If adding a connector: follow [docs/adding-connectors.md](docs/adding-connectors.md)
- [ ] If adding a CIS rule: follow [docs/cis-rules.md](docs/cis-rules.md)

## Commit convention

```
type(scope): short description

Types: feat, fix, docs, test, refactor, chore
Scope: core, perception, api, frontend, tests, docs
```

Examples:
```
feat(perception): add CloudFront connector
fix(core): handle empty posture_flags in neo4j serialization
test(e2e): add attack-path traversal test
docs(adr): ADR-004 async boto3 strategy
```
