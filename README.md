# SENTINEL

**Autonomous cloud security architect** — continuously observes, reasons about, and remediates security vulnerabilities in AWS infrastructure.

SENTINEL builds a live graph of your cloud environment, evaluates it against the CIS AWS Foundations Benchmark v1.5, and surfaces actionable findings through a graph explorer UI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL                                  │
│                                                                   │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  Perception  │    │     Core     │    │       API          │  │
│  │   Engine     │───▶│  Graph + CIS │◀───│   FastAPI Layer    │  │
│  │  (boto3)     │    │   Knowledge  │    │                    │  │
│  └─────────────┘    └──────┬───────┘    └────────────────────┘  │
│                             │                       ▲             │
│                             ▼                       │             │
│                      ┌─────────────┐    ┌──────────┴─────────┐  │
│                      │    Neo4j    │    │      Frontend       │  │
│                      │   Graph DB  │    │  Next.js + Cytoscape│  │
│                      └─────────────┘    └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

| Package | Path | Purpose |
|---------|------|---------|
| `sentinel-core` | `packages/core/` | Graph schema (Pydantic models), Neo4j client, CIS rules, posture evaluator |
| `sentinel-perception` | `packages/perception/` | AWS connectors (boto3), graph builder, CloudTrail poller |
| `sentinel-api` | `packages/api/` | FastAPI REST API |
| Frontend | `frontend/` | Next.js 14 + Cytoscape.js |

---

## Quickstart

### Prerequisites

- Docker + Docker Compose
- Python 3.12+ with [uv](https://docs.astral.sh/uv/)
- Node.js 20+ with npm

### 1. Clone and configure

```bash
git clone https://github.com/baselyne-systems/sentinel.git
cd sentinel
cp .env.example .env
# Edit .env: set AWS_REGIONS and optionally AWS_ASSUME_ROLE_ARN
```

### 2. Start Neo4j

```bash
make neo4j
# Neo4j browser → http://localhost:7474  (neo4j / sentinel_dev)
```

### 3. Start the API

```bash
make install   # uv sync
make dev       # uvicorn --reload
# API → http://localhost:8000
# OpenAPI docs → http://localhost:8000/docs
```

### 4. Start the frontend

```bash
make install-frontend
make frontend
# UI → http://localhost:3000
```

### 5. Run your first scan

```bash
make scan
# or via curl:
curl -X POST http://localhost:8000/api/v1/scan/trigger \
     -H "Content-Type: application/json" \
     -d '{"regions": ["us-east-1"]}'
```

---

## Development commands

| Command | Description |
|---------|-------------|
| `make dev` | Start Neo4j + API in watch mode |
| `make neo4j` | Start Neo4j only |
| `make scan` | Trigger a full AWS scan via API |
| `make test` | Run the full pytest suite |
| `make test-cov` | Tests with coverage report |
| `make lint` | ruff + mypy |
| `make fmt` | Auto-format with ruff |
| `make clean` | Stop containers and clean build artifacts |

---

## Testing

```bash
make test                         # all tests
make test-cov                     # with coverage

# Specific suites
uv run pytest tests/unit/         # unit tests (no Docker needed)
uv run pytest tests/integration/  # integration tests (no Docker needed)
uv run pytest tests/e2e/          # end-to-end (requires Docker for Neo4j)
```

Unit and integration tests use **moto** for AWS mocking and an in-memory
Neo4j mock — no real AWS credentials or running Neo4j required.

E2E tests use **testcontainers** to spin up a real Neo4j instance in Docker.

---

## Adding a new AWS connector

See [docs/adding-connectors.md](docs/adding-connectors.md).

## Adding a CIS rule

See [docs/cis-rules.md](docs/cis-rules.md).

## Architecture decisions

See [docs/adr/](docs/adr/) for Architecture Decision Records.

---

## Phase roadmap

| Phase | Name | Status |
|-------|------|--------|
| 1 | Foundation — Live AWS graph + CIS posture | ✅ Complete |
| 2 | Reasoning — LLM-powered analysis (Claude) | Planned |
| 3 | Action — Autonomous remediation with approval gates | Planned |
| 4 | Multi-cloud — GCP and Azure connectors | Planned |

---

## License

MIT © Baselyne Systems
