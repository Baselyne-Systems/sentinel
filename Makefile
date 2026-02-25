.PHONY: dev neo4j api scan test lint install clean

# ── Env ───────────────────────────────────────────────────────────────────────
-include .env
export

# ── Dev ───────────────────────────────────────────────────────────────────────

## Start Neo4j only
neo4j:
	docker compose up neo4j -d
	@echo "Neo4j browser: http://localhost:7474  (neo4j / sentinel_dev)"

## Start Neo4j + API in watch mode
dev: neo4j
	uv run --package sentinel-api uvicorn sentinel_api.main:app \
		--host 0.0.0.0 --port $${API_PORT:-8000} --reload

## Start frontend dev server
frontend:
	cd frontend && npm run dev

# ── Scan ──────────────────────────────────────────────────────────────────────

## Trigger a full AWS environment scan via API
scan:
	curl -s -X POST http://localhost:$${API_PORT:-8000}/api/v1/scan/trigger \
		-H "Content-Type: application/json" \
		| python3 -m json.tool

# ── Test ──────────────────────────────────────────────────────────────────────

## Run unit + integration tests (no Docker required)
test:
	uv run pytest tests/unit tests/integration -v --tb=short

## Run end-to-end tests (requires Docker)
test-e2e:
	uv run pytest tests/e2e -v --tb=short -m e2e --timeout=120

## Run ALL tests including E2E
test-all:
	uv run pytest tests/ -v --tb=short --timeout=120

## Run tests with coverage (unit + integration)
test-cov:
	uv run pytest tests/unit tests/integration -v --tb=short \
	  --cov=packages --cov-report=term-missing --cov-report=html

# ── Quality ───────────────────────────────────────────────────────────────────

## Lint with ruff + mypy
lint:
	uv run ruff check packages/ tests/
	uv run mypy packages/ --ignore-missing-imports

## Format with ruff
fmt:
	uv run ruff format packages/ tests/

# ── Install ───────────────────────────────────────────────────────────────────

## Install all Python dependencies
install:
	uv sync

## Install frontend dependencies
install-frontend:
	cd frontend && npm install

## Install everything
install-all: install install-frontend

# ── Clean ─────────────────────────────────────────────────────────────────────

## Stop and remove all containers + volumes
clean:
	docker compose down -v
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

## Show this help
help:
	@grep -E '^##' Makefile | sed 's/^## //'
