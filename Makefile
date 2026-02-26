.PHONY: dev neo4j api scan test lint install clean \
        docker-build docker-push up-prod down-prod logs logs-dev

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

## Run performance benchmarks (requires Docker)
bench:
	uv run pytest tests/benchmarks/ -v -m benchmark --timeout=300 \
	  --benchmark-sort=mean --benchmark-warmup=on

## Save benchmark baseline for regression comparison
bench-save:
	uv run pytest tests/benchmarks/ -v -m benchmark --timeout=300 \
	  --benchmark-sort=mean --benchmark-save=baseline

## Compare benchmarks against saved baseline
bench-compare:
	uv run pytest tests/benchmarks/ -v -m benchmark --timeout=300 \
	  --benchmark-sort=mean --benchmark-compare=baseline

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

# ── Docker ────────────────────────────────────────────────────────────────────

## Build API and frontend Docker images
docker-build:
	docker build -t $${REGISTRY:-sentinel}/sentinel-api:$${IMAGE_TAG:-latest} \
		-f packages/api/Dockerfile .
	docker build -t $${REGISTRY:-sentinel}/sentinel-frontend:$${IMAGE_TAG:-latest} \
		./frontend

## Push images to registry (set REGISTRY and IMAGE_TAG env vars)
docker-push: docker-build
	docker push $${REGISTRY:-sentinel}/sentinel-api:$${IMAGE_TAG:-latest}
	docker push $${REGISTRY:-sentinel}/sentinel-frontend:$${IMAGE_TAG:-latest}

## Start full production stack (Neo4j + API + Frontend + Nginx) on port 80
up-prod:
	docker compose -f docker-compose.prod.yml up -d
	@echo "SENTINEL production stack running at http://localhost"

## Stop production stack
down-prod:
	docker compose -f docker-compose.prod.yml down

## Tail logs from production stack (Ctrl-C to stop)
logs:
	docker compose -f docker-compose.prod.yml logs -f

## Tail logs from dev stack (Ctrl-C to stop)
logs-dev:
	docker compose logs -f

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
