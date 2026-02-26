# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Uses the official uv image (Python 3.12 + uv pre-installed) to resolve and
# install all production dependencies into an isolated .venv.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

# Copy the workspace root manifest and lockfile first so that the dependency
# installation layer is cached as long as these files don't change.
COPY pyproject.toml uv.lock ./

# Copy all package pyproject.toml files (needed for workspace resolution).
COPY packages/core/pyproject.toml       packages/core/pyproject.toml
COPY packages/perception/pyproject.toml packages/perception/pyproject.toml
COPY packages/api/pyproject.toml        packages/api/pyproject.toml
COPY packages/agent/pyproject.toml      packages/agent/pyproject.toml
COPY packages/remediation/pyproject.toml packages/remediation/pyproject.toml

# Copy all source code (workspace packages are installed as editable installs).
COPY packages/ packages/

# Install production dependencies only, using the exact lockfile versions.
RUN uv sync --package sentinel-api --no-dev --frozen


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Lean Python image with no build tools. The venv and source code from the
# builder stage are copied in; everything runs as a non-root user.
FROM python:3.12-slim AS runtime

# Create a dedicated non-root user/group.
RUN groupadd -r sentinel && useradd -r -g sentinel -u 1000 sentinel

WORKDIR /app

# Copy the pre-built virtual environment from the builder stage.
COPY --from=builder --chown=sentinel:sentinel /app/.venv /app/.venv

# Copy workspace package source (needed because packages are editable installs
# and the .venv contains references to these paths).
COPY --from=builder --chown=sentinel:sentinel /app/packages /app/packages

# Activate the venv by prepending its bin directory to PATH.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER sentinel

EXPOSE 8000

# Lightweight health check: hit the /health endpoint we expose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()"

CMD ["uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
