FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install uv

# Copy workspace files
COPY pyproject.toml .
COPY packages/ packages/

# Install dependencies
RUN uv sync --package sentinel-api

CMD ["uv", "run", "--package", "sentinel-api", "uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
