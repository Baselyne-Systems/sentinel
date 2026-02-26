"""
E2E test fixtures — real Neo4j via testcontainers.

The ``neo4j_client`` fixture spins up a Neo4j 5 Community container for the
test session, creates the SENTINEL graph indexes, and yields a connected
``Neo4jClient``. The container is shared across all tests in the session
for speed (container startup takes ~15-30 seconds).

Each individual test that writes data should use the ``clean_db`` fixture
(function-scoped) to wipe all nodes between tests so tests don't interfere.

AWS fixtures are re-used from ``tests/conftest.py`` via pytest's conftest
inheritance. All AWS calls use moto, so no real credentials are needed.
"""

from __future__ import annotations

import asyncio
import os
from typing import Generator

import pytest
import pytest_asyncio

from sentinel_api.deps import set_neo4j_client, set_store
from sentinel_api.store import SentinelStore
from sentinel_core.graph.client import Neo4jClient

# ── Neo4j container ───────────────────────────────────────────────────────────

try:
    from testcontainers.neo4j import Neo4jContainer

    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False


@pytest.fixture(scope="session")
def neo4j_container():
    """
    Start a Neo4j 5 Community container for the entire test session.

    The container is shared across all E2E tests to amortize the ~20s
    startup cost. Individual tests must clear their own data via the
    ``clean_db`` fixture.

    Yields:
        neo4j container object (provides ``get_connection_url()``).

    Skips:
        If testcontainers is not installed or Docker is not available.
    """
    if not HAS_TESTCONTAINERS:
        pytest.skip("testcontainers[neo4j] not installed. Run: uv sync")

    try:
        container = Neo4jContainer(image="neo4j:5-community", password="sentinel_test")
        container.start()
        yield container
        container.stop()
    except Exception as e:
        pytest.skip(f"Docker not available or Neo4j container failed to start: {e}")


@pytest.fixture(scope="session")
def neo4j_bolt_url(neo4j_container) -> str:
    """Return the Bolt URL for the running Neo4j container.

    Returns:
        Bolt URI string, e.g. ``bolt://localhost:7687``.
    """
    return neo4j_container.get_connection_url()


@pytest_asyncio.fixture(scope="session")
async def neo4j_client(neo4j_bolt_url) -> Neo4jClient:
    """
    Yield a connected ``Neo4jClient`` for the test session.

    Creates all SENTINEL indexes on first connection. The client is shared
    across all E2E tests and closed at session end.

    Yields:
        Connected ``Neo4jClient`` instance.
    """
    client = Neo4jClient(
        uri=neo4j_bolt_url,
        user="neo4j",
        password="sentinel_test",
    )
    await client.connect()
    await client.ensure_indexes()
    yield client
    await client.close()
    # Reset global singleton so integration tests (TestClient) start clean
    set_neo4j_client(None)  # type: ignore[arg-type]


@pytest_asyncio.fixture(scope="session")
async def job_store() -> SentinelStore:
    """
    Session-scoped in-memory SQLite store for E2E tests.

    Uses :memory: so no file is created; injected into the app via set_store().
    The store is shared across all E2E tests in the session. Individual tests
    that need a clean store should truncate the relevant tables via
    ``await store._db.execute("DELETE FROM ...")``.
    """
    store = SentinelStore(db_path=":memory:")
    await store.initialize()
    set_store(store)
    yield store
    await store.close()
    set_store(None)


@pytest_asyncio.fixture(scope="function")
async def clean_db(neo4j_client: Neo4jClient):
    """
    Delete all nodes from Neo4j before each test.

    This fixture ensures test isolation — each test starts with an empty
    graph. Because the Neo4j container is session-scoped, data written by
    one test would otherwise pollute subsequent tests.

    Yields:
        The ``Neo4jClient`` after the graph has been cleared.
    """
    # Clear all nodes and relationships
    await neo4j_client.execute("MATCH (n) DETACH DELETE n")
    yield neo4j_client
    # Optional: clear after test too for cleanliness
    # await neo4j_client.execute("MATCH (n) DETACH DELETE n")
