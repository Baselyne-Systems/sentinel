"""
Fixtures for SENTINEL benchmark tests.

All benchmarks run against a real Neo4j container (requires Docker).
The ``neo4j_bolt_url`` and ``neo4j_client`` fixtures are session-scoped
so container startup cost is paid only once per benchmark run.

Usage::

    make bench                         # run all benchmarks
    pytest tests/benchmarks/ -v -m benchmark --timeout=300
"""

from __future__ import annotations

import asyncio

import pytest

try:
    from testcontainers.neo4j import Neo4jContainer

    HAS_TESTCONTAINERS = True
except ImportError:
    HAS_TESTCONTAINERS = False

from sentinel_core.graph.client import Neo4jClient


@pytest.fixture(scope="session")
def neo4j_container():
    if not HAS_TESTCONTAINERS:
        pytest.skip("testcontainers[neo4j] not installed")
    try:
        container = Neo4jContainer(image="neo4j:5-community", password="sentinel_bench")
        container.start()
        yield container
        container.stop()
    except Exception as e:
        pytest.skip(f"Docker unavailable: {e}")


@pytest.fixture(scope="session")
def neo4j_bolt_url(neo4j_container) -> str:
    return neo4j_container.get_connection_url()


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for async benchmark helpers."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def neo4j_client(neo4j_bolt_url, event_loop):
    """Connected Neo4jClient shared across all benchmark tests."""
    async def _setup():
        client = Neo4jClient(
            uri=neo4j_bolt_url,
            user="neo4j",
            password="sentinel_bench",
        )
        await client.connect()
        await client.ensure_indexes()
        return client

    client = event_loop.run_until_complete(_setup())
    yield client
    event_loop.run_until_complete(client.close())


@pytest.fixture()
def clean_graph(neo4j_client, event_loop):
    """Wipe all nodes before each benchmark."""
    event_loop.run_until_complete(
        neo4j_client.execute("MATCH (n) DETACH DELETE n")
    )
    yield neo4j_client
    event_loop.run_until_complete(
        neo4j_client.execute("MATCH (n) DETACH DELETE n")
    )
