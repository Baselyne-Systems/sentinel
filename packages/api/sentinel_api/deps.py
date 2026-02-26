"""FastAPI dependency injection for shared resources."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sentinel_agent.agent import AgentSettings, SentinelAgent
from sentinel_core.graph.client import Neo4jClient
from sentinel_core.graph.queries import GraphQueries
from sentinel_core.knowledge.evaluator import PostureEvaluator

from sentinel_api.config import Settings, get_settings
from sentinel_api.store import SentinelStore

# Module-level singletons (initialized at startup)
_neo4j_client: Neo4jClient | None = None
_store: SentinelStore | None = None


def get_store() -> SentinelStore:
    if _store is None:
        raise RuntimeError("Job store not initialized. Check lifespan setup.")
    return _store


def set_store(store: SentinelStore | None) -> None:
    global _store
    _store = store


def get_neo4j_client() -> Neo4jClient:
    if _neo4j_client is None:
        raise RuntimeError("Neo4j client not initialized. Check lifespan setup.")
    return _neo4j_client


def set_neo4j_client(client: Neo4jClient) -> None:
    global _neo4j_client
    _neo4j_client = client


def get_graph_queries(
    client: Annotated[Neo4jClient, Depends(get_neo4j_client)],
) -> GraphQueries:
    return GraphQueries(client)


def get_posture_evaluator(
    client: Annotated[Neo4jClient, Depends(get_neo4j_client)],
) -> PostureEvaluator:
    return PostureEvaluator(client)


def get_sentinel_agent(
    client: Annotated[Neo4jClient, Depends(get_neo4j_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SentinelAgent:
    agent_settings = AgentSettings(
        anthropic_api_key=settings.anthropic_api_key,
        agent_model=settings.agent_model,
        agent_max_tokens=settings.agent_max_tokens,
        enable_thinking=settings.agent_enable_thinking,
        thinking_budget_tokens=settings.agent_thinking_budget_tokens,
        provider=settings.agent_provider,
        openai_api_key=settings.openai_api_key,
        openai_base_url=settings.agent_base_url,
    )
    return SentinelAgent(neo4j_client=client, settings=agent_settings)


SettingsDep = Annotated[Settings, Depends(get_settings)]
Neo4jDep = Annotated[Neo4jClient, Depends(get_neo4j_client)]
QueriesDep = Annotated[GraphQueries, Depends(get_graph_queries)]
EvaluatorDep = Annotated[PostureEvaluator, Depends(get_posture_evaluator)]
AgentDep = Annotated[SentinelAgent, Depends(get_sentinel_agent)]
StoreDep = Annotated[SentinelStore, Depends(get_store)]
