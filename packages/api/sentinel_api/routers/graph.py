"""
/api/v1/graph — graph node and subgraph endpoints.

Provides read access to the SENTINEL environment graph stored in Neo4j.
All writes happen through the scan pipeline; this router is purely read-only
(plus the optional raw Cypher endpoint for development introspection).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from sentinel_api.config import get_settings
from sentinel_api.deps import Neo4jDep, QueriesDep
from sentinel_api.schemas import (
    ErrorResponse,
    GraphNodeDetailResponse,
    GraphNodeResponse,
    SubgraphResponse,
)

router = APIRouter(prefix="/graph", tags=["graph"])


class RawCypherRequest(BaseModel):
    """Request body for the raw Cypher endpoint (dev only)."""

    cypher: str = Field(
        ...,
        description="Cypher query to execute. Read-only queries recommended.",
        examples=["MATCH (n:S3Bucket {is_public: true}) RETURN n LIMIT 10"],
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Named parameters for the Cypher query.",
    )


@router.get(
    "/nodes",
    response_model=list[GraphNodeResponse],
    summary="List graph nodes",
    description=(
        "Return a paginated list of all discovered AWS resources. "
        "Optionally filter by resource type, account, or region. "
        "Results are ordered by discovery time (newest first)."
    ),
    responses={200: {"description": "List of matching graph nodes"}},
)
async def list_nodes(
    queries: QueriesDep,
    type: str | None = Query(
        None,
        description=(
            "Filter by resource_type. Valid values: AWSAccount, Region, EC2Instance, "
            "SecurityGroup, VPC, Subnet, S3Bucket, RDSInstance, LambdaFunction, "
            "IAMRole, IAMUser, IAMPolicy."
        ),
        examples={"s3": {"value": "S3Bucket"}, "iam": {"value": "IAMRole"}},
    ),
    account_id: str | None = Query(None, description="Filter by AWS account ID.", examples={"default": {"value": "123456789012"}}),
    region: str | None = Query(None, description="Filter by AWS region.", examples={"us-east-1": {"value": "us-east-1"}}),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of nodes to return."),
    offset: int = Query(0, ge=0, description="Number of nodes to skip (for pagination)."),
) -> list[dict[str, Any]]:
    """
    List graph nodes with optional filters.

    Returns up to `limit` nodes matching the specified filters, ordered by
    discovery time descending. Use `offset` for pagination.
    """
    results = await queries.list_nodes(
        resource_type=type,
        account_id=account_id,
        region=region,
        limit=limit,
        offset=offset,
    )
    return [r.get("n", r) for r in results]


@router.get(
    "/nodes/{node_id}",
    response_model=GraphNodeDetailResponse,
    summary="Get node detail",
    description=(
        "Return a single graph node by its unique ID, along with all connected edges. "
        "The `edges` array includes the edge type, the neighboring node's ID and type, "
        "and whether the edge is outbound from this node."
    ),
    responses={
        200: {"description": "Node found with edge list"},
        404: {"model": ErrorResponse, "description": "No node with this ID exists in the graph"},
    },
)
async def get_node(
    node_id: str,
    queries: QueriesDep,
    client: Neo4jDep,
) -> dict[str, Any]:
    """
    Get a single node with all its edges.

    Use this endpoint to inspect the full detail of a resource, including its
    security posture flags and all relationships to other resources.
    Particularly useful for investigating findings: e.g. fetching an S3Bucket
    node that was flagged by a CIS rule will show its `posture_flags`.
    """
    node = await queries.get_resource_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {node_id!r} not found")

    edges_cypher = """
    MATCH (n {node_id: $node_id})-[r]-(neighbor)
    RETURN type(r) AS edge_type,
           neighbor.node_id AS neighbor_id,
           neighbor.resource_type AS neighbor_type,
           startNode(r).node_id = $node_id AS is_outbound
    """
    edges = await client.query(edges_cypher, {"node_id": node_id})

    result = dict(node.get("n", node))
    result["edges"] = edges
    return result


@router.get(
    "/nodes/{node_id}/neighbors",
    response_model=SubgraphResponse,
    summary="Get node subgraph",
    description=(
        "Return all nodes and edges within `depth` hops of the specified node. "
        "Designed for the Graph Explorer frontend (Cytoscape.js). "
        "`depth=1` returns immediate neighbors; `depth=2` (default) includes their neighbors too. "
        "Maximum depth is 5."
    ),
    responses={
        200: {"description": "Subgraph centered on the requested node"},
        404: {"model": ErrorResponse, "description": "Root node not found"},
    },
)
async def get_neighbors(
    node_id: str,
    queries: QueriesDep,
    depth: int = Query(
        2,
        ge=1,
        le=5,
        description="Graph traversal depth. depth=1 = immediate neighbors only.",
    ),
) -> dict[str, Any]:
    """
    Get a subgraph around a node for visualization.

    Returns deduplicated nodes and edges. If the root node has no neighbors,
    returns an empty nodes/edges list (not 404).
    """
    raw = await queries.get_neighbors(node_id, depth=depth)

    nodes_map: dict[str, Any] = {}
    edges_list: list[dict[str, Any]] = []

    for record in raw:
        for node in record.get("nodes", []):
            nid = node.get("node_id")
            if nid and nid not in nodes_map:
                nodes_map[nid] = dict(node)
        for rel in record.get("rels", []):
            edges_list.append(
                {
                    "from": rel.start_node.get("node_id") if hasattr(rel, "start_node") else None,
                    "to": rel.end_node.get("node_id") if hasattr(rel, "end_node") else None,
                    "type": rel.type if hasattr(rel, "type") else str(rel),
                }
            )

    return {
        "nodes": list(nodes_map.values()),
        "edges": edges_list,
        "root_node_id": node_id,
    }


@router.post(
    "/query",
    summary="Raw Cypher query (dev only)",
    description=(
        "Execute an arbitrary Cypher query against the Neo4j graph. "
        "**This endpoint is disabled in production.** "
        "Enable it by setting `ENABLE_RAW_CYPHER=true` in your environment. "
        "Useful for ad-hoc exploration during development. "
        "Returns raw records from Neo4j."
    ),
    responses={
        200: {"description": "Raw query results as a list of records"},
        403: {
            "model": ErrorResponse,
            "description": "Raw Cypher is disabled. Set ENABLE_RAW_CYPHER=true to enable.",
        },
    },
)
async def raw_cypher(
    request: RawCypherRequest,
    client: Neo4jDep,
) -> list[dict[str, Any]]:
    """
    Execute a raw Cypher query. Dev only — controlled by ENABLE_RAW_CYPHER feature flag.

    Example queries:
    - ``MATCH (n:S3Bucket {is_public: true}) RETURN n``
    - ``MATCH p=(sg:SecurityGroup)-[:MEMBER_OF_SG]-(i:EC2Instance) RETURN p``
    - ``MATCH (n) WHERE 'CRITICAL' IN n.posture_flags RETURN n``
    """
    settings = get_settings()
    if not settings.enable_raw_cypher:
        raise HTTPException(
            status_code=403,
            detail="Raw Cypher queries are disabled. Set ENABLE_RAW_CYPHER=true to enable.",
        )
    return await client.query(request.cypher, request.params)
