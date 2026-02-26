"""Pydantic models for all SENTINEL graph edges."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel_core.models.enums import EdgeType


def _utcnow() -> datetime:
    return datetime.now(UTC)


class GraphEdge(BaseModel):
    """Base class for every edge in the SENTINEL graph."""

    from_node_id: str
    to_node_id: str
    edge_type: EdgeType
    account_id: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    properties: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": True}

    def to_neo4j_props(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["created_at"] = self.created_at.isoformat()
        # Neo4j only accepts primitives; serialize any dict / list-of-dict fields.
        for key, value in list(data.items()):
            if isinstance(value, dict) or (isinstance(value, list) and value and isinstance(value[0], dict)):
                data[key] = json.dumps(value)
        return data


# ── Concrete edge types ────────────────────────────────────────────────────────


class HasResource(GraphEdge):
    """Account → Region, or Region → any resource."""

    edge_type: EdgeType = EdgeType.HAS_RESOURCE


class InVPC(GraphEdge):
    """EC2Instance / LambdaFunction / RDSInstance → VPC."""

    edge_type: EdgeType = EdgeType.IN_VPC


class InSubnet(GraphEdge):
    """EC2Instance / RDSInstance → Subnet."""

    edge_type: EdgeType = EdgeType.IN_SUBNET


class MemberOfSG(GraphEdge):
    """EC2Instance / LambdaFunction / RDSInstance → SecurityGroup."""

    edge_type: EdgeType = EdgeType.MEMBER_OF_SG


class CanAssume(GraphEdge):
    """IAMRole / IAMUser → IAMRole (trust relationship)."""

    edge_type: EdgeType = EdgeType.CAN_ASSUME
    trust_conditions: list[dict[str, Any]] = Field(default_factory=list)


class HasAttachedPolicy(GraphEdge):
    """IAMRole / IAMUser → IAMPolicy."""

    edge_type: EdgeType = EdgeType.HAS_ATTACHED_POLICY
    attachment_type: str = "managed"  # "managed" | "inline"


class ExecutesAs(GraphEdge):
    """LambdaFunction → IAMRole."""

    edge_type: EdgeType = EdgeType.EXECUTES_AS


class PeerOf(GraphEdge):
    """VPC → VPC (bidirectional peering)."""

    edge_type: EdgeType = EdgeType.PEER_OF
    peering_id: str = ""
    status: str = ""
