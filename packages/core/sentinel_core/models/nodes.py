"""Pydantic models for all SENTINEL graph nodes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from sentinel_core.models.enums import CloudProvider, PostureFlag, ResourceType


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GraphNode(BaseModel):
    """Base class for every node in the SENTINEL graph."""

    node_id: str
    cloud_provider: CloudProvider = CloudProvider.AWS
    account_id: str
    region: str = ""
    resource_type: ResourceType
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=_utcnow)
    posture_flags: list[PostureFlag] = Field(default_factory=list)

    model_config = {"use_enum_values": True}

    def neo4j_labels(self) -> list[str]:
        """Return Neo4j node labels: base label + resource-type label."""
        return ["GraphNode", self.resource_type]

    def to_neo4j_props(self) -> dict[str, Any]:
        """Serialize for Neo4j MERGE. Converts nested objects to JSON-safe types.

        Neo4j only supports primitive types and lists of primitives as property
        values. All dict-valued fields (e.g. tags, inbound_rules, trust_policy)
        are JSON-serialized to strings so they round-trip safely.
        """
        data = self.model_dump(mode="json")
        # Serialize tags as JSON string; remove the original dict field.
        data["tags_json"] = json.dumps(self.tags)
        del data["tags"]
        # posture_flags as plain string list
        data["posture_flags"] = [str(f) for f in self.posture_flags]
        data["discovered_at"] = self.discovered_at.isoformat()
        # Serialize any remaining dict or list-of-dict fields to JSON strings.
        for key, value in list(data.items()):
            if isinstance(value, dict):
                data[key] = json.dumps(value)
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                data[key] = json.dumps(value)
        return data


# ── Account / Organization ─────────────────────────────────────────────────────


class AWSAccount(GraphNode):
    resource_type: ResourceType = ResourceType.AWS_ACCOUNT
    name: str = ""
    regions: list[str] = Field(default_factory=list)

    @field_validator("node_id", mode="before")
    @classmethod
    def set_node_id(cls, v: str, info: Any) -> str:
        return v or info.data.get("account_id", v)


class Region(GraphNode):
    resource_type: ResourceType = ResourceType.REGION
    name: str
    provider: CloudProvider = CloudProvider.AWS


# ── Compute ───────────────────────────────────────────────────────────────────


class EC2Instance(GraphNode):
    resource_type: ResourceType = ResourceType.EC2_INSTANCE
    instance_id: str
    instance_type: str = ""
    state: str = ""
    public_ip: str | None = None
    private_ip: str | None = None
    ami_id: str = ""
    vpc_id: str | None = None
    subnet_id: str | None = None
    security_group_ids: list[str] = Field(default_factory=list)
    iam_instance_profile: str | None = None
    key_name: str | None = None
    launch_time: datetime | None = None


class LambdaFunction(GraphNode):
    resource_type: ResourceType = ResourceType.LAMBDA_FUNCTION
    function_name: str
    arn: str
    runtime: str = ""
    role_arn: str = ""
    handler: str = ""
    code_size: int = 0
    memory_size: int = 128
    timeout: int = 3
    vpc_config: dict[str, Any] = Field(default_factory=dict)
    environment_variables: dict[str, str] = Field(default_factory=dict)
    last_modified: str = ""


# ── Network ───────────────────────────────────────────────────────────────────


class InboundRule(BaseModel):
    ip_protocol: str = "-1"
    from_port: int | None = None
    to_port: int | None = None
    cidr: str = ""
    cidr_ipv6: str = ""
    description: str = ""


class SecurityGroup(GraphNode):
    resource_type: ResourceType = ResourceType.SECURITY_GROUP
    group_id: str
    name: str
    description: str = ""
    vpc_id: str | None = None
    inbound_rules: list[dict[str, Any]] = Field(default_factory=list)
    outbound_rules: list[dict[str, Any]] = Field(default_factory=list)


class VPC(GraphNode):
    resource_type: ResourceType = ResourceType.VPC
    vpc_id: str
    cidr_block: str = ""
    is_default: bool = False
    state: str = ""
    dhcp_options_id: str | None = None


class Subnet(GraphNode):
    resource_type: ResourceType = ResourceType.SUBNET
    subnet_id: str
    cidr: str = ""
    az: str = ""
    public_facing: bool = False
    vpc_id: str | None = None
    available_ips: int = 0


# ── Storage ───────────────────────────────────────────────────────────────────


class S3Bucket(GraphNode):
    resource_type: ResourceType = ResourceType.S3_BUCKET
    name: str
    is_public: bool = False
    versioning: bool = False
    encryption: bool = False
    logging: bool = False
    public_access_block: bool = False
    creation_date: datetime | None = None
    policy_exists: bool = False
    acl_public: bool = False


# ── Database ──────────────────────────────────────────────────────────────────


class RDSInstance(GraphNode):
    resource_type: ResourceType = ResourceType.RDS_INSTANCE
    db_id: str
    engine: str = ""
    engine_version: str = ""
    instance_class: str = ""
    publicly_accessible: bool = False
    encrypted: bool = False
    multi_az: bool = False
    db_subnet_group: str = ""
    security_group_ids: list[str] = Field(default_factory=list)
    vpc_id: str | None = None
    endpoint: str | None = None
    port: int | None = None
    status: str = ""
    deletion_protection: bool = False


# ── IAM ───────────────────────────────────────────────────────────────────────


class IAMRole(GraphNode):
    resource_type: ResourceType = ResourceType.IAM_ROLE
    role_id: str
    name: str
    arn: str
    trust_policy: dict[str, Any] = Field(default_factory=dict)
    max_session: int = 3600
    path: str = "/"
    attached_policy_arns: list[str] = Field(default_factory=list)
    inline_policy_names: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class IAMUser(GraphNode):
    resource_type: ResourceType = ResourceType.IAM_USER
    user_id: str
    name: str
    arn: str
    has_mfa: bool = False
    has_console_access: bool = False
    password_last_used: datetime | None = None
    access_key_count: int = 0
    attached_policy_arns: list[str] = Field(default_factory=list)
    group_names: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class IAMPolicy(GraphNode):
    resource_type: ResourceType = ResourceType.IAM_POLICY
    policy_arn: str
    name: str
    document: dict[str, Any] = Field(default_factory=dict)
    is_managed: bool = True
    is_aws_managed: bool = False
    attachment_count: int = 0
    path: str = "/"
    created_at: datetime | None = None
