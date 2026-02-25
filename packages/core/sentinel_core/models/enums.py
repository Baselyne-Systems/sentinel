"""
Enumeration types for the SENTINEL graph model.

All enums use ``StrEnum`` so they serialize as plain strings in Pydantic models,
Neo4j properties, and JSON responses — no extra ``.value`` calls needed.

Design decision: string enums instead of int enums so Neo4j properties remain
human-readable without a lookup table.
"""

from enum import StrEnum


class CloudProvider(StrEnum):
    """Cloud providers supported by SENTINEL.

    Phase 1 supports AWS only. GCP and Azure are reserved for Phase 4.

    Values:
        AWS: Amazon Web Services
        GCP: Google Cloud Platform (Phase 4)
        AZURE: Microsoft Azure (Phase 4)
    """

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class ResourceType(StrEnum):
    """AWS resource types that SENTINEL models as graph nodes.

    These string values are used as:
    - Neo4j node labels (alongside the base ``GraphNode`` label)
    - ``resource_type`` property on every graph node
    - Filter values in ``GET /api/v1/graph/nodes?type=``

    Groupings:
        Account/Org: AWS_ACCOUNT, REGION
        Compute:     EC2_INSTANCE, LAMBDA_FUNCTION
        Network:     SECURITY_GROUP, VPC, SUBNET
        Storage:     S3_BUCKET
        Database:    RDS_INSTANCE
        IAM:         IAM_ROLE, IAM_USER, IAM_POLICY
    """

    # Account / org
    AWS_ACCOUNT = "AWSAccount"
    REGION = "Region"

    # Compute
    EC2_INSTANCE = "EC2Instance"
    LAMBDA_FUNCTION = "LambdaFunction"

    # Network
    SECURITY_GROUP = "SecurityGroup"
    VPC = "VPC"
    SUBNET = "Subnet"

    # Storage
    S3_BUCKET = "S3Bucket"

    # Database
    RDS_INSTANCE = "RDSInstance"

    # IAM
    IAM_ROLE = "IAMRole"
    IAM_USER = "IAMUser"
    IAM_POLICY = "IAMPolicy"


class EdgeType(StrEnum):
    """Relationship types between graph nodes.

    These become Neo4j relationship type labels (e.g. ``-[:IN_VPC]->``)
    and are stored on ``GraphEdge.edge_type``.

    Edge semantics:
        HAS_RESOURCE:      AWSAccount→Region, Region→Resource
        IN_VPC:            EC2/Lambda/RDS/Subnet → VPC
        IN_SUBNET:         EC2/RDS → Subnet
        MEMBER_OF_SG:      EC2/Lambda/RDS → SecurityGroup
        CAN_ASSUME:        IAMRole/User → IAMRole (trust relationship)
        HAS_ATTACHED_POLICY: IAMRole/User → IAMPolicy
        EXECUTES_AS:       LambdaFunction → IAMRole
        PEER_OF:           VPC ↔ VPC (peering, bidirectional)
    """

    HAS_RESOURCE = "HAS_RESOURCE"
    IN_VPC = "IN_VPC"
    IN_SUBNET = "IN_SUBNET"
    MEMBER_OF_SG = "MEMBER_OF_SG"
    CAN_ASSUME = "CAN_ASSUME"
    HAS_ATTACHED_POLICY = "HAS_ATTACHED_POLICY"
    EXECUTES_AS = "EXECUTES_AS"
    PEER_OF = "PEER_OF"


class PostureFlag(StrEnum):
    """Security posture flags that can be stamped on any graph node.

    Flags are stored as a string list on the ``posture_flags`` property of
    Neo4j nodes. Two categories of flags exist:

    **Severity labels** (always added alongside a specific flag):
        CRITICAL, HIGH, MEDIUM, LOW

    **Specific CIS finding flags**:
        These describe the exact violation. A node with a CRITICAL finding
        will have both a specific flag (e.g. ``SG_OPEN_SSH``) AND the
        severity label (``CRITICAL``) in its ``posture_flags`` list.

    Example node posture_flags:
        ``["CRITICAL", "SG_OPEN_SSH", "HIGH", "SG_OPEN_RDP"]``
    """

    # Severity labels (always co-added with a specific flag)
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    # S3 findings
    S3_PUBLIC_ACCESS = "S3_PUBLIC_ACCESS"
    S3_NO_VERSIONING = "S3_NO_VERSIONING"
    S3_NO_ENCRYPTION = "S3_NO_ENCRYPTION"
    S3_NO_LOGGING = "S3_NO_LOGGING"
    S3_NO_POLICY = "S3_NO_POLICY"

    # Security group findings
    SG_OPEN_SSH = "SG_OPEN_SSH"
    SG_OPEN_RDP = "SG_OPEN_RDP"
    SG_OPEN_ALL_INGRESS = "SG_OPEN_ALL_INGRESS"

    # IAM findings
    IAM_NO_MFA = "IAM_NO_MFA"
    IAM_STAR_POLICY = "IAM_STAR_POLICY"
    IAM_ROOT_USAGE = "IAM_ROOT_USAGE"
    IAM_STALE_CREDENTIALS = "IAM_STALE_CREDENTIALS"
    IAM_STALE_ACCESS_KEYS = "IAM_STALE_ACCESS_KEYS"
    IAM_WEAK_PASSWORD_POLICY = "IAM_WEAK_PASSWORD_POLICY"

    # RDS findings
    RDS_PUBLIC = "RDS_PUBLIC"
    RDS_NO_ENCRYPTION = "RDS_NO_ENCRYPTION"
    RDS_NO_MULTI_AZ = "RDS_NO_MULTI_AZ"

    # CloudTrail findings
    NO_CLOUDTRAIL = "NO_CLOUDTRAIL"
    NO_CLOUDTRAIL_VALIDATION = "NO_CLOUDTRAIL_VALIDATION"

    # EC2 findings
    EBS_UNENCRYPTED = "EBS_UNENCRYPTED"

    # Lambda findings
    LAMBDA_PUBLIC_URL = "LAMBDA_PUBLIC_URL"
    LAMBDA_NO_VPC = "LAMBDA_NO_VPC"

    # VPC findings
    VPC_CROSS_ACCOUNT_PEERING = "VPC_CROSS_ACCOUNT_PEERING"


class Severity(StrEnum):
    """Standalone severity enum used in CIS rules and API filter parameters.

    Mirrors the severity labels in PostureFlag but as a separate, cleaner
    enum for use in function signatures and API query parameters.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
