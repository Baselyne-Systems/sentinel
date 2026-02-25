"""
CIS AWS Foundations Benchmark v1.5 — structured rules for SENTINEL.

Each CISRule embeds a Cypher query (cypher_check) that, when run against Neo4j,
returns non-empty results if the rule is violated. The evaluator stamps
posture_flags on the offending nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sentinel_core.models.enums import ResourceType

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass
class CISRule:
    id: str
    title: str
    severity: Severity
    resource_types: list[ResourceType]
    cypher_check: str
    """Cypher query — non-empty result means the rule is VIOLATED."""
    posture_flag: str
    """The PostureFlag string value to stamp on violating nodes."""
    remediation_hint: str
    tags: list[str] = field(default_factory=list)


# ── CIS Section 1: IAM ────────────────────────────────────────────────────────

CIS_1_1 = CISRule(
    id="CIS-1.1",
    title="Avoid the use of the 'root' account",
    severity="CRITICAL",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser)
    WHERE u.name IN ['root', 'Root', 'AWS Root']
    RETURN u.node_id AS node_id, u.name AS name
    """,
    posture_flag="IAM_ROOT_USAGE",
    remediation_hint="Do not use root account for day-to-day operations. Enable MFA and restrict root access.",
    tags=["iam", "root"],
)

CIS_1_2 = CISRule(
    id="CIS-1.2",
    title="Ensure MFA is enabled for the 'root' account",
    severity="CRITICAL",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser)
    WHERE u.name IN ['root', 'Root'] AND u.has_mfa = false
    RETURN u.node_id AS node_id, u.name AS name
    """,
    posture_flag="IAM_NO_MFA",
    remediation_hint="Enable MFA for the root account via AWS Console > My Security Credentials.",
    tags=["iam", "mfa", "root"],
)

CIS_1_3 = CISRule(
    id="CIS-1.3",
    title="Ensure credentials unused for 90 days or greater are disabled",
    severity="HIGH",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser)
    WHERE u.has_console_access = true
      AND u.password_last_used IS NOT NULL
      AND duration.inDays(datetime(u.password_last_used), datetime()).days > 90
    RETURN u.node_id AS node_id, u.name AS name
    """,
    posture_flag="IAM_STALE_CREDENTIALS",
    remediation_hint="Disable or delete IAM users with credentials unused for 90+ days.",
    tags=["iam", "credentials"],
)

CIS_1_4 = CISRule(
    id="CIS-1.4",
    title="Ensure access keys are rotated every 90 days or less",
    severity="HIGH",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser)
    WHERE u.access_key_count > 0
    RETURN u.node_id AS node_id, u.name AS name
    """,
    posture_flag="IAM_STALE_ACCESS_KEYS",
    remediation_hint="Rotate IAM access keys every 90 days. Use AWS Config rule access-keys-rotated.",
    tags=["iam", "access-keys"],
)

CIS_1_5 = CISRule(
    id="CIS-1.5",
    title="Ensure IAM password policy requires at least one uppercase letter",
    severity="MEDIUM",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser {has_console_access: true})
    WHERE u.password_policy_uppercase IS NULL OR u.password_policy_uppercase = false
    RETURN u.node_id AS node_id, u.name AS name
    LIMIT 1
    """,
    posture_flag="IAM_WEAK_PASSWORD_POLICY",
    remediation_hint="Update the IAM account password policy to require uppercase letters.",
    tags=["iam", "password-policy"],
)

CIS_1_10 = CISRule(
    id="CIS-1.10",
    title="Ensure MFA is enabled for all IAM users that have a console password",
    severity="HIGH",
    resource_types=[ResourceType.IAM_USER],
    cypher_check="""
    MATCH (u:IAMUser {has_console_access: true, has_mfa: false})
    WHERE NOT u.name IN ['root', 'Root']
    RETURN u.node_id AS node_id, u.name AS name
    """,
    posture_flag="IAM_NO_MFA",
    remediation_hint="Enable MFA for all IAM users with console access.",
    tags=["iam", "mfa"],
)

CIS_1_16 = CISRule(
    id="CIS-1.16",
    title="Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
    severity="CRITICAL",
    resource_types=[ResourceType.IAM_POLICY],
    cypher_check="""
    MATCH (p:IAMPolicy)
    WHERE 'IAM_STAR_POLICY' IN p.posture_flags
    RETURN p.node_id AS node_id, p.name AS name
    """,
    posture_flag="IAM_STAR_POLICY",
    remediation_hint="Replace wildcard policies with least-privilege policies scoped to specific resources.",
    tags=["iam", "least-privilege"],
)

# ── CIS Section 2: Storage ────────────────────────────────────────────────────

CIS_2_1_1 = CISRule(
    id="CIS-2.1.1",
    title="Ensure S3 Bucket Policy is set to deny HTTP requests",
    severity="MEDIUM",
    resource_types=[ResourceType.S3_BUCKET],
    cypher_check="""
    MATCH (b:S3Bucket)
    WHERE b.policy_exists = false
    RETURN b.node_id AS node_id, b.name AS name
    """,
    posture_flag="S3_NO_POLICY",
    remediation_hint="Add a bucket policy that denies all HTTP (non-HTTPS) requests.",
    tags=["s3", "encryption-in-transit"],
)

CIS_2_1_2 = CISRule(
    id="CIS-2.1.2",
    title="Ensure MFA Delete is enabled on S3 buckets",
    severity="MEDIUM",
    resource_types=[ResourceType.S3_BUCKET],
    cypher_check="""
    MATCH (b:S3Bucket {versioning: false})
    RETURN b.node_id AS node_id, b.name AS name
    """,
    posture_flag="S3_NO_VERSIONING",
    remediation_hint="Enable versioning and MFA Delete on S3 buckets containing sensitive data.",
    tags=["s3", "versioning"],
)

CIS_2_1_5 = CISRule(
    id="CIS-2.1.5",
    title="Ensure that S3 Buckets are configured with 'Block public access'",
    severity="CRITICAL",
    resource_types=[ResourceType.S3_BUCKET],
    cypher_check="""
    MATCH (b:S3Bucket {is_public: true})
    RETURN b.node_id AS node_id, b.name AS name
    """,
    posture_flag="S3_PUBLIC_ACCESS",
    remediation_hint="Enable S3 Block Public Access at both bucket and account level.",
    tags=["s3", "public-access"],
)

CIS_2_1_6 = CISRule(
    id="CIS-2.1.6",
    title="Ensure S3 bucket access logging is enabled",
    severity="LOW",
    resource_types=[ResourceType.S3_BUCKET],
    cypher_check="""
    MATCH (b:S3Bucket {logging: false})
    RETURN b.node_id AS node_id, b.name AS name
    """,
    posture_flag="S3_NO_LOGGING",
    remediation_hint="Enable server access logging on all S3 buckets.",
    tags=["s3", "logging"],
)

CIS_2_2_1 = CISRule(
    id="CIS-2.2.1",
    title="Ensure EBS volume encryption is enabled",
    severity="HIGH",
    resource_types=[ResourceType.EC2_INSTANCE],
    cypher_check="""
    MATCH (i:EC2Instance)
    WHERE 'EBS_UNENCRYPTED' IN i.posture_flags
    RETURN i.node_id AS node_id, i.instance_id AS instance_id
    """,
    posture_flag="EBS_UNENCRYPTED",
    remediation_hint="Enable default EBS encryption in EC2 settings or encrypt volumes individually.",
    tags=["ec2", "encryption"],
)

CIS_2_3_1 = CISRule(
    id="CIS-2.3.1",
    title="Ensure that encryption-at-rest is enabled for RDS Instances",
    severity="HIGH",
    resource_types=[ResourceType.RDS_INSTANCE],
    cypher_check="""
    MATCH (r:RDSInstance {encrypted: false})
    RETURN r.node_id AS node_id, r.db_id AS db_id
    """,
    posture_flag="RDS_NO_ENCRYPTION",
    remediation_hint="Enable storage encryption when creating RDS instances. Existing instances require snapshot restoration.",
    tags=["rds", "encryption"],
)

CIS_2_3_2 = CISRule(
    id="CIS-2.3.2",
    title="Ensure that public access is not given to RDS Instance",
    severity="CRITICAL",
    resource_types=[ResourceType.RDS_INSTANCE],
    cypher_check="""
    MATCH (r:RDSInstance {publicly_accessible: true})
    RETURN r.node_id AS node_id, r.db_id AS db_id
    """,
    posture_flag="RDS_PUBLIC",
    remediation_hint="Modify RDS instance to disable 'Publicly Accessible' and restrict SG access.",
    tags=["rds", "public-access"],
)

CIS_2_3_3 = CISRule(
    id="CIS-2.3.3",
    title="Ensure that RDS clusters have Multi-AZ enabled",
    severity="MEDIUM",
    resource_types=[ResourceType.RDS_INSTANCE],
    cypher_check="""
    MATCH (r:RDSInstance {multi_az: false})
    RETURN r.node_id AS node_id, r.db_id AS db_id
    """,
    posture_flag="RDS_NO_MULTI_AZ",
    remediation_hint="Enable Multi-AZ for production RDS instances to ensure high availability.",
    tags=["rds", "availability"],
)

# ── CIS Section 3: Networking ─────────────────────────────────────────────────

CIS_3_1 = CISRule(
    id="CIS-3.1",
    title="Ensure security groups do not allow ingress from 0.0.0.0/0 to port 22",
    severity="CRITICAL",
    resource_types=[ResourceType.SECURITY_GROUP],
    cypher_check="""
    MATCH (sg:SecurityGroup)
    WHERE 'SG_OPEN_SSH' IN sg.posture_flags
    RETURN sg.node_id AS node_id, sg.group_id AS group_id, sg.name AS name
    """,
    posture_flag="SG_OPEN_SSH",
    remediation_hint="Restrict SSH (port 22) ingress to specific trusted IP ranges, not 0.0.0.0/0.",
    tags=["security-group", "ssh"],
)

CIS_3_2 = CISRule(
    id="CIS-3.2",
    title="Ensure security groups do not allow ingress from 0.0.0.0/0 to port 3389",
    severity="CRITICAL",
    resource_types=[ResourceType.SECURITY_GROUP],
    cypher_check="""
    MATCH (sg:SecurityGroup)
    WHERE 'SG_OPEN_RDP' IN sg.posture_flags
    RETURN sg.node_id AS node_id, sg.group_id AS group_id, sg.name AS name
    """,
    posture_flag="SG_OPEN_RDP",
    remediation_hint="Restrict RDP (port 3389) ingress to specific trusted IP ranges, not 0.0.0.0/0.",
    tags=["security-group", "rdp"],
)

CIS_3_3 = CISRule(
    id="CIS-3.3",
    title="Ensure the default security group of every VPC restricts all traffic",
    severity="HIGH",
    resource_types=[ResourceType.SECURITY_GROUP],
    cypher_check="""
    MATCH (sg:SecurityGroup)
    WHERE 'SG_OPEN_ALL_INGRESS' IN sg.posture_flags
    RETURN sg.node_id AS node_id, sg.group_id AS group_id, sg.name AS name
    """,
    posture_flag="SG_OPEN_ALL_INGRESS",
    remediation_hint="Remove all inbound and outbound rules from the default security group.",
    tags=["security-group", "default-sg"],
)

CIS_3_4 = CISRule(
    id="CIS-3.4",
    title="Ensure routing tables for VPC peering are 'least access'",
    severity="MEDIUM",
    resource_types=[ResourceType.VPC],
    cypher_check="""
    MATCH (v1:VPC)-[:PEER_OF]->(v2:VPC)
    WHERE v1.account_id <> v2.account_id
    RETURN v1.node_id AS node_id, v1.vpc_id AS vpc_id
    """,
    posture_flag="VPC_CROSS_ACCOUNT_PEERING",
    remediation_hint="Review cross-account VPC peering routes and apply least-privilege routing.",
    tags=["vpc", "peering"],
)

# ── CIS Section 4: Monitoring ─────────────────────────────────────────────────

CIS_4_1 = CISRule(
    id="CIS-4.1",
    title="Ensure AWS CloudTrail is enabled in all regions",
    severity="CRITICAL",
    resource_types=[ResourceType.AWS_ACCOUNT],
    cypher_check="""
    MATCH (a:AWSAccount)
    WHERE 'NO_CLOUDTRAIL' IN a.posture_flags
    RETURN a.node_id AS node_id, a.account_id AS account_id
    """,
    posture_flag="NO_CLOUDTRAIL",
    remediation_hint="Enable CloudTrail with multi-region logging and log file validation.",
    tags=["cloudtrail", "monitoring"],
)

CIS_4_2 = CISRule(
    id="CIS-4.2",
    title="Ensure CloudTrail log file validation is enabled",
    severity="HIGH",
    resource_types=[ResourceType.AWS_ACCOUNT],
    cypher_check="""
    MATCH (a:AWSAccount)
    WHERE 'NO_CLOUDTRAIL_VALIDATION' IN a.posture_flags
    RETURN a.node_id AS node_id, a.account_id AS account_id
    """,
    posture_flag="NO_CLOUDTRAIL_VALIDATION",
    remediation_hint="Enable log file validation in CloudTrail to detect tampering.",
    tags=["cloudtrail", "integrity"],
)

CIS_4_3 = CISRule(
    id="CIS-4.3",
    title="Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
    severity="CRITICAL",
    resource_types=[ResourceType.S3_BUCKET],
    cypher_check="""
    MATCH (b:S3Bucket {is_public: true})
    WHERE b.name CONTAINS 'cloudtrail'
    RETURN b.node_id AS node_id, b.name AS name
    """,
    posture_flag="S3_PUBLIC_ACCESS",
    remediation_hint="Make the CloudTrail S3 bucket private and enable Block Public Access.",
    tags=["s3", "cloudtrail", "public-access"],
)

# ── CIS Section 5: Lambda / Advanced ─────────────────────────────────────────

CIS_5_1 = CISRule(
    id="CIS-5.1",
    title="Ensure Lambda functions are not exposed to the public internet via function URL",
    severity="HIGH",
    resource_types=[ResourceType.LAMBDA_FUNCTION],
    cypher_check="""
    MATCH (f:LambdaFunction)
    WHERE 'LAMBDA_PUBLIC_URL' IN f.posture_flags
    RETURN f.node_id AS node_id, f.function_name AS function_name
    """,
    posture_flag="LAMBDA_PUBLIC_URL",
    remediation_hint="Remove public Lambda function URLs or add auth_type=AWS_IAM.",
    tags=["lambda", "public-access"],
)

CIS_5_2 = CISRule(
    id="CIS-5.2",
    title="Ensure Lambda functions use a VPC",
    severity="LOW",
    resource_types=[ResourceType.LAMBDA_FUNCTION],
    cypher_check="""
    MATCH (f:LambdaFunction)
    WHERE NOT (f)-[:IN_VPC]->(:VPC)
    RETURN f.node_id AS node_id, f.function_name AS function_name
    """,
    posture_flag="LAMBDA_NO_VPC",
    remediation_hint="Configure Lambda functions to run within a VPC for network isolation.",
    tags=["lambda", "network"],
)

# ── Rule registry ─────────────────────────────────────────────────────────────

ALL_RULES: list[CISRule] = [
    CIS_1_1,
    CIS_1_2,
    CIS_1_3,
    CIS_1_4,
    CIS_1_5,
    CIS_1_10,
    CIS_1_16,
    CIS_2_1_1,
    CIS_2_1_2,
    CIS_2_1_5,
    CIS_2_1_6,
    CIS_2_2_1,
    CIS_2_3_1,
    CIS_2_3_2,
    CIS_2_3_3,
    CIS_3_1,
    CIS_3_2,
    CIS_3_3,
    CIS_3_4,
    CIS_4_1,
    CIS_4_2,
    CIS_4_3,
    CIS_5_1,
    CIS_5_2,
]

RULES_BY_ID: dict[str, CISRule] = {r.id: r for r in ALL_RULES}
