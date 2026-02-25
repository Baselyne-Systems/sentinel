"""
EC2 remediators — enable EBS encryption by default for an AWS account+region.

Interface:
    def execute(params: dict, session: boto3.Session) -> dict

This is a regional account-level setting, not tied to a specific EC2 instance.
New EBS volumes created after this call are encrypted by default with the
account's default KMS key.

Reversible: Yes — can be disabled via disable_ebs_encryption_by_default.
"""

from __future__ import annotations


def enable_ebs_encryption(params: dict, session) -> dict:
    """Enable EBS encryption by default for the session's account and region.

    This is an account-level, region-scoped setting.  Once enabled, all new
    EBS volumes and snapshots created in the region are automatically encrypted
    using the account's default KMS key (aws/ebs).

    Required params:
        region: AWS region name (e.g. ``us-east-1``).

    Returns:
        Summary dict with region and ebs_encryption_by_default flag.
    """
    region: str = params["region"]
    ec2 = session.client("ec2", region_name=region)
    ec2.enable_ebs_encryption_by_default()
    return {"region": region, "ebs_encryption_by_default": True}
