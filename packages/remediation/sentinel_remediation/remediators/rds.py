"""
RDS remediators — disable public accessibility on an RDS instance.

Interface:
    def execute(params: dict, session: boto3.Session) -> dict

Reversible: Yes — PubliclyAccessible can be re-enabled via modify_db_instance.
"""

from __future__ import annotations


def disable_public_access(params: dict, session) -> dict:
    """Disable public accessibility on an RDS DB instance.

    Sets ``PubliclyAccessible=False`` and applies the change immediately.
    The instance may briefly restart depending on the DB engine.

    Required params:
        db_id:  The RDS DB instance identifier.
        region: AWS region where the DB lives.

    Returns:
        Summary dict with db_id and publicly_accessible flag.
    """
    db_id: str = params["db_id"]
    region: str = params["region"]

    rds = session.client("rds", region_name=region)
    rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    return {"db_id": db_id, "publicly_accessible": False}
