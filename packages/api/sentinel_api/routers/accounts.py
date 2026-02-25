"""
/api/v1/accounts — register and manage AWS accounts for SENTINEL scanning.

Before scanning a cross-account environment, register the account here with
an IAM assume-role ARN. The scan engine will use STS AssumeRole to access
the account's resources.

For same-account scanning (using the API's own credential chain), registration
is optional — just call POST /scan/trigger directly.

Phase 1: In-memory store. Phase 2: Persist to a database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel_api.schemas import AccountResponse, ErrorResponse

router = APIRouter(prefix="/accounts", tags=["accounts"])

# In-memory account store (Phase 1).
_accounts: dict[str, dict[str, Any]] = {}


class AccountRegistration(BaseModel):
    """Request body for registering or updating an AWS account."""

    account_id: str = Field(
        ...,
        description="12-digit AWS account ID.",
        pattern=r"^\d{12}$",
        examples={"default": {"value": "123456789012"}},
    )
    name: str = Field(
        default="",
        description="Human-friendly account name (e.g. 'Production', 'Staging').",
        max_length=64,
    )
    assume_role_arn: str = Field(
        default="",
        description=(
            "IAM Role ARN for cross-account access via STS AssumeRole. "
            "Leave empty to use the API's default credential chain. "
            "Example: arn:aws:iam::123456789012:role/SentinelReadOnly"
        ),
    )
    regions: list[str] = Field(
        default=["us-east-1"],
        description="AWS regions to include in scans for this account.",
        min_length=1,
        examples={
            "single": {"value": ["us-east-1"]},
            "multi": {"value": ["us-east-1", "us-west-2", "eu-west-1"]},
        },
    )


@router.post(
    "",
    response_model=AccountResponse,
    status_code=200,
    summary="Register or update an AWS account",
    description=(
        "Register an AWS account with SENTINEL. If the account is already registered, "
        "this updates its configuration (idempotent). "
        "After registration, use POST /scan/trigger to scan the account."
    ),
    responses={
        200: {"description": "Account registered or updated"},
    },
)
async def register_account(body: AccountRegistration) -> dict[str, Any]:
    """
    Register an AWS account for scanning.

    Registering an account is required before scanning if you need to:
    - Use a specific assume-role ARN for cross-account access
    - Configure non-default regions

    For simple same-account scans (AWS_REGIONS env var), registration is optional.
    """
    now = datetime.now(timezone.utc).isoformat()
    if body.account_id in _accounts:
        _accounts[body.account_id].update(
            {
                "name": body.name or _accounts[body.account_id]["name"],
                "assume_role_arn": body.assume_role_arn,
                "regions": body.regions,
                "updated_at": now,
            }
        )
    else:
        _accounts[body.account_id] = {
            "account_id": body.account_id,
            "name": body.name,
            "assume_role_arn": body.assume_role_arn,
            "regions": body.regions,
            "registered_at": now,
            "updated_at": now,
        }
    return _accounts[body.account_id]


@router.get(
    "",
    response_model=list[AccountResponse],
    summary="List registered accounts",
    description="Return all AWS accounts registered with this SENTINEL instance.",
    responses={
        200: {"description": "All registered accounts"},
    },
)
async def list_accounts() -> list[dict[str, Any]]:
    """Return all registered AWS accounts."""
    return list(_accounts.values())


@router.get(
    "/{account_id}",
    response_model=AccountResponse,
    summary="Get a registered account",
    description="Return configuration for a specific registered AWS account.",
    responses={
        200: {"description": "Account configuration"},
        404: {"model": ErrorResponse, "description": "Account not registered"},
    },
)
async def get_account(account_id: str) -> dict[str, Any]:
    """Get a registered account by ID."""
    account = _accounts.get(account_id)
    if not account:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id!r} is not registered. Use POST /accounts to register it.",
        )
    return account


@router.delete(
    "/{account_id}",
    summary="Remove a registered account",
    description=(
        "Remove an account from SENTINEL's registry. "
        "This does NOT delete graph data for the account — "
        "use POST /scan/trigger with clear_first=true for that."
    ),
    responses={
        200: {"description": "Account removed"},
        404: {"model": ErrorResponse, "description": "Account not registered"},
    },
)
async def delete_account(account_id: str) -> dict[str, str]:
    """Remove a registered account."""
    if account_id not in _accounts:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id!r} is not registered.",
        )
    del _accounts[account_id]
    return {"status": "deleted", "account_id": account_id}
