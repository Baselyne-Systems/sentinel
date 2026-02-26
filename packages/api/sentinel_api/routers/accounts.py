"""
/api/v1/accounts — register and manage AWS accounts for SENTINEL scanning.

Before scanning a cross-account environment, register the account here with
an IAM assume-role ARN. The scan engine will use STS AssumeRole to access
the account's resources.

For same-account scanning (using the API's own credential chain), registration
is optional — just call POST /scan/trigger directly.

Account registrations are persisted in the SQLite store (sentinel.db) and
survive API restarts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel_api.deps import StoreDep
from sentinel_api.schemas import AccountResponse, ErrorResponse

router = APIRouter(prefix="/accounts", tags=["accounts"])


class AccountRegistration(BaseModel):
    """Request body for registering or updating an AWS account."""

    account_id: str = Field(
        ...,
        description="12-digit AWS account ID.",
        pattern=r"^\d{12}$",
        examples=["123456789012"],
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
        examples=[["us-east-1"], ["us-east-1", "us-west-2", "eu-west-1"]],
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
async def register_account(body: AccountRegistration, store: StoreDep) -> dict[str, Any]:
    """
    Register an AWS account for scanning.

    Registering an account is required before scanning if you need to:
    - Use a specific assume-role ARN for cross-account access
    - Configure non-default regions

    For simple same-account scans (AWS_REGIONS env var), registration is optional.
    """
    now = datetime.now(UTC).isoformat()
    existing = await store.get_account(body.account_id)
    account: dict[str, Any] = {
        "account_id": body.account_id,
        "name": body.name or (existing["name"] if existing else ""),
        "assume_role_arn": body.assume_role_arn,
        "regions": body.regions,
        "registered_at": existing["registered_at"] if existing else now,
        "updated_at": now,
    }
    await store.upsert_account(account)
    return account


@router.get(
    "",
    response_model=list[AccountResponse],
    summary="List registered accounts",
    description="Return all AWS accounts registered with this SENTINEL instance.",
    responses={
        200: {"description": "All registered accounts"},
    },
)
async def list_accounts(store: StoreDep) -> list[dict[str, Any]]:
    """Return all registered AWS accounts."""
    return await store.list_accounts()


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
async def get_account(account_id: str, store: StoreDep) -> dict[str, Any]:
    """Get a registered account by ID."""
    account = await store.get_account(account_id)
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
async def delete_account(account_id: str, store: StoreDep) -> dict[str, str]:
    """Remove a registered account."""
    account = await store.get_account(account_id)
    if not account:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id!r} is not registered.",
        )
    await store.delete_account(account_id)
    return {"status": "deleted", "account_id": account_id}
