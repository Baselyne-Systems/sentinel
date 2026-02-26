"""
SQLite-backed async job/account store for SENTINEL.

Replaces the module-level in-memory dicts in scan.py, remediation.py, and
accounts.py with a single aiosqlite database.  The database file defaults to
``./sentinel.db`` and is configurable via the ``SENTINEL_DB_PATH`` env var.

Usage::

    store = SentinelStore(db_path="./sentinel.db")
    await store.initialize()   # creates tables if they don't exist
    ...
    await store.close()

Pass ``db_path=":memory:"`` in tests for an ephemeral in-memory database.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiosqlite
from sentinel_remediation.models import RemediationJob

logger = logging.getLogger(__name__)

_CREATE_SCAN_JOBS = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    account_id   TEXT NOT NULL,
    regions      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    result       TEXT,
    error        TEXT
)
"""

_CREATE_REMEDIATION_JOBS = """
CREATE TABLE IF NOT EXISTS remediation_jobs (
    job_id       TEXT PRIMARY KEY,
    proposal     TEXT NOT NULL,
    status       TEXT NOT NULL,
    proposed_at  TEXT NOT NULL,
    approved_at  TEXT,
    rejected_at  TEXT,
    executed_at  TEXT,
    completed_at TEXT,
    error        TEXT,
    output       TEXT
)
"""

_CREATE_ACCOUNTS = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id      TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    assume_role_arn TEXT NOT NULL DEFAULT '',
    regions         TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    updated_at      TEXT NOT NULL
)
"""


class SentinelStore:
    """Async SQLite store for scan jobs, remediation jobs, and accounts."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Open the database connection and create tables if needed."""
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute(_CREATE_SCAN_JOBS)
        await self._db.execute(_CREATE_REMEDIATION_JOBS)
        await self._db.execute(_CREATE_ACCOUNTS)
        await self._db.commit()
        logger.info("SentinelStore initialized (db=%s)", self._db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ── Scan jobs ──────────────────────────────────────────────────────────────

    async def create_scan_job(self, job: dict[str, Any]) -> None:
        """Insert a new scan job record."""
        assert self._db is not None
        await self._db.execute(
            """
            INSERT INTO scan_jobs
                (job_id, status, account_id, regions, started_at, completed_at, result, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job["job_id"],
                job["status"],
                job["account_id"],
                json.dumps(job["regions"]),
                job["started_at"],
                job.get("completed_at"),
                json.dumps(job["result"]) if job.get("result") is not None else None,
                job.get("error"),
            ),
        )
        await self._db.commit()

    async def update_scan_job(self, job_id: str, **fields: Any) -> None:
        """Partially update a scan job by job_id."""
        assert self._db is not None
        if not fields:
            return
        # Serialize complex fields
        if "regions" in fields:
            fields["regions"] = json.dumps(fields["regions"])
        if "result" in fields and fields["result"] is not None:
            fields["result"] = json.dumps(fields["result"])

        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [job_id]
        await self._db.execute(
            f"UPDATE scan_jobs SET {set_clause} WHERE job_id = ?",  # noqa: S608
            values,
        )
        await self._db.commit()

    async def get_scan_job(self, job_id: str) -> dict[str, Any] | None:
        """Return a scan job dict or None if not found."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _row_to_scan_job(row) if row else None

    async def list_scan_jobs(self) -> list[dict[str, Any]]:
        """Return all scan jobs, newest first."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM scan_jobs ORDER BY started_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_scan_job(r) for r in rows]

    # ── Remediation jobs ───────────────────────────────────────────────────────

    async def create_remediation_job(self, job: RemediationJob) -> None:
        """Insert a new remediation job."""
        assert self._db is not None
        d = job.model_dump(mode="json")
        await self._db.execute(
            """
            INSERT INTO remediation_jobs
                (job_id, proposal, status, proposed_at, approved_at,
                 rejected_at, executed_at, completed_at, error, output)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d["job_id"],
                json.dumps(d["proposal"]),
                d["status"],
                d["proposed_at"],
                d.get("approved_at"),
                d.get("rejected_at"),
                d.get("executed_at"),
                d.get("completed_at"),
                d.get("error"),
                json.dumps(d["output"]) if d.get("output") is not None else None,
            ),
        )
        await self._db.commit()

    async def update_remediation_job(self, job: RemediationJob) -> None:
        """Overwrite all mutable fields for an existing remediation job."""
        assert self._db is not None
        d = job.model_dump(mode="json")
        await self._db.execute(
            """
            UPDATE remediation_jobs SET
                status       = ?,
                approved_at  = ?,
                rejected_at  = ?,
                executed_at  = ?,
                completed_at = ?,
                error        = ?,
                output       = ?
            WHERE job_id = ?
            """,
            (
                d["status"],
                d.get("approved_at"),
                d.get("rejected_at"),
                d.get("executed_at"),
                d.get("completed_at"),
                d.get("error"),
                json.dumps(d["output"]) if d.get("output") is not None else None,
                d["job_id"],
            ),
        )
        await self._db.commit()

    async def get_remediation_job(self, job_id: str) -> RemediationJob | None:
        """Return a RemediationJob or None if not found."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM remediation_jobs WHERE job_id = ?", (job_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _row_to_remediation_job(row) if row else None

    async def list_remediation_jobs(self) -> list[RemediationJob]:
        """Return all remediation jobs, newest first."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM remediation_jobs ORDER BY proposed_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_remediation_job(r) for r in rows]

    # ── Accounts ───────────────────────────────────────────────────────────────

    async def upsert_account(self, account: dict[str, Any]) -> None:
        """Insert or replace an account record."""
        assert self._db is not None
        await self._db.execute(
            """
            INSERT INTO accounts
                (account_id, name, assume_role_arn, regions, registered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                name            = excluded.name,
                assume_role_arn = excluded.assume_role_arn,
                regions         = excluded.regions,
                updated_at      = excluded.updated_at
            """,
            (
                account["account_id"],
                account.get("name", ""),
                account.get("assume_role_arn", ""),
                json.dumps(account["regions"]),
                account["registered_at"],
                account["updated_at"],
            ),
        )
        await self._db.commit()

    async def get_account(self, account_id: str) -> dict[str, Any] | None:
        """Return an account dict or None if not found."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _row_to_account(row) if row else None

    async def list_accounts(self) -> list[dict[str, Any]]:
        """Return all registered accounts."""
        assert self._db is not None
        async with self._db.execute("SELECT * FROM accounts") as cursor:
            rows = await cursor.fetchall()
        return [_row_to_account(r) for r in rows]

    async def delete_account(self, account_id: str) -> None:
        """Delete an account record."""
        assert self._db is not None
        await self._db.execute(
            "DELETE FROM accounts WHERE account_id = ?", (account_id,)
        )
        await self._db.commit()


# ── Row deserializers ──────────────────────────────────────────────────────────


def _row_to_scan_job(row: aiosqlite.Row) -> dict[str, Any]:
    d = dict(row)
    d["regions"] = json.loads(d["regions"])
    if d.get("result") is not None:
        d["result"] = json.loads(d["result"])
    return d


def _row_to_remediation_job(row: aiosqlite.Row) -> RemediationJob:
    d = dict(row)
    d["proposal"] = json.loads(d["proposal"])
    if d.get("output") is not None:
        d["output"] = json.loads(d["output"])
    return RemediationJob.model_validate(d)


def _row_to_account(row: aiosqlite.Row) -> dict[str, Any]:
    d = dict(row)
    d["regions"] = json.loads(d["regions"])
    return d
