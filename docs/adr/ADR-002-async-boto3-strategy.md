# ADR-002: Async boto3 Strategy via asyncio.to_thread

**Status:** Accepted
**Date:** 2026-02-25
**Deciders:** Baselyne Systems founding team

---

## Context

SENTINEL's perception engine needs to make many AWS API calls concurrently
(multiple regions × multiple services). The backend uses Python asyncio with
FastAPI. However, boto3 is fundamentally **synchronous** and blocks the event loop.

Options evaluated:

1. **aiobotocore**: async wrapper around botocore. More native async, but complex
   dependency and maintenance overhead. Authentication/session management differs.

2. **asyncio.to_thread()**: runs synchronous functions on a thread pool executor.
   Standard library, zero additional deps, well-understood semantics.

3. **multiprocessing**: full process-level parallelism. Significant overhead, IPC
   complexity, and overkill for I/O-bound AWS API calls.

---

## Decision

Wrap all boto3 calls with **`asyncio.to_thread()`** via the `run_sync()` helper
in `connectors/aws/base.py`.

```python
async def run_sync(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)

# Usage in connectors:
raw_roles = await run_sync(paginate, iam, "list_roles", "Roles")
```

GraphBuilder then uses `asyncio.gather()` to run multiple connector calls
concurrently, keeping the event loop free while boto3 blocks on the thread pool.

---

## Rationale

- **Zero dependencies**: `asyncio.to_thread` is stdlib (Python 3.9+)
- **Thread pool is appropriate**: AWS API calls are I/O-bound; threads release the
  GIL during network I/O, so actual parallelism is achieved
- **Transparent**: existing boto3 code works unchanged inside `to_thread`
- **Testable**: moto works transparently with threads (context managers propagate)

---

## Trade-offs accepted

| Trade-off | Mitigation |
|-----------|-----------|
| Thread pool overhead vs. true async | Negligible vs. network latency |
| Thread pool size limits concurrency | Default ThreadPoolExecutor is fine for 10–20 concurrent region scans |
| Slightly verbose call sites | `run_sync` helper keeps it to one line |

---

## Consequences

- All boto3 calls in connectors must use `await run_sync(...)` or
  `await asyncio.to_thread(...)`
- Direct synchronous boto3 calls in an async function will block the event loop
  (caught by `make lint` via asyncio-aware linters)
- boto3 sessions are created synchronously via `asyncio.to_thread(get_session, ...)`
