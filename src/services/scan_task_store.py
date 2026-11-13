"""Shared Redis-backed store for async (task_id + poll) scan task records.

Both the container-security async path and the dependency async path submit a
scan as a background task, stamp a status record in Redis, and expose a poll
endpoint that reads it back. The naive version stored the status with NO
timestamp, so a worker that died right after stamping ``running`` left the
record frozen at ``running`` until the 24h TTL expired — and a poll could not
tell a live-but-slow scan apart from a dead one.

This module centralises the write/read so that:

* every write stamps ``updated_at`` (``created_at`` marks submission and is set
  only on the first ``queued`` write, not carried forward), plus the background
  task re-stamps a ``running`` heartbeat once the slow fetch phase is done and
  the actual scan begins; and
* the poll derives ``failed`` + ``stale`` for a ``running`` record whose
  ``updated_at`` is older than ``stale_after_seconds`` (or missing /
  unparseable) — i.e. a worker that stopped heartbeating is observable as a
  failure instead of a permanent ``running``. A ``queued`` record is NOT
  stale-eligible: with the durable Redis-Streams worker the job sits in the
  stream (reclaim-guaranteed by the consumer-group PEL) until a worker picks it
  up, so a queued job that has not yet started must not false-flip to failed
  just because no worker has read it within ``stale_after_seconds``.

Deliberately free of any FastAPI import: it takes a ``redis_getter`` callable
(evaluated at call time, never bound as a default arg, so router-level test
patches of ``get_redis`` still take effect) and raises plain exceptions the
routers translate to HTTP responses.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Current UTC time as an ISO-8601 string (the wire format for timestamps)."""
    return datetime.now(UTC).isoformat()


class ScanTaskStoreUnavailable(Exception):  # noqa: N818 — public store API name, not "*Error"
    """The results store could not be reached for a write that requires it.

    Raised only when a caller passes ``required=True`` (the initial ``queued``
    write): if we cannot persist the task there is nowhere for the poll to
    observe completion, so the submit endpoint fails loud with 503 instead of
    dropping the scan into a void.
    """


class ScanTaskAccessDenied(Exception):  # noqa: N818 — public store API name, not "*Error"
    """A task record belongs to a different tenant than the caller."""


class AsyncScanTaskRecord(BaseModel):
    """One async scan task's status record, flattened onto the Redis payload.

    ``extra`` carries path-specific top-level fields (e.g. ``container_name``)
    that ``to_payload`` merges onto the flat payload so the poll response keeps
    the exact wire shape existing consumers key on.
    """

    task_id: str
    status: str
    tenant_id: str
    created_at: str | None = None
    updated_at: str | None = None
    error: str | None = None
    result: dict | None = None
    scan_degraded: bool | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}

    def to_payload(self) -> dict:
        """Flatten to the dict persisted in Redis.

        ``exclude_none`` drops absent optionals but KEEPS ``False`` — so a
        completed record's ``scan_degraded=False`` survives to the top level as a
        real bool. ``extra`` is merged in last as top-level keys.
        """
        payload = self.model_dump(exclude={"extra"}, exclude_none=True)
        payload.update(self.extra)
        return payload


class ScanTaskStore:
    """Redis-backed CRUD for async scan task records with staleness derivation."""

    def __init__(
        self,
        *,
        key_prefix: str,
        ttl_seconds: int,
        redis_getter: Callable[[], Any],
        stale_after_seconds: float,
    ) -> None:
        self._key_prefix = key_prefix
        self._ttl = ttl_seconds
        self._redis_getter = redis_getter
        self._stale_after = stale_after_seconds

    def _key(self, task_id: str) -> str:
        return f"{self._key_prefix}{task_id}"

    async def store(self, record: AsyncScanTaskRecord, *, required: bool = False) -> None:
        """Persist a task record, stamping ``updated_at`` (and ``created_at``).

        Best-effort by default: a store failure is logged and swallowed so a
        transient Redis blip on a heartbeat / terminal write does not crash the
        background task. When ``required=True`` (the initial ``queued`` write) a
        failure raises ``ScanTaskStoreUnavailable`` so the submit endpoint can
        fail loud.
        """
        record.updated_at = _now_iso()
        # ``created_at`` marks submission time and is stamped only on the initial
        # ``queued`` write. Later writes build a fresh record and intentionally do
        # NOT carry it forward — reconstructing it would require a read before
        # every write, and only ``updated_at`` drives staleness. So a terminal
        # record has no ``created_at``; that is deliberate, not a dropped field.
        if record.status == "queued" and record.created_at is None:
            record.created_at = record.updated_at
        try:
            client = self._redis_getter()
            await client.set(
                self._key(record.task_id),
                json.dumps(record.to_payload(), default=str),
                ex=self._ttl,
            )
        except (ConnectionError, OSError, RuntimeError) as err:
            if required:
                raise ScanTaskStoreUnavailable(str(err)) from err
            logger.warning("Failed to store async scan task %s: %s", record.task_id, err)

    async def load(self, task_id: str, tenant_id: str) -> dict | None:
        """Read a task record, tenant-guarded and staleness-derived.

        Returns ``None`` when there is no record (unknown task / expired TTL /
        Redis unreachable / corrupt payload) so the caller can render the
        ``pending`` response. Raises ``ScanTaskAccessDenied`` when the record
        belongs to another tenant.
        """
        try:
            client = self._redis_getter()
            cached = await client.get(self._key(task_id))
        except RuntimeError:
            # Redis not initialised (non-fatal startup) — treat as no record.
            return None
        except (ConnectionError, OSError) as err:
            logger.warning("Redis lookup failed for scan task %s: %s", task_id, err)
            return None

        if not cached:
            return None

        try:
            record = json.loads(cached)
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.warning("Corrupt async scan record for %s; treating as pending", task_id)
            return None

        if record.get("tenant_id") != tenant_id:
            raise ScanTaskAccessDenied

        return self._derive_staleness(record)

    def _derive_staleness(self, record: dict) -> dict:
        """Turn a ``running`` record with a stale heartbeat into ``failed``.

        A terminal record (``completed`` / ``failed``) is returned unchanged, and
        so is a ``queued`` record — a queued job is durable in the Redis stream
        (the consumer-group PEL guarantees reclaim), so it must not false-flip to
        failed merely because no worker has started it yet. Only a ``running``
        record whose ``updated_at`` is older than ``stale_after`` (or missing /
        unparseable) is presumed dead: return a copy with ``status="failed"``,
        ``stale=True`` and an explanatory ``error``.
        """
        if record.get("status") != "running":
            return record

        updated_at = record.get("updated_at")
        stale = True
        if updated_at is not None:
            try:
                ts = datetime.fromisoformat(updated_at)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                stale = (datetime.now(UTC) - ts).total_seconds() > self._stale_after
            except (ValueError, TypeError):
                stale = True

        if not stale:
            return record

        return {
            **record,
            "status": "failed",
            "stale": True,
            "error": (
                f"scan stalled: no update for >{self._stale_after:.0f}s — worker likely died"
            ),
        }
