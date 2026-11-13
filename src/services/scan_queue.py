"""Redis Streams queue for durable async scans.

A single stream (``settings.scan_stream``) carries both container-security and
dependency scan jobs, distinguished by the ``kind`` field. A single consumer
group (``settings.scan_consumer_group``) is drained by the in-lifespan
``ScanWorker``; the consumer-group pending-entries-list (PEL) makes an
in-flight job durable across a worker crash — it is reclaimed via
``reclaim_pending`` instead of being silently lost the way an in-process
FastAPI ``BackgroundTask`` was.

The reclaim path uses ``xautoclaim`` (proven under fakeredis) rather than
``xpending_range`` / ``xclaim`` (which fakeredis does not faithfully model), and
tracks a message's delivery count with a plain Redis ``INCR`` counter so a job
that keeps failing is dead-lettered after ``settings.scan_max_deliveries``
attempts instead of looping forever.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import redis.asyncio as aioredis

if TYPE_CHECKING:
    from config.settings import Settings

logger = logging.getLogger(__name__)

# Redis key prefix for the per-message delivery counter used by the reclaim
# poison-detection path. Namespaced under the stream so two services sharing a
# Redis never collide.
_DELIVERIES_KEY_PREFIX = "security:scan:deliveries:"


@dataclass(slots=True)
class ScanJob:
    """One decoded scan job read off the stream.

    ``msg_id`` is the Redis stream entry id (the XACK / delivery-counter key);
    ``kind`` is ``"container"`` or ``"dependency"``. ``scan_request`` carries the
    container-scan request as a JSON string (empty for dependency jobs).
    """

    msg_id: str
    task_id: str
    tenant_id: str
    container_name: str
    kind: str
    budget_seconds: float
    scan_request: str = ""
    correlation_id: str = ""


def _deliveries_key(msg_id: str) -> str:
    return f"{_DELIVERIES_KEY_PREFIX}{msg_id}"


def _job_from_fields(msg_id: str, fields: dict[str, str]) -> ScanJob:
    """Build a ScanJob from a decoded stream entry's flat str→str fields."""
    try:
        budget = float(fields.get("budget_seconds", "0") or "0")
    except (TypeError, ValueError):
        budget = 0.0
    return ScanJob(
        msg_id=msg_id,
        task_id=fields.get("task_id", ""),
        tenant_id=fields.get("tenant_id", ""),
        container_name=fields.get("container_name", ""),
        kind=fields.get("kind", ""),
        budget_seconds=budget,
        scan_request=fields.get("scan_request", ""),
        correlation_id=fields.get("correlation_id", ""),
    )


async def ensure_consumer_group(redis: aioredis.Redis, settings: Settings) -> None:
    """Create the scan consumer group (id=0, mkstream) if it does not exist.

    ``id="0"`` starts the group at the very first stream entry, so jobs enqueued
    before the group existed are still delivered. BUSYGROUP (already created) is
    swallowed; any other ResponseError propagates.
    """
    try:
        await redis.xgroup_create(
            settings.scan_stream,
            settings.scan_consumer_group,
            id="0",
            mkstream=True,
        )
        logger.info("scan_consumer_group_created", extra={"stream": settings.scan_stream})
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            return
        raise


async def enqueue(
    redis: aioredis.Redis,
    settings: Settings,
    *,
    task_id: str,
    tenant_id: str,
    container_name: str,
    kind: str,
    budget_seconds: float,
    scan_request: str = "",
    correlation_id: str = "",
) -> str:
    """Append a scan job to the stream. Returns the new entry's msg_id.

    Fields are flat str→str (Redis stream requirement); ``maxlen`` bounds the
    stream so an operator-set retention keeps it from growing unbounded.
    """
    # ``dict`` is invariant in its params, so a ``dict[str, str]`` literal does
    # not satisfy xadd's ``Dict[FieldT, EncodableT]`` param — cast to the broad
    # field type (the runtime values ARE plain str, as Redis requires).
    fields: dict[Any, Any] = {
        "task_id": task_id,
        "tenant_id": tenant_id,
        "container_name": container_name,
        "kind": kind,
        "budget_seconds": str(budget_seconds),
        "scan_request": scan_request,
        "correlation_id": correlation_id,
    }
    msg_id = await redis.xadd(
        settings.scan_stream,
        fields,
        maxlen=settings.scan_stream_maxlen,
        approximate=True,
    )
    return msg_id if isinstance(msg_id, str) else msg_id.decode()


async def read_batch(
    redis: aioredis.Redis,
    settings: Settings,
    consumer: str,
    *,
    count: int,
    block_ms: int,
) -> list[ScanJob]:
    """XREADGROUP a batch of never-delivered jobs (``>``) for this consumer."""
    results = cast(
        "list[tuple[str, list[tuple[str, dict[str, str]]]]] | None",
        await redis.xreadgroup(
            groupname=settings.scan_consumer_group,
            consumername=consumer,
            streams={settings.scan_stream: ">"},
            count=count,
            block=block_ms,
        ),
    )
    if not results:
        return []
    ttl_seconds = max(settings.security_scan_task_ttl_seconds, 1)
    jobs: list[ScanJob] = []
    for _stream_name, entries in results:
        for msg_id, fields in entries:
            # Count THIS first (never-before-delivered) delivery. reclaim_pending
            # only INCRs on reclaims, so without this the initial delivery is
            # uncounted and a poison job runs ``scan_max_deliveries`` + 1 full
            # scans before being dead-lettered. Counting it here makes total
            # attempts == ``scan_max_deliveries``.
            await redis.incrby(_deliveries_key(msg_id), 1)
            await redis.expire(_deliveries_key(msg_id), ttl_seconds)
            jobs.append(_job_from_fields(msg_id, fields))
    return jobs


async def ack(redis: aioredis.Redis, settings: Settings, msg_id: str) -> None:
    """XACK a message and best-effort drop its delivery counter (terminal)."""
    await redis.xack(settings.scan_stream, settings.scan_consumer_group, msg_id)
    try:
        await redis.delete(_deliveries_key(msg_id))
    except aioredis.RedisError:
        logger.warning("failed to drop delivery counter for %s", msg_id, exc_info=True)


async def reclaim_pending(
    redis: aioredis.Redis,
    settings: Settings,
    consumer: str,
    *,
    max_deliveries: int,
) -> tuple[list[ScanJob], list[ScanJob]]:
    """Reclaim PEL entries idle longer than the reclaim min-idle window.

    Returns ``(reprocess, poison)``: jobs to re-run vs. jobs that have been
    delivered more than ``max_deliveries`` times (dead-letter candidates). A
    per-message ``INCR`` counter (TTL-bounded) tracks delivery attempts because
    fakeredis does not model ``xpending``'s ``times_delivered`` faithfully;
    ``xautoclaim`` IS proven under fakeredis, so it is the reclaim primitive.

    The cursor loop terminates on the real-Redis ``"0-0"`` sentinel and also
    breaks when a batch yields no entries not already seen this pass — both
    bounding the loop on real Redis and tolerating fakeredis's non-converging
    cursor. A hard iteration cap is the final backstop.
    """
    min_idle_ms = settings.scan_reclaim_min_idle_seconds * 1000
    ttl_seconds = max(settings.security_scan_task_ttl_seconds, 1)
    reprocess: list[ScanJob] = []
    poison: list[ScanJob] = []
    cursor: str = "0-0"
    seen: set[str] = set()
    for _ in range(10_000):  # backstop against a pathological cursor
        reply = await redis.xautoclaim(
            settings.scan_stream,
            settings.scan_consumer_group,
            consumer,
            min_idle_ms,
            start_id=cursor,
            count=100,
        )
        # redis-py >= 5 returns (next_cursor, claimed, deleted); older builds
        # return (next_cursor, claimed). Normalize.
        next_cursor = reply[0]
        claimed = cast("list[tuple[str, dict[str, str] | None]]", reply[1])
        new_entries = [(mid, f) for (mid, f) in claimed if mid not in seen]
        for msg_id, fields in new_entries:
            seen.add(msg_id)
            # A claimed id whose entry was deleted from the stream comes back
            # with None fields (auto-evicted from the PEL by Redis) — nothing to
            # reprocess.
            if not fields:
                continue
            deliveries = await redis.incrby(_deliveries_key(msg_id), 1)
            await redis.expire(_deliveries_key(msg_id), ttl_seconds)
            job = _job_from_fields(msg_id, fields)
            if deliveries > max_deliveries:
                poison.append(job)
            else:
                reprocess.append(job)
        if next_cursor in ("0-0", "0", b"0-0", b"0"):
            break
        if not new_entries:
            break
        cursor = next_cursor if isinstance(next_cursor, str) else next_cursor.decode()
    if reprocess or poison:
        logger.info("scan_pel_reclaimed reprocess=%d poison=%d", len(reprocess), len(poison))
    return reprocess, poison
