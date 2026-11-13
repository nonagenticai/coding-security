"""Durable async-scan worker — a Redis Streams consumer-group drain loop.

Replaces the in-process FastAPI ``BackgroundTasks`` execution of async scans.
The submit endpoints now only enqueue a job onto ``settings.scan_stream``; this
worker, started in the app lifespan, runs ``scan_worker_concurrency`` read loops
plus one reclaim loop and executes each job via the relocated runner bodies in
``services.scan_runner``.

Durability + bounded concurrency (the two properties BackgroundTasks lacked):

* A job survives a worker crash — it stays in the consumer-group
  pending-entries-list and is reclaimed by the reclaim loop (``xautoclaim``),
  instead of vanishing with the process.
* Concurrency is bounded by the number of read loops — BackgroundTasks spawned
  one coroutine per request with no ceiling.

XACK happens ONLY after a terminal ``ScanTaskStore`` write (the runner owns the
``completed`` / ``failed`` write). A shutdown ``CancelledError`` propagates
un-acked so the in-flight job is reclaimed and re-run. A job delivered more than
``scan_max_deliveries`` times is dead-lettered (``failed`` record + XACK).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Callable

import redis.asyncio as aioredis

from config.settings import Settings
from services import scan_queue
from services.scan_queue import ScanJob
from services.scan_runner import run_container_scan, run_dependency_scan
from services.scan_task_store import AsyncScanTaskRecord, ScanTaskStore

logger = logging.getLogger(__name__)


class ScanWorker:
    """Owns the read loops + a reclaim loop draining ``settings.scan_stream``."""

    def __init__(self, settings: Settings, redis_getter: Callable[[], aioredis.Redis]) -> None:
        self._settings = settings
        self._redis_getter = redis_getter
        # Per-pod-unique consumer name: Kubernetes sets HOSTNAME to the pod name,
        # so each replica is a distinct consumer in the shared group (the stream
        # is split between replicas; no double-read). Falls back to the configured
        # name for local / unit runs where HOSTNAME is unset.
        self._consumer = os.environ.get("HOSTNAME") or settings.scan_consumer_name
        self._tasks: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()

    # ── lifecycle ─────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._tasks:
            return
        self._stop.clear()
        for i in range(max(1, self._settings.scan_worker_concurrency)):
            self._tasks.append(asyncio.create_task(self._read_loop(i), name=f"scan-worker-{i}"))
        self._tasks.append(asyncio.create_task(self._reclaim_loop(), name="scan-worker-reclaim"))
        logger.info(
            "scan worker started: %d read loop(s) + reclaim, consumer=%s",
            self._settings.scan_worker_concurrency,
            self._consumer,
        )

    async def stop(self) -> None:
        self._stop.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        logger.info("scan worker stopped")

    # ── loops ─────────────────────────────────────────────────────────────
    async def _read_loop(self, idx: int) -> None:
        redis = self._redis_getter()
        group_ready = False
        while not self._stop.is_set():
            try:
                if not group_ready:
                    await scan_queue.ensure_consumer_group(redis, self._settings)
                    group_ready = True
                jobs = await scan_queue.read_batch(
                    redis,
                    self._settings,
                    self._consumer,
                    count=1,
                    block_ms=self._settings.scan_worker_block_ms,
                )
                if not jobs:
                    # Some clients (fakeredis) return instantly even with a
                    # block; yield so this loop never spins a CPU core.
                    await asyncio.sleep(0)
                    continue
                for job in jobs:
                    await self._process(redis, job)
            except asyncio.CancelledError:
                break
            except aioredis.ResponseError as exc:
                if "NOGROUP" in str(exc):
                    logger.warning("scan consumer group lost; recreating", exc_info=True)
                    group_ready = False
                else:
                    logger.warning("scan worker read error", exc_info=True)
                await self._sleep(1)
            except aioredis.RedisError:
                logger.warning("scan worker redis error", exc_info=True)
                await self._sleep(1)

    async def _reclaim_loop(self) -> None:
        redis = self._redis_getter()
        while not self._stop.is_set():
            await self._sleep(self._settings.scan_reclaim_interval_seconds)
            if self._stop.is_set():
                break
            try:
                reprocess, poison = await scan_queue.reclaim_pending(
                    redis,
                    self._settings,
                    self._consumer,
                    max_deliveries=self._settings.scan_max_deliveries,
                )
                for job in poison:
                    await self._dead_letter(redis, job)
                for job in reprocess:
                    await self._process(redis, job)
            except asyncio.CancelledError:
                break
            except aioredis.RedisError:
                logger.warning("scan worker reclaim error", exc_info=True)

    # ── per-job ───────────────────────────────────────────────────────────
    def _store_for(self, job: ScanJob) -> ScanTaskStore:
        prefix = "dependency_scan_task:" if job.kind == "dependency" else "security_scan_task:"
        return ScanTaskStore(
            key_prefix=prefix,
            ttl_seconds=self._settings.security_scan_task_ttl_seconds,
            redis_getter=self._redis_getter,
            stale_after_seconds=self._settings.security_scan_stale_after_seconds,
        )

    async def _process(self, redis: aioredis.Redis, job: ScanJob) -> None:
        """Run one job to a terminal store write, then XACK.

        The runner owns the ``running`` / ``completed`` / ``failed`` store
        writes. On shutdown (``CancelledError``) we re-raise WITHOUT acking so
        the job stays in the PEL and is reclaimed. On any other unexpected
        escape we log and leave it un-acked (reclaim will re-run / poison it).
        """
        store = self._store_for(job)
        try:
            if job.kind == "dependency":
                await run_dependency_scan(job, store, self._settings)
            else:
                await run_container_scan(job, store, self._settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "scan job %s crashed unexpectedly; left un-acked for reclaim", job.msg_id
            )
            return
        await scan_queue.ack(redis, self._settings, job.msg_id)

    async def _dead_letter(self, redis: aioredis.Redis, job: ScanJob) -> None:
        """Persist a ``failed`` record for a poison job, then XACK it."""
        store = self._store_for(job)
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="failed",
                tenant_id=job.tenant_id,
                error=(
                    f"scan job dead-lettered after {self._settings.scan_max_deliveries} "
                    "delivery attempts (worker kept failing to complete it)"
                ),
                extra={"container_name": job.container_name},
            )
        )
        await scan_queue.ack(redis, self._settings, job.msg_id)

    async def _sleep(self, seconds: float) -> None:
        """Sleep up to ``seconds``, waking early if stop is requested."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
