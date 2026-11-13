"""Tests for the durable scan queue (Redis Streams consumer group).

Uses ``fakeredis.aioredis.FakeRedis(decode_responses=True)`` — the same fake the
in-fleet billing consumer is tested against. The reclaim path is proven with
``xautoclaim`` (which fakeredis models) plus the per-message delivery counter.
"""

import fakeredis.aioredis
import pytest

from config.settings import get_settings
from services import scan_queue
from services.scan_queue import ScanJob


@pytest.fixture
def fredis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _settings(**overrides):
    return get_settings().model_copy(update=overrides)


class TestEnsureConsumerGroup:
    async def test_creates_group(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        groups = await fredis.xinfo_groups(settings.scan_stream)
        assert len(groups) == 1
        assert groups[0]["name"] == settings.scan_consumer_group

    async def test_idempotent(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        # Second call must not raise (BUSYGROUP swallowed).
        await scan_queue.ensure_consumer_group(fredis, settings)
        groups = await fredis.xinfo_groups(settings.scan_stream)
        assert len(groups) == 1

    async def test_propagates_non_busygroup_error(self, fredis):
        import redis.asyncio as aioredis

        settings = _settings()

        async def _raise_other(*_a, **_k):
            raise aioredis.ResponseError("WRONGTYPE not a busygroup")

        fredis.xgroup_create = _raise_other
        with pytest.raises(aioredis.ResponseError, match="WRONGTYPE"):
            await scan_queue.ensure_consumer_group(fredis, settings)


class TestEnqueueAndRead:
    async def test_enqueue_appends_and_roundtrips(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)

        msg_id = await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="cont-1",
            kind="container",
            budget_seconds=120.0,
            scan_request='{"scan_type": "full"}',
            correlation_id="corr-9",
        )
        assert isinstance(msg_id, str)
        assert await fredis.xlen(settings.scan_stream) == 1

        jobs = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)
        assert len(jobs) == 1
        job = jobs[0]
        assert isinstance(job, ScanJob)
        assert job.task_id == "task-1"
        assert job.tenant_id == "tenant-a"
        assert job.container_name == "cont-1"
        assert job.kind == "container"
        assert job.budget_seconds == 120.0
        assert job.scan_request == '{"scan_type": "full"}'
        assert job.correlation_id == "corr-9"
        assert job.msg_id == msg_id

    async def test_read_batch_empty_returns_empty_list(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        jobs = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)
        assert jobs == []

    async def test_enqueue_bounds_stream_with_maxlen(self, fredis):
        """enqueue passes the configured MAXLEN cap so the stream can't grow
        unbounded under the redis `volatile-lru`/`noeviction`-adjacent policy."""
        settings = _settings(scan_stream_maxlen=7)
        captured: dict = {}
        real_xadd = fredis.xadd

        async def _spy_xadd(name, fields, **kwargs):
            captured.update(kwargs)
            return await real_xadd(name, fields, **kwargs)

        fredis.xadd = _spy_xadd
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="cont-1",
            kind="container",
            budget_seconds=30.0,
        )
        assert captured.get("maxlen") == 7
        assert captured.get("approximate") is True

    async def test_read_batch_splits_across_consumers(self, fredis):
        """Two consumers in one group split the stream — no double delivery."""
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        for i in range(4):
            await scan_queue.enqueue(
                fredis,
                settings,
                task_id=f"t{i}",
                tenant_id="tenant-a",
                container_name="c",
                kind="dependency",
                budget_seconds=60.0,
            )
        a = await scan_queue.read_batch(fredis, settings, "worker-a", count=10, block_ms=10)
        b = await scan_queue.read_batch(fredis, settings, "worker-b", count=10, block_ms=10)
        assert len(a) + len(b) == 4
        ids = {j.task_id for j in a} | {j.task_id for j in b}
        assert ids == {"t0", "t1", "t2", "t3"}

    async def test_ack_clears_pending_and_counter(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="t",
            tenant_id="tenant-a",
            container_name="c",
            kind="container",
            budget_seconds=60.0,
        )
        [job] = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)
        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 1

        # Seed a delivery counter, then prove ack drops it.
        await fredis.set(f"security:scan:deliveries:{job.msg_id}", "2")
        await scan_queue.ack(fredis, settings, job.msg_id)

        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 0
        assert await fredis.get(f"security:scan:deliveries:{job.msg_id}") is None


class TestReclaimPending:
    async def test_reclaims_stranded_entry_as_reprocess(self, fredis):
        """An entry read but never acked (crashed worker) is reclaimed for reprocess."""
        settings = _settings(scan_reclaim_min_idle_seconds=0, scan_max_deliveries=3)
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="t",
            tenant_id="tenant-a",
            container_name="c",
            kind="container",
            budget_seconds=60.0,
        )
        # Simulate a crash: read it (now in PEL) but never ack.
        await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)

        reprocess, poison = await scan_queue.reclaim_pending(
            fredis, settings, "worker-0", max_deliveries=settings.scan_max_deliveries
        )
        assert len(reprocess) == 1
        assert poison == []
        assert reprocess[0].task_id == "t"

    async def test_poisons_after_max_deliveries(self, fredis):
        """With ``scan_max_deliveries=1`` the initial read is the one-and-only
        allowed attempt, so the very next reclaim dead-letters (no reprocess)."""
        settings = _settings(scan_reclaim_min_idle_seconds=0, scan_max_deliveries=1)
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="t",
            tenant_id="tenant-a",
            container_name="c",
            kind="container",
            budget_seconds=60.0,
        )
        # Initial delivery via read_batch counts as attempt 1 (== max_deliveries).
        await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)

        # Next reclaim → counter=2 > 1 → poison immediately, no reprocess.
        reprocess, poison = await scan_queue.reclaim_pending(
            fredis, settings, "worker-0", max_deliveries=1
        )
        assert reprocess == [] and len(poison) == 1
        assert poison[0].task_id == "t"

    async def test_poison_deadletters_after_exactly_max_deliveries(self, fredis):
        """A poison job must be dead-lettered after EXACTLY ``scan_max_deliveries``
        full scan attempts, not ``scan_max_deliveries`` + 1.

        The initial ``read_batch`` delivery is a real scan attempt; each
        subsequent reclaim that returns the job as ``reprocess`` is another. The
        job is dead-lettered when a reclaim returns it as ``poison`` (no scan
        run at that point). This counts the total and asserts it equals the cap.
        """
        max_deliveries = 3
        settings = _settings(scan_reclaim_min_idle_seconds=0, scan_max_deliveries=max_deliveries)
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="t",
            tenant_id="tenant-a",
            container_name="c",
            kind="container",
            budget_seconds=60.0,
        )

        # Initial delivery = attempt 1.
        jobs = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)
        assert len(jobs) == 1
        attempts = 1

        for _ in range(20):  # bounded — a correct impl poisons well before this
            reprocess, poison = await scan_queue.reclaim_pending(
                fredis, settings, "worker-0", max_deliveries=max_deliveries
            )
            if poison:
                assert reprocess == []
                assert poison[0].task_id == "t"
                break
            attempts += len(reprocess)
        else:
            pytest.fail("job was never dead-lettered")

        assert attempts == max_deliveries, (
            f"poison job ran {attempts} scans, expected exactly {max_deliveries}"
        )

    async def test_reclaim_noop_when_pel_empty(self, fredis):
        settings = _settings(scan_reclaim_min_idle_seconds=0)
        await scan_queue.ensure_consumer_group(fredis, settings)
        reprocess, poison = await scan_queue.reclaim_pending(
            fredis, settings, "worker-0", max_deliveries=3
        )
        assert reprocess == [] and poison == []
