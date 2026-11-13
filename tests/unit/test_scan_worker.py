"""Tests for the durable async-scan worker + the relocated runner bodies.

The worker drains ``settings.scan_stream`` and executes each job via
``services.scan_runner.run_container_scan`` / ``run_dependency_scan``. These
tests use ``fakeredis.aioredis.FakeRedis`` and stub the scan services so no real
container / SAST work happens.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest

from config.settings import get_settings
from models.architecture_models import Vulnerability
from models.container_models import ContainerInfo, ContainerStatus
from models.package_manager_models import ExternalPackage
from models.security_api_models import ContainerSecurityScanRequest, SecurityScanResult
from services import scan_queue
from services.scan_queue import ScanJob
from services.scan_runner import (
    ResolvedRepo,
    _MaterializeResult,
    run_container_scan,
    run_dependency_scan,
)
from services.scan_task_store import AsyncScanTaskRecord, ScanTaskStore
from services.scan_worker import ScanWorker


@pytest.fixture
def fredis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


def _settings(**overrides):
    return get_settings().model_copy(update=overrides)


def _vuln(vuln_id="CVE-0000-0000", severity="HIGH", package_name="requests"):
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary="test",
        details="test",
        affected_versions=[],
        fixed_versions=[],
        references=[],
        published_date="2026-01-01",
        modified_date="2026-01-01",
        package_name=package_name,
    )


def _store(fredis, prefix="security_scan_task:"):
    return ScanTaskStore(
        key_prefix=prefix,
        ttl_seconds=3600,
        redis_getter=lambda: fredis,
        stale_after_seconds=600.0,
    )


def _container_info(name="c1", codebase_path="/tmp/codebase"):
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path=codebase_path,
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _scan_result(name="c1", degraded=False):
    return SecurityScanResult(
        container_name=name,
        scan_timestamp=datetime.now(UTC),
        scan_duration_seconds=1.0,
        total_files_scanned=3,
        total_vulnerabilities=2,
        overall_risk_score=42.0,
        security_grade="B",
        scan_degraded=degraded,
    )


# ===========================================================================
# Request serialisation round-trip (the wire contract to the worker)
# ===========================================================================


def test_scan_request_json_roundtrip_preserves_fields():
    req = ContainerSecurityScanRequest(
        container_name="c1",
        scan_type="quick",
        include_dependencies=False,
        severity_filter=["critical", "high"],
        include_low_confidence=False,
        max_files=50,
    )
    restored = ContainerSecurityScanRequest.model_validate_json(req.model_dump_json())
    assert restored.container_name == "c1"
    assert restored.scan_type == "quick"
    assert restored.include_dependencies is False
    assert restored.severity_filter == ["critical", "high"]
    assert restored.include_low_confidence is False
    assert restored.max_files == 50


# ===========================================================================
# Runner bodies (executed directly)
# ===========================================================================


class TestRunContainerScan:
    async def test_completed_record_written(self, fredis):
        settings = _settings()
        store = _store(fredis)
        job = ScanJob(
            msg_id="0-1",
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )

        mock_svc = MagicMock()
        mock_svc.scan_container = AsyncMock(return_value=_scan_result())
        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container_info(),
            ),
            patch("services.scan_runner.get_security_scan_service", return_value=mock_svc),
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            await run_container_scan(job, store, settings)

        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "completed"
        assert record["scan_degraded"] is False
        assert record["result"]["security_grade"] == "B"
        assert record["container_name"] == "c1"

    async def test_incomplete_fetch_reaches_the_assembler(self, fredis):
        """The coverage answer is known before the scan; hand it to the grades.

        Patching ``scan_degraded`` on the finished result leaves the grades
        computed as if coverage were complete — measured on the openplanner
        branch scan: security_grade D and base_image_grade A over 823 of ~990
        files with no Dockerfile in the set.
        """
        settings = _settings()
        store = _store(fredis)
        job = ScanJob(
            msg_id="0-1",
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )
        mock_svc = MagicMock()
        mock_svc.scan_container = AsyncMock(return_value=_scan_result())
        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container_info(),
            ),
            patch("services.scan_runner.get_security_scan_service", return_value=mock_svc),
            patch(
                "services.scan_runner._materialize_codebase",
                new_callable=AsyncMock,
                return_value=_MaterializeResult(temp_dir=None, incomplete=True),
            ),
        ):
            await run_container_scan(job, store, settings)

        assert mock_svc.scan_container.await_args.kwargs["force_degraded"] is True
        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["scan_degraded"] is True
        assert "codebase fetch was incomplete" in record["result"]["degraded_reasons"]

    async def test_heartbeat_running_written_before_completed(self, fredis):
        """running is stamped twice (initial + post-fetch heartbeat)."""
        settings = _settings()
        writes: list[dict] = []

        real_set = fredis.set

        async def _spy_set(k, v, ex=None):
            writes.append(json.loads(v))
            return await real_set(k, v, ex=ex)

        fredis.set = _spy_set
        store = _store(fredis)
        job = ScanJob(
            msg_id="0-1",
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )
        mock_svc = MagicMock()
        mock_svc.scan_container = AsyncMock(return_value=_scan_result())
        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container_info(),
            ),
            patch("services.scan_runner.get_security_scan_service", return_value=mock_svc),
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            await run_container_scan(job, store, settings)

        running = [w for w in writes if w.get("status") == "running"]
        assert len(running) >= 2
        assert all(w.get("updated_at") for w in writes)

    async def test_failure_writes_failed(self, fredis):
        settings = _settings()
        store = _store(fredis)
        job = ScanJob(
            msg_id="0-1",
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )
        with patch(
            "services.scan_runner.validate_and_get_container_for_tenant",
            new_callable=AsyncMock,
            side_effect=RuntimeError("validate boom"),
        ):
            await run_container_scan(job, store, settings)

        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "failed"
        assert "validate boom" in record["error"]

    async def test_incomplete_fetch_marks_degraded(self, fredis):
        """A partial codebase fetch forces scan_degraded even if the scan result was clean."""
        settings = _settings()
        store = _store(fredis)
        job = ScanJob(
            msg_id="0-1",
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )
        mock_svc = MagicMock()
        mock_svc.scan_container = AsyncMock(return_value=_scan_result(degraded=False))
        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container_info(),
            ),
            patch("services.scan_runner.get_security_scan_service", return_value=mock_svc),
            patch(
                "services.scan_runner._materialize_codebase",
                new_callable=AsyncMock,
                return_value=_MaterializeResult(temp_dir=None, incomplete=True),
            ),
        ):
            await run_container_scan(job, store, settings)

        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "completed"
        assert record["scan_degraded"] is True


class TestRunDependencyScan:
    async def test_completed_record_written(self, fredis):
        settings = _settings()
        store = _store(fredis, prefix="dependency_scan_task:")
        job = ScanJob(
            msg_id="0-1",
            task_id="dep-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="dependency",
            budget_seconds=30.0,
        )

        report = MagicMock()
        report.scan_degraded = False
        report.model_dump = MagicMock(return_value={"codebase_id": "c1"})
        fake_analyzer = MagicMock()
        fake_analyzer.analyze = AsyncMock(return_value=report)

        @asynccontextmanager
        async def _fake_resolve(container_name, tenant_id):
            yield ResolvedRepo(Path("/tmp/repo"), False)

        with (
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer",
                return_value=fake_analyzer,
            ),
            patch("services.scan_runner.resolve_repo_path", _fake_resolve),
        ):
            await run_dependency_scan(job, store, settings)

        record = json.loads(await fredis.get("dependency_scan_task:dep-1"))
        assert record["status"] == "completed"
        assert record["result"]["codebase_id"] == "c1"

    async def test_async_timeout_preserves_partial_findings(self, fredis):
        """A budget timeout surfaces the completed batches as a degraded
        ``completed`` record instead of discarding them to ``failed`` — parity
        with the container path's ``build_partial_result`` recovery."""
        settings = _settings()
        store = _store(fredis, prefix="dependency_scan_task:")
        job = ScanJob(
            msg_id="0-1",
            task_id="dep-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="dependency",
            budget_seconds=0.02,
        )

        async def _slow_analyze(_path, _name, *, partial):
            # A batch completes and deposits into the caller-held accumulator...
            partial.packages.append(
                ExternalPackage(name="requests", version="2.0.0", ecosystem="pypi")
            )
            partial.vulnerabilities.append(_vuln("CVE-2026-0001", "HIGH"))
            # ...then the scan overruns the budget and gets cancelled.
            await asyncio.sleep(1.0)

        def _build_partial_report(codebase_id, partial):
            # Faithful stand-in: a degraded report reflecting whatever the
            # accumulator captured before the timeout.
            report = MagicMock()
            report.scan_degraded = True
            report.model_dump = MagicMock(
                return_value={
                    "codebase_id": codebase_id,
                    "vulnerabilities": [v.id for v in partial.vulnerabilities],
                    "packages": [p.name for p in partial.packages],
                    "scan_degraded": True,
                }
            )
            return report

        fake_analyzer = MagicMock()
        fake_analyzer.analyze = _slow_analyze
        fake_analyzer.build_partial_report = _build_partial_report

        @asynccontextmanager
        async def _fake_resolve(container_name, tenant_id):
            yield ResolvedRepo(Path("/tmp/repo"), False)

        with (
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer",
                return_value=fake_analyzer,
            ),
            patch("services.scan_runner.resolve_repo_path", _fake_resolve),
        ):
            await run_dependency_scan(job, store, settings)

        record = json.loads(await fredis.get("dependency_scan_task:dep-1"))
        assert record["status"] == "completed"  # NOT "failed"
        assert record["scan_degraded"] is True
        # The completed batch's finding survived the timeout, not discarded.
        assert record["result"]["vulnerabilities"] == ["CVE-2026-0001"]
        assert record["result"]["packages"] == ["requests"]

    async def test_timeout_build_partial_failure_falls_back_to_failed(self, fredis):
        """If building/storing the degraded report itself fails after a timeout,
        the runner must record a terminal ``failed`` rather than let the
        exception escape (which would leave the job un-acked → reclaim storm)."""
        settings = _settings()
        store = _store(fredis, prefix="dependency_scan_task:")
        job = ScanJob(
            msg_id="0-1",
            task_id="dep-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="dependency",
            budget_seconds=0.02,
        )

        async def _slow_analyze(_path, _name, *, partial):
            await asyncio.sleep(1.0)

        def _boom(_codebase_id, _partial):
            raise ValueError("Codebase ID cannot be empty")

        fake_analyzer = MagicMock()
        fake_analyzer.analyze = _slow_analyze
        fake_analyzer.build_partial_report = _boom

        @asynccontextmanager
        async def _fake_resolve(container_name, tenant_id):
            yield ResolvedRepo(Path("/tmp/repo"), False)

        with (
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer",
                return_value=fake_analyzer,
            ),
            patch("services.scan_runner.resolve_repo_path", _fake_resolve),
        ):
            # Must NOT raise — the recovery branch is exception-safe.
            await run_dependency_scan(job, store, settings)

        record = json.loads(await fredis.get("dependency_scan_task:dep-1"))
        assert record["status"] == "failed"
        assert "budget" in record["error"]

    async def test_analyzer_degraded_flag_survives_a_complete_repo(self, fredis):
        """An OSV lookup failure flags the report inside analyze(); a complete repo
        fetch must not overwrite that back to False (coding-security#103)."""
        settings = _settings()
        store = _store(fredis, prefix="dependency_scan_task:")
        job = ScanJob(
            msg_id="0-1",
            task_id="dep-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="dependency",
            budget_seconds=30.0,
        )
        report = MagicMock()
        report.scan_degraded = True
        report.model_dump = MagicMock(return_value={"codebase_id": "c1"})
        fake_analyzer = MagicMock()
        fake_analyzer.analyze = AsyncMock(return_value=report)

        @asynccontextmanager
        async def _fake_resolve(container_name, tenant_id):
            yield ResolvedRepo(Path("/tmp/repo"), False)

        with (
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer",
                return_value=fake_analyzer,
            ),
            patch("services.scan_runner.resolve_repo_path", _fake_resolve),
        ):
            await run_dependency_scan(job, store, settings)

        record = json.loads(await fredis.get("dependency_scan_task:dep-1"))
        assert record["status"] == "completed"
        assert record["scan_degraded"] is True

    async def test_incomplete_repo_marks_degraded(self, fredis):
        """A partially-fetched manifest set marks the dependency report degraded."""
        settings = _settings()
        store = _store(fredis, prefix="dependency_scan_task:")
        job = ScanJob(
            msg_id="0-1",
            task_id="dep-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="dependency",
            budget_seconds=30.0,
        )
        report = MagicMock()
        report.scan_degraded = False
        report.model_dump = MagicMock(return_value={"codebase_id": "c1"})
        fake_analyzer = MagicMock()
        fake_analyzer.analyze = AsyncMock(return_value=report)

        @asynccontextmanager
        async def _fake_resolve(container_name, tenant_id):
            yield ResolvedRepo(Path("/tmp/repo"), True)  # incomplete=True

        with (
            patch(
                "services.dependency_analyzer.ArchitectureDependencyAnalyzer",
                return_value=fake_analyzer,
            ),
            patch("services.scan_runner.resolve_repo_path", _fake_resolve),
        ):
            await run_dependency_scan(job, store, settings)

        record = json.loads(await fredis.get("dependency_scan_task:dep-1"))
        assert record["status"] == "completed"
        assert record["scan_degraded"] is True


# ===========================================================================
# Worker: _process (ack semantics) + dead-letter + lifecycle
# ===========================================================================


class TestScanWorkerProcess:
    async def test_process_acks_after_terminal_write(self, fredis):
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
            scan_request=ContainerSecurityScanRequest(container_name="c1").model_dump_json(),
        )
        [job] = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)

        worker = ScanWorker(settings, lambda: fredis)
        mock_svc = MagicMock()
        mock_svc.scan_container = AsyncMock(return_value=_scan_result())
        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container_info(),
            ),
            patch("services.scan_runner.get_security_scan_service", return_value=mock_svc),
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            await worker._process(fredis, job)

        # Completed record persisted AND the message acked (PEL empty).
        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "completed"
        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 0

    async def test_process_leaves_job_unacked_on_cancel(self, fredis):
        """Shutdown cancellation must NOT ack — the job stays in the PEL so a
        later worker incarnation reclaims and re-runs it (the whole point of the
        durable queue vs the old in-process BackgroundTask that vanished)."""
        settings = _settings()
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
        )
        [job] = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)

        worker = ScanWorker(settings, lambda: fredis)

        async def _cancelled_run(_job, _store, _settings):
            raise asyncio.CancelledError

        with patch("services.scan_worker.run_container_scan", _cancelled_run):
            with pytest.raises(asyncio.CancelledError):
                await worker._process(fredis, job)

        # Un-acked → still pending in the PEL, reclaimable. NOT lost.
        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 1

    async def test_dead_letter_writes_failed_and_acks(self, fredis):
        settings = _settings(scan_max_deliveries=1)
        await scan_queue.ensure_consumer_group(fredis, settings)
        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
        )
        [job] = await scan_queue.read_batch(fredis, settings, "worker-0", count=10, block_ms=10)

        worker = ScanWorker(settings, lambda: fredis)
        await worker._dead_letter(fredis, job)

        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "failed"
        assert "dead-lettered" in record["error"]
        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 0


class TestScanWorkerLifecycle:
    async def test_start_creates_tasks_stop_clears(self, fredis):
        settings = _settings(scan_worker_concurrency=2, scan_reclaim_interval_seconds=100.0)
        worker = ScanWorker(settings, lambda: fredis)
        worker.start()
        # concurrency read loops + 1 reclaim loop
        assert len(worker._tasks) == 3
        await worker.stop()
        assert worker._tasks == []

    async def test_start_is_idempotent(self, fredis):
        settings = _settings(scan_worker_concurrency=1, scan_reclaim_interval_seconds=100.0)
        worker = ScanWorker(settings, lambda: fredis)
        worker.start()
        first = list(worker._tasks)
        worker.start()  # no-op while running
        assert worker._tasks == first
        await worker.stop()

    async def test_worker_drains_enqueued_job(self, fredis):
        """End-to-end: start the worker, enqueue a job, it lands completed."""
        settings = _settings(
            scan_worker_concurrency=1,
            scan_worker_block_ms=50,
            scan_reclaim_interval_seconds=100.0,
        )

        async def _stub_run(job, store, _settings):
            await store.store(
                AsyncScanTaskRecord(
                    task_id=job.task_id,
                    status="completed",
                    tenant_id=job.tenant_id,
                    result={"ok": True},
                    extra={"container_name": job.container_name},
                )
            )

        await scan_queue.enqueue(
            fredis,
            settings,
            task_id="task-1",
            tenant_id="tenant-a",
            container_name="c1",
            kind="container",
            budget_seconds=30.0,
        )

        worker = ScanWorker(settings, lambda: fredis)
        with patch("services.scan_worker.run_container_scan", _stub_run):
            worker.start()
            try:
                for _ in range(200):
                    raw = await fredis.get("security_scan_task:task-1")
                    if raw and json.loads(raw).get("status") == "completed":
                        break
                    await asyncio.sleep(0.02)
            finally:
                await worker.stop()

        record = json.loads(await fredis.get("security_scan_task:task-1"))
        assert record["status"] == "completed"
        pending = await fredis.xpending(settings.scan_stream, settings.scan_consumer_group)
        assert pending["pending"] == 0
