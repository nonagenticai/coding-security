"""Tests for the async (task_id + poll) dependency-scan HTTP contract.

Covers POST /api/dependencies/{name}/scan/async + GET /api/dependencies/scan/results/{task_id}.

The scan is now executed by the durable Redis-Streams worker
(``services.scan_worker``), NOT an in-request BackgroundTask. So the submit
endpoint's job is: write a ``queued`` record synchronously and enqueue a durable
job. These tests assert that HTTP contract (queued + task_id, 503 when the store
is offline, tenant-scoped poll). The actual scan execution (running → completed /
failed) is covered against the worker/runner in ``test_scan_worker.py``.

Redis is unreachable in unit tests, so ``get_redis()`` is patched with an
in-memory async fake that records both the status-record SET and the stream
XADD.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

from models.container_models import ContainerInfo, ContainerStatus


class _FakeRedis:
    """In-memory async stand-in for the redis.asyncio client.

    Records the status-record ``set`` (poll store) and the ``xadd`` (durable
    enqueue) so a test can prove the submit endpoint both persisted ``queued``
    and enqueued a job — without a real Redis.
    """

    def __init__(self):
        self.store: dict[str, str] = {}
        self.jobs: list[tuple[str, dict]] = []
        self._seq = 0

    async def set(self, k, v, ex=None):
        self.store[k] = v

    async def get(self, k):
        return self.store.get(k)

    async def xadd(self, stream, fields, maxlen=None, approximate=None):
        self._seq += 1
        msg_id = f"0-{self._seq}"
        self.jobs.append((msg_id, dict(fields)))
        return msg_id


class _RaisingSetRedis(_FakeRedis):
    """FakeRedis whose ``set`` raises ConnectionError — models a store offline
    on the write path (get_redis() succeeds, but the SET fails)."""

    async def set(self, k, v, ex=None):
        raise ConnectionError("redis down")


def _make_container_info(name="test-container"):
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path="/tmp/test-codebase",
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


class TestAsyncDependencyScanSubmit:
    def test_async_submit_returns_task_id_and_enqueues(self, test_client, tenant_headers):
        """POST /{name}/scan/async returns 200 + queued and enqueues a durable job."""
        fake = _FakeRedis()
        with (
            patch(
                "routers.dependencies.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_make_container_info(),
            ),
            patch("routers.dependencies.get_redis", return_value=fake),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan/async",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert data["container_name"] == "test-container"
        assert data.get("task_id")

        # queued record persisted for an immediate poll ...
        assert any(k.startswith("dependency_scan_task:") for k in fake.store)
        # ... and exactly one durable job enqueued with the right shape.
        assert len(fake.jobs) == 1
        _msg_id, fields = fake.jobs[0]
        assert fields["kind"] == "dependency"
        assert fields["container_name"] == "test-container"
        assert fields["task_id"] == data["task_id"]
        assert fields["tenant_id"] == "test-tenant"
        assert float(fields["budget_seconds"]) > 0
        assert fields["scan_request"] == ""

    def test_async_submit_redis_down_returns_503(self, test_client, tenant_headers):
        """Redis offline (get_redis raises RuntimeError) -> 503, nothing enqueued."""
        with (
            patch(
                "routers.dependencies.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_make_container_info(),
            ),
            patch(
                "routers.dependencies.get_redis",
                side_effect=RuntimeError("Redis not initialised"),
            ),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan/async",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 503

    def test_async_submit_store_fails_returns_503(self, test_client, tenant_headers):
        """get_redis() succeeds but the queued SET raises -> 503, no job enqueued."""
        fake = _RaisingSetRedis()
        with (
            patch(
                "routers.dependencies.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_make_container_info(),
            ),
            patch("routers.dependencies.get_redis", return_value=fake),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan/async",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 503
        assert fake.jobs == []  # required queued write failed before enqueue


class TestAsyncDependencyScanPoll:
    def test_async_poll_pending_for_unknown_task(self, test_client, tenant_headers):
        """Polling a random/unknown task_id returns status pending."""
        fake = _FakeRedis()
        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{uuid.uuid4()}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        assert response.json()["status"] == "pending"

    def test_async_poll_queued_stays_queued(self, test_client, tenant_headers):
        """A queued record with an OLD updated_at must NOT flip to failed: the job
        is durable in the stream (reclaim-guaranteed) until a worker starts it."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"dependency_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "queued",
                "updated_at": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            }
        )

        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert "stale" not in data

    def test_async_poll_cross_tenant_returns_404(self, test_client, tenant_headers):
        """A record owned by another tenant must not be readable -> 404."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"dependency_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "other-tenant",
                "status": "completed",
                "scan_degraded": False,
                "result": {},
            }
        )

        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 404

    def test_async_poll_corrupt_record_returns_pending(self, test_client, tenant_headers):
        """A corrupt (non-JSON) stored record is treated as pending, not a 500."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"dependency_scan_task:{task_id}"] = "{ not json"

        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        assert response.json()["status"] == "pending"

    def test_async_poll_stale_running_returns_failed(self, test_client, tenant_headers):
        """A running record with a far-past updated_at -> failed+stale."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"dependency_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "running",
                "updated_at": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            }
        )

        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data["stale"] is True

    def test_async_poll_fresh_running_stays_running(self, test_client, tenant_headers):
        """A running record with a fresh updated_at is NOT stale -> stays running."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"dependency_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "running",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )

        with patch("routers.dependencies.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/dependencies/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "stale" not in data
