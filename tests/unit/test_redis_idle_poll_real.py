"""#117: the scan worker's idle XREADGROUP poll must not time out the socket.

Runs against a REAL redis (fakeredis returns a blocking read instantly, so it
cannot see this): CI's ``has_redis`` sidecar via REDIS_HOST/REDIS_PORT, else an
ephemeral ``redis:7-alpine`` container started here. No docker => fail.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator

import pytest

from app_factory import build_redis
from config.settings import get_settings
from services import scan_queue


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    if os.environ.get("REDIS_HOST") and os.environ.get("REDIS_PORT"):
        yield f"redis://{os.environ['REDIS_HOST']}:{os.environ['REDIS_PORT']}/0"
        return
    cid = subprocess.run(
        ["docker", "run", "--rm", "-d", "-p", "127.0.0.1::6379", "redis:7-alpine"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        port = (
            subprocess.run(
                ["docker", "port", cid, "6379/tcp"], check=True, capture_output=True, text=True
            )
            .stdout.split(":")[-1]
            .strip()
        )
        url = f"redis://127.0.0.1:{port}/0"
        for _ in range(50):
            ok = subprocess.run(["docker", "exec", cid, "redis-cli", "ping"], capture_output=True)
            if ok.returncode == 0:
                break
            time.sleep(0.1)
        yield url
    finally:
        subprocess.run(["docker", "stop", cid], capture_output=True)


async def test_idle_blocking_read_returns_empty_not_timeout(redis_url):
    """Two idle polls with the production block time and the production client."""
    settings = get_settings().model_copy(
        update={"redis_url": redis_url, "scan_stream": f"t117:{time.time_ns()}"}
    )
    redis = build_redis(settings)
    try:
        await scan_queue.ensure_consumer_group(redis, settings)
        for _ in range(2):
            t0 = time.monotonic()
            jobs = await scan_queue.read_batch(
                redis, settings, "c1", count=1, block_ms=settings.scan_worker_block_ms
            )
            assert jobs == []
            # Control: the server really blocked (this is a real redis, not a fake).
            assert time.monotonic() - t0 >= settings.scan_worker_block_ms / 1000 - 0.1
        await redis.delete(settings.scan_stream)
    finally:
        await redis.aclose()
