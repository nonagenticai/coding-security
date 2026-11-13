"""Prove the SAST detector singleton is built off the event loop.

``get_security_detector()`` lazily constructs a module-global
``SecurityVulnerabilityDetector`` whose ``__init__`` builds ``BanditScanner`` and
``SecretsScanner`` — each of which runs blocking ``subprocess.run([tool,
"--version"], timeout=5)`` probes in its own ``__init__``. Done on a running
event loop, the FIRST caller would block the whole worker (up to ~20s if a tool
binary is wedged), stalling every concurrent request.

``get_security_detector_async()`` therefore builds via ``asyncio.to_thread(...)``
so the blocking probes run off-loop, and the FastAPI lifespan eager-warms the
singleton off-thread before serving traffic (so the sync ``__init__`` callers
that can't await hit a cached instance).
"""

import asyncio
import inspect
import time
from unittest.mock import patch

import pytest

import services.security_detector as sd
from services.security_detector import (
    SecurityVulnerabilityDetector,
    get_security_detector_async,
)


@pytest.fixture(autouse=True)
def _isolate_singleton():
    """Give every test a cold singleton + fresh lock, and restore afterwards.

    These tests build the singleton with a STUBBED ``__init__`` (no patterns /
    scanners), so a leaked global would poison every other test in the same
    worker that resolves the detector. Reset to ``None`` before and after so the
    next real caller rebuilds a proper instance lazily.
    """
    saved = sd._security_detector
    sd._security_detector = None
    sd._security_detector_lock = asyncio.Lock()
    try:
        yield
    finally:
        sd._security_detector = None
        sd._security_detector_lock = asyncio.Lock()
        # `saved` was almost certainly None (module import time); don't restore a
        # potentially half-built instance — force a clean lazy rebuild instead.
        _ = saved


# How long the stubbed synchronous build blocks its calling thread.
_BUILD_SLEEP = 0.3
# The background ticker re-schedules on this cadence.
_TICK_INTERVAL = 0.005


class _Ticker:
    """Counts how many times the event loop got to schedule us in a window."""

    def __init__(self) -> None:
        self.ticks = 0
        self._run = True

    async def run(self) -> None:
        while self._run:
            self.ticks += 1
            await asyncio.sleep(_TICK_INTERVAL)

    def stop(self) -> None:
        self._run = False


def _slow_init_patch(counter: list[int]):
    """Patch ``SecurityVulnerabilityDetector.__init__`` with a slow, sync stub.

    Mimics the real build's blocking version-probes with a plain
    ``time.sleep`` and records how many times it ran (to assert single-build).
    """

    def _slow_init(self) -> None:
        counter.append(1)
        time.sleep(_BUILD_SLEEP)

    return patch.object(SecurityVulnerabilityDetector, "__init__", _slow_init)


async def test_async_accessor_keeps_loop_responsive():
    """The blocking build runs off-thread, so the loop keeps advancing."""
    counter: list[int] = []

    ticker = _Ticker()
    task = asyncio.create_task(ticker.run())
    await asyncio.sleep(0)  # let the ticker start
    ticker.ticks = 0

    with _slow_init_patch(counter):
        detector = await get_security_detector_async()

    ticker.stop()
    await task

    assert isinstance(detector, SecurityVulnerabilityDetector)
    assert counter == [1]  # built exactly once
    # A ~0.3s build off-thread with a 5ms ticker → many ticks. If the build had
    # run ON the loop, the ticker would have been frozen (~0 ticks).
    assert ticker.ticks >= 10, f"loop was starved during build (ticks={ticker.ticks})"


async def test_async_accessor_builds_once_under_concurrency():
    """N concurrent callers trigger exactly one build (double-checked lock)."""
    counter: list[int] = []

    with _slow_init_patch(counter):
        results = await asyncio.gather(*(get_security_detector_async() for _ in range(8)))

    assert len(counter) == 1, f"constructor ran {len(counter)} times, expected 1"
    # All callers get the same cached instance.
    assert all(r is results[0] for r in results)


async def test_async_accessor_fast_path_skips_lock():
    """Once warmed, the accessor returns the cached instance without building."""
    counter: list[int] = []

    with _slow_init_patch(counter):
        first = await get_security_detector_async()
        second = await get_security_detector_async()

    assert first is second
    assert len(counter) == 1  # second call did not rebuild


def test_async_accessor_source_uses_to_thread():
    """Regression guard: the async accessor must offload the build off-thread."""
    src = inspect.getsource(get_security_detector_async)
    assert "asyncio.to_thread(SecurityVulnerabilityDetector)" in src, (
        "async accessor must build the singleton via asyncio.to_thread"
    )


def test_startup_lifespan_warms_detector_off_thread():
    """Regression guard: the FastAPI lifespan must pre-warm the detector.

    Warming at startup (before serving traffic) is what covers the SYNC
    ``__init__`` callers — ``SecurityScanService`` / ``UnifiedSecurityScanner``
    call ``get_security_detector()`` inside a sync ``__init__`` and cannot
    await, so they must find an already-cached instance.
    """
    import app_factory

    src = inspect.getsource(app_factory.lifespan)
    assert "get_security_detector_async" in src, (
        "lifespan must pre-warm the SAST detector singleton"
    )
