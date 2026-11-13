"""Prove scanner version-probes don't block the async event loop.

Each scanner's ``__init__`` runs a synchronous ``subprocess.run([..., "--version"])``
availability/version probe (up to a 5s timeout). Constructed inside an async
request handler, a wedged tool binary would block the WHOLE worker event loop
for the probe duration, stalling every other in-flight request. The
container-image scan hot path (``routers.security.image_sbom``) therefore builds
its scanners via ``asyncio.to_thread(...)`` so the blocking probe runs off-loop.
"""

import asyncio
import inspect
import time
from unittest.mock import MagicMock, patch

from services.trivy_scanner import TrivyScanner

# A stand-in "wedged binary": each sync probe blocks the calling thread this long.
_PROBE_SLEEP = 0.2


def _blocking_run(*_args, **_kwargs):
    time.sleep(_PROBE_SLEEP)
    return MagicMock(returncode=0, stdout="Version: 0.0.0\n")


class _Ticker:
    """Counts how many times the event loop got to schedule us in a window."""

    def __init__(self) -> None:
        self.ticks = 0
        self._run = True

    async def run(self) -> None:
        while self._run:
            self.ticks += 1
            await asyncio.sleep(0.01)

    def stop(self) -> None:
        self._run = False


async def test_direct_construction_starves_the_loop():
    """Baseline: a bare in-loop ``TrivyScanner()`` blocks the loop for the probe."""
    ticker = _Ticker()
    task = asyncio.create_task(ticker.run())
    await asyncio.sleep(0)  # let the ticker start
    ticker.ticks = 0
    with patch("services.trivy_scanner.subprocess.run", _blocking_run):
        TrivyScanner()  # synchronous, in the running loop → blocks it
    ticker.stop()
    await task
    # The loop could not advance the ticker while the probe blocked the thread.
    assert ticker.ticks <= 1


async def test_offloaded_construction_keeps_loop_responsive():
    """The fix: ``asyncio.to_thread(TrivyScanner)`` frees the loop during the probe."""
    ticker = _Ticker()
    task = asyncio.create_task(ticker.run())
    await asyncio.sleep(0)
    ticker.ticks = 0
    with patch("services.trivy_scanner.subprocess.run", _blocking_run):
        scanner = await asyncio.to_thread(TrivyScanner)
    ticker.stop()
    await task
    assert scanner.trivy_available is True
    # Two probes (~2 * _PROBE_SLEEP) ran off-thread, so the ticker kept advancing.
    assert ticker.ticks >= 5


def test_image_sbom_router_offloads_scanner_construction():
    """Regression guard: the container-image hot path must construct its scanners
    off-thread — never with a bare in-loop ``ScannerClass()`` call."""
    from routers.security import image_sbom

    src = inspect.getsource(image_sbom)
    # TrivyScanner is no longer used here: a workspace has no image to scan.
    for cls in ("GrypeScanner", "SyftScanner"):
        assert f"await asyncio.to_thread({cls})" in src, f"{cls} not offloaded off-thread"
    for cls in ("TrivyScanner", "GrypeScanner", "SyftScanner"):
        assert f"{cls}()" not in src, f"{cls} still constructed synchronously in-loop"
