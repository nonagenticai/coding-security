"""Linearity budgets measured in process CPU time, best of ``ATTEMPTS`` (#118).

Wall-clock on a loaded shared CI runner counts time the test spent
descheduled, so wall-clock budgets flaked. CPU time is what the regex/analysis
actually costs, across every thread of the process (``to_thread`` work and the
TestClient portal included).

CPU time still inflates on a contended host (shared caches, slower cores), and
a bounded-but-heavy pattern can sit close to an absolute budget on any machine.
So :func:`is_linear` keeps the absolute budget as the fast path and, only when
it is exceeded, checks the property directly: doubling the input must not
quadruple the cost (linear ~2x, quadratic ~4x), under a hard cap of
``HARD_CAP_FACTOR`` x budget. A super-linear pattern on the 200 KB adversarial
inputs costs tens of CPU-seconds, so it fails both.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

ATTEMPTS = 3
HARD_CAP_FACTOR = 10
MAX_DOUBLING_RATIO = 3.0


def cpu_seconds(run: Callable[[], Any], budget: float, give_up: float = float("inf")) -> float:
    """Best-of-``ATTEMPTS`` process CPU time of ``run()``; stops once within budget
    (or once a single attempt is already past ``give_up``)."""
    best = float("inf")
    for _ in range(ATTEMPTS):
        t0 = time.process_time()
        run()
        dt = time.process_time() - t0
        best = min(best, dt)
        if best < budget or dt > give_up:
            break
    return best


async def cpu_seconds_async(
    run: Callable[[], Awaitable[Any]], budget: float, give_up: float = float("inf")
) -> float:
    best = float("inf")
    for _ in range(ATTEMPTS):
        t0 = time.process_time()
        await run()
        dt = time.process_time() - t0
        best = min(best, dt)
        if best < budget or dt > give_up:
            break
    return best


def _verdict(full: float, half: float | None, budget: float) -> tuple[bool, str]:
    if full < budget:
        return True, f"{full:.3f}s"
    if half is None:
        return False, f"{full:.3f}s > hard cap {HARD_CAP_FACTOR * budget}s"
    ratio = full / max(half, 1e-9)
    return ratio < MAX_DOUBLING_RATIO, f"{full:.3f}s, doubling ratio {ratio:.2f}"


def is_linear(run: Callable[[str], Any], data: str, budget: float) -> tuple[bool, str]:
    cap = HARD_CAP_FACTOR * budget
    full = cpu_seconds(lambda: run(data), budget, give_up=cap)
    if budget <= full < cap:
        half = cpu_seconds(lambda: run(data[: len(data) // 2]), 0.0)
        return _verdict(full, half, budget)
    return _verdict(full, None, budget)


async def is_linear_async(
    run: Callable[[str], Awaitable[Any]], data: str, budget: float
) -> tuple[bool, str]:
    cap = HARD_CAP_FACTOR * budget
    full = await cpu_seconds_async(lambda: run(data), budget, give_up=cap)
    if budget <= full < cap:
        half = await cpu_seconds_async(lambda: run(data[: len(data) // 2]), 0.0)
        return _verdict(full, half, budget)
    return _verdict(full, None, budget)
