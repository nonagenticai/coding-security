"""Tests for the cancel-safe subprocess runner (bug #3: orphaned scanner children).

These exercise the two failure modes that leaked a child before this helper:
an inner ``asyncio.wait_for`` timeout, and an OUTER cancellation (the router's
own ``wait_for`` deadline). In both cases the spawned child — and, via the new
session/process group, any grandchildren — must be SIGKILLed and reaped, and
the originating exception must still propagate. We use ``sys.executable`` with a
long ``time.sleep`` so the test has no external CLI dependency and runs in CI.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys

import pytest

from utils.subprocess_runner import run_subprocess

_SLEEP_CMD = [sys.executable, "-c", "import time; time.sleep(30)"]


def _pid_alive(pid: int) -> bool:
    """True if ``pid`` still exists (signal 0 probes without killing)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but not ours to signal — still alive for our purposes.
        return True
    return True


class _ChildSpy:
    """Record the real child pid AND signal the moment the child exists.

    ``started`` is the piece that makes the outer-cancel test deterministic: it
    is set only after ``create_subprocess_exec`` has actually returned a live
    child, so a test can arm its cancellation *after* the spawn instead of
    racing it against a wall clock.
    """

    def __init__(self) -> None:
        self.pid: int | None = None
        self.proc: asyncio.subprocess.Process | None = None
        self.started = asyncio.Event()

    def install(self, monkeypatch) -> None:
        real = asyncio.create_subprocess_exec

        async def _wrapped(*args, **kwargs):
            proc = await real(*args, **kwargs)
            self.pid = proc.pid
            self.proc = proc
            self.started.set()
            return proc

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _wrapped)


async def _assert_child_killed(spy: _ChildSpy) -> None:
    """The child must have been SIGKILLed and reaped — not merely gone.

    The returncode check is the load-independent discriminator, and it is the
    whole point of the assertion: ``_SLEEP_CMD`` exits 0 when it finishes its
    own 30s sleep, so a helper that killed nothing and simply blocked on
    ``proc.wait()`` until the child died of old age ALSO ends with a dead pid.
    Asserting only "the pid is gone" therefore passes with the kill removed —
    verified by mutation: neutering ``_kill_group`` left this file fully green
    (it just took 65s instead of 1.2s). Only ``returncode == -SIGKILL`` tells
    the two apart, and it does so without depending on any wall clock.
    """
    assert spy.pid is not None, "the spawn wrapper never recorded a child pid"
    # The kill+reap happens inside the helper's except block, which the caller
    # has already awaited to completion — this poll is cheap belt-and-braces
    # against the OS not having torn the pid down yet, not a race we depend on.
    for _ in range(50):
        if not _pid_alive(spy.pid):
            break
        await asyncio.sleep(0.02)
    with pytest.raises(ProcessLookupError):
        os.kill(spy.pid, 0)

    assert spy.proc is not None
    assert spy.proc.returncode == -signal.SIGKILL, (
        f"child exited with returncode {spy.proc.returncode!r}, expected "
        f"{-signal.SIGKILL} (SIGKILL). A returncode of 0 means the child was "
        f"never killed — it ran its full sleep to completion and the helper "
        f"merely waited for it."
    )


@pytest.mark.asyncio
async def test_kills_child_on_inner_timeout(monkeypatch):
    """The helper's own timeout SIGKILLs the child and re-raises TimeoutError.

    Not load-sensitive: the helper's ``timeout`` is applied to ``communicate()``,
    which is reached strictly *after* ``create_subprocess_exec`` has returned, so
    the child always exists before this deadline starts running.
    """
    spy = _ChildSpy()
    spy.install(monkeypatch)

    with pytest.raises(TimeoutError):
        await run_subprocess(_SLEEP_CMD, timeout=0.1)

    await _assert_child_killed(spy)


@pytest.mark.asyncio
async def test_kills_child_on_outer_cancel(monkeypatch):
    """An OUTER wait_for cancel (the router scenario) still kills the child.

    ``run_subprocess`` is given a generous timeout, but a tighter OUTER
    ``asyncio.wait_for`` cancels it mid-``communicate`` — the exact production
    path. The CancelledError surfaces to the outer wait_for as TimeoutError, and
    the child must be dead.

    DETERMINISM: this used to read
    ``asyncio.wait_for(run_subprocess(...), timeout=0.1)``, which started the
    0.1s cancellation clock *before* the child was spawned. On a loaded box the
    spawn itself took longer than 0.1s, so wait_for cancelled the task before
    ``create_subprocess_exec`` had returned: no pid was ever recorded and the
    test died with ``KeyError: 'pid'`` — never reaching the kill path it exists
    to cover. The deadline is now armed only once the child provably exists, so
    the 0.1s is measured against a child already sleeping 30s and can never lose
    that race no matter how loaded the machine is.
    """
    spy = _ChildSpy()
    spy.install(monkeypatch)

    task = asyncio.ensure_future(run_subprocess(_SLEEP_CMD, timeout=30))
    try:
        # Deadlock failsafe only: the spawn takes milliseconds. This bound never
        # participates in normal operation — it exists so a genuinely stuck
        # spawn fails loudly instead of hanging the suite forever.
        await asyncio.wait_for(spy.started.wait(), timeout=30)

        # The child now EXISTS. Cancelling the already-running task via an outer
        # wait_for is exactly the router's production deadline path.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(task, timeout=0.1)
    finally:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task

    await _assert_child_killed(spy)


@pytest.mark.asyncio
async def test_returns_output_on_success():
    """A fast command returns (returncode, stdout, stderr) with real output."""
    returncode, stdout, stderr = await run_subprocess(
        [sys.executable, "-c", "print('hi')"], timeout=5
    )
    assert returncode == 0
    assert b"hi" in stdout
    assert stderr == b""


@pytest.mark.asyncio
async def test_returns_text_when_requested():
    """``text=True`` decodes stdout/stderr to str."""
    returncode, stdout, stderr = await run_subprocess(
        [sys.executable, "-c", "print('hi')"], timeout=5, text=True
    )
    assert returncode == 0
    assert "hi" in stdout
    assert isinstance(stdout, str)


def test_kill_group_never_signals_pg1_for_mock_proc(monkeypatch):
    """REGRESSION: the coding-security RED-main root cause.

    A mocked ``proc`` (as every scanner ``*_timeout`` test uses) has a ``.pid``
    that is NOT a real int but coerces via ``__index__`` to **1**. The old
    ``_kill_group`` therefore ran ``os.killpg(1, SIGKILL)`` — SIGKILLing process
    group 1, which in a CI runner is the runner agent, so a single mocked-timeout
    test killed the runner ("runner lost communication", no logs). ``_kill_group``
    must signal NOTHING for such a proc.
    """
    from unittest.mock import AsyncMock

    import utils.subprocess_runner as sr

    signalled: list[int] = []
    monkeypatch.setattr(sr.os, "killpg", lambda pgid, sig: signalled.append(pgid))

    sr._kill_group(AsyncMock())  # .pid coerces to int 1

    assert signalled == [], f"_kill_group signalled process group(s) {signalled} for a mock proc"


def test_kill_group_never_signals_callers_own_group(monkeypatch):
    """A pid that resolves to the CALLER's process group must be skipped — killing
    our own group would take down pytest / the runner agent."""
    import utils.subprocess_runner as sr

    signalled: list[int] = []
    monkeypatch.setattr(sr.os, "killpg", lambda pgid, sig: signalled.append(pgid))

    class _Proc:
        pid = os.getpid()  # a real pid living in the caller's own session/group

    sr._kill_group(_Proc())

    assert signalled == [], "must never signal the caller's own process group"
