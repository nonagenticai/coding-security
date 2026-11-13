"""Cancel-safe subprocess runner for the CLI security scanners.

The async scan path wraps the whole scan coroutine in the router's
``asyncio.wait_for(..., timeout=budget)``. When that budget expires asyncio
does not raise ``TimeoutError`` *inside* the scan coroutine — it **cancels**
it, which surfaces as ``asyncio.CancelledError`` at whatever ``await`` is
currently suspended (typically ``proc.communicate()``). Two distinct failure
modes therefore have to be handled at the point we spawn a child:

* **Inner timeout** — this helper's own ``asyncio.wait_for`` deadline fires and
  raises ``TimeoutError``. This is the per-scanner ``timeout + N`` budget.
* **Outer cancel** — the *router's* ``wait_for`` cancels us mid-``communicate``
  and we see ``asyncio.CancelledError``. In Python 3.14 ``CancelledError`` is a
  ``BaseException``, so a plain ``except Exception`` / ``except TimeoutError`` in
  the scanner never catches it — the child would be orphaned and leak.

Both cases must (1) SIGKILL the child's **process group** so the CLI tool and
any grandchildren it spawned actually die, (2) reap the child to avoid a
zombie, and (3) re-raise so the timeout still propagates as a timeout and the
cancellation still tears the task down. The child is spawned with
``start_new_session=True`` precisely so ``killpg`` can reach the whole group.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Mapping
from typing import Literal, overload

# Environment every scanner child inherits. The pod has no egress to the tool
# vendors' update endpoints, so a CLI that phones home on start-up logs
# ``failed to fetch latest version`` (syft) or burns its budget on a dead
# connection. None of these flags change WHAT a scan checks — only that the CLI
# does not try to update itself. Vulnerability-DB update behaviour is left
# alone on purpose: an offline DB must surface as a scanner error (degraded),
# not be silently skipped.
SCANNER_CHILD_ENV: dict[str, str] = {
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "TRIVY_SKIP_VERSION_CHECK": "true",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
}


def scanner_child_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the environment for a scanner child: ours + no-update flags + ``extra``."""
    return {**os.environ, **SCANNER_CHILD_ENV, **(extra or {})}


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the child's own new-session process group; never raise.

    HARD GUARD against a mock/invalid pid. Under the scanner unit tests ``proc``
    is a mock whose ``.pid`` is NOT a real ``int`` but coerces (via ``__index__``)
    to **1** — so the old ``os.getpgid(proc.pid)`` returned 1 and the unguarded
    ``os.killpg(1, SIGKILL)`` SIGKILLed **process group 1**. In a CI runner PG 1
    contains the runner agent itself (``run.sh -> Runner.Worker -> ... -> pytest``),
    so a single mocked-timeout scanner test KILLED THE RUNNER — surfacing ~10 min
    later as "runner lost communication" with the step ``null`` and no logs (the
    ``except`` never fired because ``getpgid(1)`` did not raise). This is the
    coding-security RED-main root cause (introduced with this helper in #74).

    The child is spawned with ``start_new_session=True`` so a REAL child's group
    is its own (``pgid == pid > 1``) and never equals init's group (1) or ours.
    Signal only such a group; anything else (mock pid, pid<=1, our own pgid, a
    race where the child already exited) is a silent no-op.
    """
    pid = proc.pid
    # A real Process.pid is always a plain int; a mock coerces to 1 via __index__
    # but is NOT an int instance, so this cleanly skips the mocked-test path.
    if not isinstance(pid, int) or pid <= 1:
        return
    try:
        pgid = os.getpgid(pid)
        # Never nuke init's group (1) or our OWN group (would kill the caller /
        # the CI runner agent). A real start_new_session child is neither.
        if pgid <= 1 or pgid == os.getpgid(0):
            return
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


@overload
async def run_subprocess(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | None = ...,
    text: Literal[False] = ...,
    input: bytes | None = ...,
    env: Mapping[str, str] | None = ...,
) -> tuple[int | None, bytes, bytes]: ...


@overload
async def run_subprocess(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | None = ...,
    text: Literal[True],
    input: bytes | None = ...,
    env: Mapping[str, str] | None = ...,
) -> tuple[int | None, str, str]: ...


async def run_subprocess(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | None = None,
    text: bool = False,
    input: bytes | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[int | None, bytes | str, bytes | str]:
    """Run ``cmd`` to completion under ``timeout``, killing its group on abort.

    Returns ``(returncode, stdout, stderr)``. Output is bytes unless ``text`` is
    true, in which case it is UTF-8 decoded. On the helper's own timeout, or on
    an outer cancellation, the child's process group is SIGKILLed and reaped and
    the originating exception (``TimeoutError`` / ``asyncio.CancelledError``) is
    re-raised — it is never swallowed.

    The child always runs with :func:`scanner_child_env` (update checks off);
    ``env`` adds per-tool variables on top.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        env=scanner_child_env(env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if input is not None else None,
        start_new_session=True,
    )

    try:
        # Only pass `input` when there is one: some scanner test fakes define
        # `communicate(self)` with no parameters, and the live scanners never
        # feed stdin — calling with an explicit None would break those fakes.
        comm = proc.communicate(input) if input is not None else proc.communicate()
        out, err = await asyncio.wait_for(comm, timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        _kill_group(proc)
        with contextlib.suppress(Exception):
            await proc.wait()
        raise

    # Defensive getattr: some scanner test fakes define only `communicate()`
    # and no `returncode`; an unconditional attribute read would AttributeError.
    returncode = getattr(proc, "returncode", None)
    if text:
        out = out.decode("utf-8", errors="ignore") if isinstance(out, bytes) else out
        err = err.decode("utf-8", errors="ignore") if isinstance(err, bytes) else err
    return (returncode, out, err)
