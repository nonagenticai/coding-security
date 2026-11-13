"""Shared exceptions for security scanner subprocess wrappers."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from typing import Any


def is_parseable_json(text: str) -> bool:
    """True if `text` is non-empty and parses as JSON.

    Used to tell "the tool ran and emitted a (possibly empty-result) report"
    from "the tool errored and emitted nothing usable". A non-zero exit with
    parseable JSON just means findings were present (grype/bandit/semgrep/
    pip-audit all exit non-zero when they find issues).
    """
    if not text.strip():
        return False
    try:
        json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return True


class ScannerExecutionError(Exception):
    """A scanner tool was available and ran, but exited abnormally.

    Raised when a scanner subprocess returns a non-zero exit code AND its
    output cannot be parsed into a result (empty or invalid). This is distinct
    from "the tool ran and found nothing" (a clean, zero-finding result) — an
    execution error means the scan is incomplete and must not be reported as
    clean. Callers in the unified-scan path append it to the report's `errors`
    list (marking the report degraded); the pattern detector folds it into its
    own `scan_degraded` flag.
    """

    def __init__(
        self,
        tool: str,
        returncode: int | None,
        stderr: str = "",
        partial_findings: list | None = None,
        *,
        reason: str | None = None,
    ) -> None:
        self.tool = tool
        # None = no exit status (the process was killed / never reaped).
        self.returncode = -1 if returncode is None else returncode
        self.stderr = stderr
        #: Findings already collected before the failure, for scanners that run the
        #: tool once per target. Losing them would trade one silent lie ("clean")
        #: for another ("nothing found on any target") — the failure is surfaced AND
        #: the real findings ride along so a caller can report degraded-with-results.
        self.partial_findings = partial_findings or []
        # Keep the TAIL of a long stderr: a Python traceback names its actual
        # exception on the last line, and the head-only cut hid the read-only-FS
        # OSError behind "Traceback (most recent call last):" for weeks.
        text = stderr.strip()
        if len(text) > 300:
            text = "…" + text[-300:]
        detail = f" stderr: {text}" if text else ""
        partial = (
            f" ({len(self.partial_findings)} finding(s) collected before the failure)"
            if self.partial_findings
            else ""
        )
        #: What was wrong with the run. Defaults to the historical wording.
        self.reason = reason or f"exited {self.returncode} with unparseable output"
        super().__init__(f"{tool} {self.reason}.{detail}{partial}")


class ScannerPartialRunError(ScannerExecutionError):
    """The tool ran and produced a valid report, but the report itself says the
    run was partial (e.g. bandit/semgrep ``errors[]``: some targets or rules were
    not analysed).

    Unlike a plain ``ScannerExecutionError`` this is ALWAYS reported as engine
    status ``degraded`` — whether or not it found anything — with whatever it
    did find riding along in ``partial_findings``. It is never ``ok``.
    """


def _summarize_errors(data: Any) -> str:
    """First few tool-reported ``errors[]`` entries, for a failure reason."""
    if not isinstance(data, dict):
        return ""
    errors: Any = data.get("errors")
    if not isinstance(errors, list) or not errors:
        return ""
    parts: list[str] = []
    for err in errors[:3]:
        if isinstance(err, dict):
            parts.append(
                str(err.get("message") or err.get("reason") or err.get("type") or err)[:200]
            )
        else:
            parts.append(str(err)[:200])
    more = f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""
    return "; ".join(parts) + more


def load_json_report(
    tool: str,
    returncode: int | None,
    stdout: str,
    stderr: str,
    *,
    ok_exit_codes: Collection[int],
    required: Mapping[str, type | tuple[type, ...]],
) -> dict[str, Any]:
    """Validate one scanner run and return its JSON report object.

    Raises ``ScannerExecutionError`` (engine status ``failed``) when ANY of:

    * the exit code is not one of the tool's documented success / "findings
      found" codes (``ok_exit_codes``) — even if stdout parses: a tool that
      exits with an error code and also prints a report has not told us the
      report is complete;
    * stdout is empty;
    * stdout is not JSON, or is JSON but not an object (``null``, a list, ...);
    * the object lacks a key the tool ALWAYS emits (``required``), or that key
      has the wrong type.

    Before R216 each wrapper raised only on ``rc != 0 and not parseable``, and
    its lenient parser turned garbage / ``null`` / a wrong-shape object into
    ``[]`` — i.e. an ``ok`` engine with zero findings.
    """
    rc = -1 if returncode is None else returncode  # None = killed / no status
    text = stdout.strip()
    data: Any = None
    parse_error: str | None = None
    if not text:
        parse_error = "produced empty output"
    else:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parse_error = "produced output that is not JSON"

    if rc not in ok_exit_codes:
        summary = _summarize_errors(data)
        raise ScannerExecutionError(
            tool,
            rc,
            stderr,
            reason=(
                f"exited {rc}, not a documented success/findings exit code "
                f"{sorted(ok_exit_codes)}" + (f"; tool reported: {summary}" if summary else "")
            ),
        )
    if parse_error is not None:
        raise ScannerExecutionError(tool, returncode, stderr, reason=parse_error)
    if not isinstance(data, dict):
        raise ScannerExecutionError(
            tool,
            returncode,
            stderr,
            reason=f"produced JSON {type(data).__name__} instead of a report object",
        )
    for key, expected in required.items():
        value = data.get(key)
        # bool is an int subclass: `"SchemaVersion": true` is not a report version
        if not isinstance(value, expected) or (isinstance(value, bool) and expected is not bool):
            raise ScannerExecutionError(
                tool,
                returncode,
                stderr,
                reason=f"report has no {key!r} of the expected type (wrong-shape output)",
            )
    return data
