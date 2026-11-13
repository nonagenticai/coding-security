"""Bandit Source-Code SAST Scanner Service.

Real Python static-analysis engine (bandit CLI) that replaces/augments the
regex `SecurityVulnerabilityDetector` for Python sources. Follows the
TrivyScanner CLI-subprocess pattern: availability-check -> async subprocess ->
JSON parse -> map to `VulnerabilityMatch` (so every downstream consumer —
SecurityScanResult, the AA measureStep gate — is unchanged).
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Sequence
from pathlib import Path

from services.scanner_errors import (
    ScannerExecutionError,
    ScannerPartialRunError,
    load_json_report,
)
from services.security_detector import (
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)

# bandit exit codes (bandit 1.9.4, uv.lock; measured with `bandit -f json -q`):
#   0 = ran, no issues; 1 = ran, issues found (report on stdout);
#   2 = argparse usage error. Anything but 0/1 means the run is not trustworthy.
_OK_EXIT_CODES = frozenset({0, 1})

# bandit `-f json` report shape (1.9.4, measured): a JSON object that ALWAYS has
#   {"errors": [{"filename": str, "reason": str}], "generated_at": str,
#    "metrics": {...}, "results": [{"test_id", "filename", "line_number", ...}]}
# `errors[]` lists files bandit could NOT analyse (e.g. "syntax error while
# parsing AST from file") — and bandit still exits 0/1 for them, so a non-empty
# errors[] is a PARTIAL run: degraded, never ok.
_REQUIRED_KEYS: dict[str, type] = {"results": list, "errors": list}

# bandit test_id -> VulnerabilityType. Unmapped ids fall back to
# INFORMATION_DISCLOSURE (a real, visible finding without claiming a wrong type).
_TEST_ID_TO_TYPE: dict[str, VulnerabilityType] = {
    # SQL injection
    "B608": VulnerabilityType.SQL_INJECTION,
    "B610": VulnerabilityType.SQL_INJECTION,  # django RawSQL
    "B611": VulnerabilityType.SQL_INJECTION,  # django extra
    # Command / shell injection
    "B602": VulnerabilityType.COMMAND_INJECTION,
    "B603": VulnerabilityType.COMMAND_INJECTION,
    "B604": VulnerabilityType.COMMAND_INJECTION,
    "B605": VulnerabilityType.COMMAND_INJECTION,
    "B606": VulnerabilityType.COMMAND_INJECTION,
    "B607": VulnerabilityType.COMMAND_INJECTION,
    "B609": VulnerabilityType.COMMAND_INJECTION,
    # Hardcoded credentials
    "B105": VulnerabilityType.HARDCODED_CREDENTIALS,
    "B106": VulnerabilityType.HARDCODED_CREDENTIALS,
    "B107": VulnerabilityType.HARDCODED_CREDENTIALS,
    # Weak cryptography / hashing
    "B303": VulnerabilityType.WEAK_CRYPTOGRAPHY,
    "B304": VulnerabilityType.WEAK_CRYPTOGRAPHY,
    "B305": VulnerabilityType.WEAK_CRYPTOGRAPHY,
    "B324": VulnerabilityType.WEAK_CRYPTOGRAPHY,
    # Insecure randomness
    "B311": VulnerabilityType.INSECURE_RANDOM,
    # Unsafe deserialization
    "B301": VulnerabilityType.DESERIALIZATION,
    "B302": VulnerabilityType.DESERIALIZATION,
    "B307": VulnerabilityType.DESERIALIZATION,
    "B403": VulnerabilityType.DESERIALIZATION,
    "B506": VulnerabilityType.DESERIALIZATION,
    # XML / external-entity
    "B313": VulnerabilityType.XML_INJECTION,
    "B314": VulnerabilityType.XML_INJECTION,
    "B315": VulnerabilityType.XML_INJECTION,
    "B316": VulnerabilityType.XML_INJECTION,
    "B317": VulnerabilityType.XML_INJECTION,
    "B318": VulnerabilityType.XML_INJECTION,
    "B319": VulnerabilityType.XML_INJECTION,
    "B320": VulnerabilityType.XML_INJECTION,
    "B405": VulnerabilityType.XML_INJECTION,
    "B406": VulnerabilityType.XML_INJECTION,
    "B407": VulnerabilityType.XML_INJECTION,
    "B408": VulnerabilityType.XML_INJECTION,
    "B409": VulnerabilityType.XML_INJECTION,
    "B410": VulnerabilityType.XML_INJECTION,
    "B411": VulnerabilityType.XML_INJECTION,
    # Information disclosure
    "B104": VulnerabilityType.INFORMATION_DISCLOSURE,
    "B201": VulnerabilityType.INFORMATION_DISCLOSURE,
}

_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "HIGH": VulnerabilitySeverity.HIGH,
    "MEDIUM": VulnerabilitySeverity.MEDIUM,
    "LOW": VulnerabilitySeverity.LOW,
}

_CONFIDENCE_MAP: dict[str, VulnerabilityConfidence] = {
    "HIGH": VulnerabilityConfidence.HIGH,
    "MEDIUM": VulnerabilityConfidence.MEDIUM,
    "LOW": VulnerabilityConfidence.LOW,
}


class BanditScanner:
    """Scanner for Python source-code vulnerabilities using the bandit CLI."""

    def __init__(self) -> None:
        self.bandit_available = self._check_bandit_available()
        self.bandit_version = self._get_bandit_version() if self.bandit_available else None

    def _check_bandit_available(self) -> bool:
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_bandit_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"Failed to get bandit version: {e}")
        return None

    def is_available(self) -> bool:
        return self.bandit_available

    async def scan(
        self, file_paths: Sequence[str | Path], timeout: int = 120
    ) -> list[VulnerabilityMatch]:
        """Run bandit over the given Python files and return mapped matches.

        Non-Python files are ignored (bandit only analyses Python). Exit 1 means
        "issues found" and is a success; any other non-zero exit, and any stdout
        that is not a bandit report object, raises ``ScannerExecutionError``
        (failed). A report with non-empty ``errors[]`` raises
        ``ScannerPartialRunError`` (degraded) carrying the findings.
        """
        if not self.bandit_available:
            logger.warning("bandit not available")
            return []

        py_files = [str(p) for p in file_paths if str(p).endswith(".py")]
        if not py_files:
            return []

        try:
            cmd = ["bandit", "-f", "json", "-q", *py_files]
            logger.debug(f"Running bandit on {len(py_files)} python file(s)")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout + 30)
            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"bandit stderr: {stderr_text}")

            # Unexpected exit code, empty / non-JSON / null / wrong-shape stdout
            # -> ScannerExecutionError (engine failed), whatever the exit code.
            data = load_json_report(
                "bandit",
                returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr_text,
                ok_exit_codes=_OK_EXIT_CODES,
                required=_REQUIRED_KEYS,
            )
            matches = self._map_bandit_report(data)
            self._raise_if_partial(data, matches, returncode, stderr_text)
            return matches
        except TimeoutError as e:
            logger.error(f"bandit scan timed out after {timeout}s")
            raise ScannerExecutionError("bandit", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running bandit scan: {e}")
            # An engine that could not run must surface as failed (R215/R216),
            # never as an ok engine with zero findings.
            raise ScannerExecutionError("bandit", -1, f"{type(e).__name__}: {e}") from e

    def _parse_bandit_json(self, output: str) -> list[VulnerabilityMatch]:
        """Map a bandit JSON report to matches.

        Strict: output that is not a JSON object raises ``ScannerExecutionError``
        (it used to return ``[]``, i.e. "clean"). Used directly by tests; the
        scan path validates the full report shape via ``load_json_report``.
        """
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError) as e:
            raise ScannerExecutionError(
                "bandit", 0, reason="produced output that is not JSON"
            ) from e
        if not isinstance(data, dict):
            raise ScannerExecutionError(
                "bandit",
                0,
                reason=f"produced JSON {type(data).__name__} instead of a report object",
            )
        return self._map_bandit_report(data)

    @staticmethod
    def _raise_if_partial(
        data: dict, matches: list[VulnerabilityMatch], returncode: int | None, stderr: str
    ) -> None:
        """bandit's own ``errors[]`` = files it could not analyse -> degraded."""
        scan_errors = data.get("errors") or []
        if not scan_errors:
            return
        listed = "; ".join(
            f"{e.get('filename', '?')}: {e.get('reason', '')}" if isinstance(e, dict) else str(e)
            for e in scan_errors[:5]
        )
        more = f" (+{len(scan_errors) - 5} more)" if len(scan_errors) > 5 else ""
        logger.warning("bandit could not scan %d file(s): %s", len(scan_errors), listed)
        raise ScannerPartialRunError(
            "bandit",
            returncode,
            stderr,
            partial_findings=matches,
            reason=(
                f"reported {len(scan_errors)} file(s) it could not analyse "
                f"(NOT covered by this scan): {listed}{more}"
            ),
        )

    def _map_bandit_report(self, data: dict) -> list[VulnerabilityMatch]:
        matches: list[VulnerabilityMatch] = []
        for r in data.get("results", []) or []:
            if not isinstance(r, dict):
                continue
            try:
                matches.append(self._to_match(r))
            except Exception as e:  # pragma: no cover - defensive
                logger.debug(f"Failed to map bandit result: {e}")
        return matches

    def _to_match(self, r: dict) -> VulnerabilityMatch:
        test_id = str(r.get("test_id", ""))
        filename = str(r.get("filename", ""))
        line_number = int(r.get("line_number", 0) or 0)
        line_range = r.get("line_range") or [line_number]
        line_end = int(line_range[-1]) if line_range else line_number

        severity = _SEVERITY_MAP.get(
            str(r.get("issue_severity", "")).upper(), VulnerabilitySeverity.MEDIUM
        )
        confidence = _CONFIDENCE_MAP.get(
            str(r.get("issue_confidence", "")).upper(), VulnerabilityConfidence.MEDIUM
        )
        vuln_type = _TEST_ID_TO_TYPE.get(test_id, VulnerabilityType.INFORMATION_DISCLOSURE)

        cwe_ids: list[str] = []
        cwe = r.get("issue_cwe")
        if isinstance(cwe, dict) and cwe.get("id") is not None:
            cwe_ids = [f"CWE-{cwe['id']}"]

        return VulnerabilityMatch(
            engine=ScanEngine.BANDIT,
            id=f"bandit_{test_id}_{filename}_{line_number}",
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            file_path=filename,
            language="python",
            line_start=line_number,
            line_end=line_end,
            pattern_id=test_id,
            title=str(r.get("test_name", test_id)),
            description=str(r.get("issue_text", "")),
            code_snippet=str(r.get("code", "")).strip(),
            cwe_ids=cwe_ids,
            references=[str(r["more_info"])] if r.get("more_info") else [],
            matched_patterns=[test_id],
        )

    def get_status(self) -> dict:
        return {
            "available": self.bandit_available,
            "version": self.bandit_version,
            "description": "Python source-code SAST using the bandit CLI",
        }
