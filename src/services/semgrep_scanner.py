"""Semgrep Multi-Language SAST Scanner Service.

Real multi-language static-analysis engine (semgrep CLI) that augments the
Python-only bandit engine and the regex `SecurityVulnerabilityDetector` across
the ~13 languages the detector already ingests (java/js/ts/go/rs/cs/c/cpp/php/
ruby/...). Follows the BanditScanner CLI-subprocess pattern: availability-check
-> async subprocess -> JSON parse -> map to `VulnerabilityMatch` (so every
downstream consumer — SecurityScanResult, the AA measureStep gate — is
unchanged).

Ruleset: production uses the community ruleset VENDORED OFFLINE into the image
at `/opt/semgrep-rules` (baked at build time from a pinned semgrep-rules commit;
see the Dockerfile). `--config auto` is deliberately NOT used: it fetches the
registry ruleset at scan time, which is (1) metrics-gated — with `--metrics=off`
semgrep hard-errors "Cannot create auto config when metrics are off" — and (2)
unreachable anyway, because the runtime pod's egress to the semgrep registry is
blocked by the ambient-mesh policy by design (same as OSV/Trivy). The ruleset is
overridable with the `SEMGREP_RULESET` env var without a code change. When
semgrep is absent, cannot load its ruleset, or reports errors, the engine is
reported failed/degraded in ``engine_status`` (R216) — never as a clean run.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
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

# Ruleset passed to `semgrep scan --config <ruleset>`. Defaults to the OFFLINE
# community rules baked into the image at /opt/semgrep-rules (see Dockerfile).
# NOT "auto": auto fetches the registry ruleset at scan time, which is
# metrics-gated (fatal with --metrics=off) AND blocked by the pod's egress policy
# — so auto can never load in this deployment. Override with SEMGREP_RULESET.
_DEFAULT_RULESET = "/opt/semgrep-rules"

# semgrep `extra.severity` -> VulnerabilitySeverity. semgrep emits no CRITICAL;
# ERROR (its highest) maps to HIGH so it is counted by the critical+high gate.
_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "ERROR": VulnerabilitySeverity.HIGH,
    "WARNING": VulnerabilitySeverity.MEDIUM,
    "INFO": VulnerabilitySeverity.LOW,
}

_CONFIDENCE_MAP: dict[str, VulnerabilityConfidence] = {
    "HIGH": VulnerabilityConfidence.HIGH,
    "MEDIUM": VulnerabilityConfidence.MEDIUM,
    "LOW": VulnerabilityConfidence.LOW,
}

# CWE number -> VulnerabilityType. semgrep tags findings with a CWE in metadata,
# which is far more stable than parsing thousands of rule ids. Unmapped / no-CWE
# falls back to INFORMATION_DISCLOSURE (a real, visible finding without claiming
# a wrong type — same catch-all bandit uses).
_CWE_TO_TYPE: dict[int, VulnerabilityType] = {
    89: VulnerabilityType.SQL_INJECTION,
    79: VulnerabilityType.XSS,
    78: VulnerabilityType.COMMAND_INJECTION,
    77: VulnerabilityType.COMMAND_INJECTION,
    22: VulnerabilityType.PATH_TRAVERSAL,
    327: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    326: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    328: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    916: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    798: VulnerabilityType.HARDCODED_CREDENTIALS,
    259: VulnerabilityType.HARDCODED_CREDENTIALS,
    330: VulnerabilityType.INSECURE_RANDOM,
    338: VulnerabilityType.INSECURE_RANDOM,
    502: VulnerabilityType.DESERIALIZATION,
    611: VulnerabilityType.XML_INJECTION,
    776: VulnerabilityType.XML_INJECTION,
    90: VulnerabilityType.LDAP_INJECTION,
    352: VulnerabilityType.CSRF,
    200: VulnerabilityType.INFORMATION_DISCLOSURE,
    209: VulnerabilityType.INFORMATION_DISCLOSURE,
    532: VulnerabilityType.INFORMATION_DISCLOSURE,
}

# File extension -> language label (best-effort; informational only).
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".php": "php",
    ".rb": "ruby",
}


def _is_dotenv_file(path: str) -> bool:
    """True for ``.env`` / ``.env.*`` — admitted scan targets semgrep cannot parse."""
    name = Path(path).name
    return name == ".env" or name.startswith(".env.")


_CWE_RE = re.compile(r"CWE-(\d+)")

# semgrep exit codes. The Dockerfile installs `semgrep>=1.95` (unpinned; measured
# here on 1.181.0). scan() does NOT pass `--error`, so findings do NOT change the
# exit code: measured `semgrep scan --json` with findings -> 0, missing --config
# path -> 7 ("unable to find a config"), invalid scanning root -> 2; documented:
# 1 = findings only WITH --error, 2 = fatal, 4 = invalid pattern, 5 = unparseable
# YAML, 7 = no valid config, 8 = invalid language. Both 2 and 7 still print a
# parseable report with `results: []` — which is how a missing ruleset used to
# report as an ok engine with zero findings. Only 0 is success.
_OK_EXIT_CODES = frozenset({0})

# `semgrep scan --json` report shape (1.181.0, measured): an object that ALWAYS
# has "results": [..], "errors": [{"level", "type", "message", ...}], "paths":
# {"scanned": [..]}, plus version/time/skipped_rules. A non-empty `errors[]`
# with exit 0 means some targets/rules were not (fully) analysed: degraded.
_REQUIRED_KEYS: dict[str, type] = {"results": list, "errors": list}


class SemgrepScanner:
    """Scanner for multi-language source-code vulnerabilities using semgrep."""

    def __init__(self) -> None:
        self.ruleset = os.environ.get("SEMGREP_RULESET", _DEFAULT_RULESET)
        # Presence probe via shutil.which — instant and reliable. Do NOT shell
        # `semgrep --version` here: semgrep's CLI start-up is slow (heavy import,
        # plus a registry version-check) and routinely exceeds a short timeout
        # in-cluster, which would false-negative is_available() and leave the
        # engine inert in the request path. The version string is cosmetic and
        # resolved lazily + bounded by get_status().
        self.semgrep_available = self._check_available()
        self.semgrep_version: str | None = None
        self._state_dir: str | None = None

    def _check_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def _get_version(self) -> str | None:
        """Best-effort, bounded version string. Cosmetic — never gates
        availability, and cached so the slow CLI call runs at most once."""
        if self.semgrep_version is not None:
            return self.semgrep_version
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=20,
                env={
                    **os.environ,
                    "SEMGREP_ENABLE_VERSION_CHECK": "0",
                    "SEMGREP_SEND_METRICS": "off",
                },
            )
            if result.returncode == 0:
                self.semgrep_version = result.stdout.strip().split("\n")[0]
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"Failed to get semgrep version: {e}")
        return self.semgrep_version

    def is_available(self) -> bool:
        return self.semgrep_available

    def _state_env(self) -> dict[str, str]:
        """Point semgrep's settings / version-cache / log files at a writable dir.

        semgrep writes ``~/.semgrep/settings.yml`` on EVERY start-up. The pod
        runs with a read-only root filesystem, so ``mkdir ~/.semgrep`` raised
        ``OSError: [Errno 30] Read-only file system`` and semgrep exited 1 with
        a traceback on every scan (measured live 2026-10-12). Each such run was
        a ScannerExecutionError, so EVERY container scan reported
        ``scan_degraded=true`` and graded "F" — a clean file included. The tmp
        dir is the writable mount the scan tempdirs already use.
        """
        if self._state_dir is None or not os.path.isdir(self._state_dir):
            self._state_dir = tempfile.mkdtemp(prefix="semgrep-state-")
        return {
            "SEMGREP_SETTINGS_FILE": os.path.join(self._state_dir, "settings.yml"),
            "SEMGREP_VERSION_CACHE_PATH": os.path.join(self._state_dir, "version"),
            "SEMGREP_LOG_FILE": os.path.join(self._state_dir, "semgrep.log"),
        }

    async def scan(
        self, file_paths: Sequence[str | Path], timeout: int = 180
    ) -> list[VulnerabilityMatch]:
        """Run semgrep over every target except dotenv files.

        semgrep has parsers and rules for the admitted source, IaC and CI file
        types — its vendored pack includes Dockerfile, Terraform/HCL, JSON and
        YAML rules — so those targets must keep reaching it. Dotenv files
        (``.env``, ``.env.*``) are the one admitted type with no language:
        semgrep reports them in ``errors[]``, which this class maps to a
        DEGRADED engine. Only those are withheld; detect-secrets still reads
        them.

        Without ``--error`` findings exit 0, so any non-zero exit (a
        missing ruleset exits 7) and any stdout that is not a semgrep report
        raise ``ScannerExecutionError`` (failed); a report with ``errors[]``
        raises ``ScannerPartialRunError`` (degraded) carrying the findings.
        """
        if not self.semgrep_available:
            logger.warning("semgrep not available")
            return []

        all_targets = [str(p) for p in file_paths]
        targets = [p for p in all_targets if not _is_dotenv_file(p)]
        if not targets:
            logger.debug("semgrep: no targets besides dotenv files (%d)", len(all_targets))
            return []

        try:
            cmd = [
                "semgrep",
                "scan",
                "--config",
                self.ruleset,
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--quiet",
                "--timeout",
                str(timeout),
                *targets,
            ]
            logger.debug(f"Running semgrep (config={self.ruleset}) on {len(targets)} file(s)")

            returncode, stdout, stderr = await run_subprocess(
                cmd, timeout=timeout + 60, env=self._state_env()
            )
            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"semgrep stderr: {stderr_text}")

            data = load_json_report(
                "semgrep",
                returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr_text,
                ok_exit_codes=_OK_EXIT_CODES,
                required=_REQUIRED_KEYS,
            )
            matches = self._map_semgrep_report(data)
            errors = data["errors"]
            if errors:
                summary = "; ".join(
                    str(e.get("message") or e.get("type") or e)[:200]
                    if isinstance(e, dict)
                    else str(e)[:200]
                    for e in errors[:3]
                )
                more = f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""
                raise ScannerPartialRunError(
                    "semgrep",
                    returncode,
                    stderr_text,
                    partial_findings=matches,
                    reason=f"reported {len(errors)} error(s); the run was partial: {summary}{more}",
                )
            return matches
        except TimeoutError as e:
            logger.error(f"semgrep scan timed out after {timeout}s")
            raise ScannerExecutionError("semgrep", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running semgrep scan: {e}")
            # An engine that could not run must surface as failed (R215/R216),
            # never as an ok engine with zero findings.
            raise ScannerExecutionError("semgrep", -1, f"{type(e).__name__}: {e}") from e

    def _parse_semgrep_json(self, output: str) -> list[VulnerabilityMatch]:
        """Map a semgrep JSON report to matches.

        Strict: output that is not a JSON object raises ``ScannerExecutionError``
        (it used to return ``[]``, i.e. "clean"). ``errors[]`` handling (degraded)
        lives in ``scan()``.
        """
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError) as e:
            raise ScannerExecutionError(
                "semgrep", 0, reason="produced output that is not JSON"
            ) from e
        if not isinstance(data, dict):
            raise ScannerExecutionError(
                "semgrep",
                0,
                reason=f"produced JSON {type(data).__name__} instead of a report object",
            )
        return self._map_semgrep_report(data)

    def _map_semgrep_report(self, data: dict) -> list[VulnerabilityMatch]:
        matches: list[VulnerabilityMatch] = []
        for r in data.get("results", []) or []:
            if not isinstance(r, dict):
                continue
            try:
                matches.append(self._to_match(r))
            except Exception as e:  # pragma: no cover - defensive
                logger.debug(f"Failed to map semgrep result: {e}")
        return matches

    def _to_match(self, r: dict) -> VulnerabilityMatch:
        check_id = str(r.get("check_id", ""))
        file_path = str(r.get("path", ""))
        start = r.get("start") or {}
        end = r.get("end") or {}
        line_start = int(start.get("line", 0) or 0)
        line_end = int(end.get("line", line_start) or line_start)

        extra = r.get("extra") or {}
        metadata = extra.get("metadata") or {}

        severity = _SEVERITY_MAP.get(
            str(extra.get("severity", "")).upper(), VulnerabilitySeverity.MEDIUM
        )
        confidence = _CONFIDENCE_MAP.get(
            str(metadata.get("confidence", "")).upper(), VulnerabilityConfidence.MEDIUM
        )

        cwe_ids = self._extract_cwe_ids(metadata.get("cwe"))
        vuln_type = self._cwe_to_type(cwe_ids)
        owasp = self._as_str_list(metadata.get("owasp"))
        references = self._as_str_list(metadata.get("references"))

        return VulnerabilityMatch(
            engine=ScanEngine.SEMGREP,
            id=f"semgrep_{check_id}_{file_path}_{line_start}",
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            language=_EXT_TO_LANG.get(Path(file_path).suffix.lower(), "unknown"),
            line_start=line_start,
            line_end=line_end,
            pattern_id=check_id,
            title=check_id.rsplit(".", 1)[-1] if check_id else "semgrep_finding",
            description=str(extra.get("message", "")),
            code_snippet=str(extra.get("lines", "")).strip(),
            cwe_ids=cwe_ids,
            owasp_categories=owasp,
            references=references,
            matched_patterns=[check_id] if check_id else [],
        )

    @staticmethod
    def _as_str_list(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]

    @classmethod
    def _extract_cwe_ids(cls, cwe: object) -> list[str]:
        """Normalize semgrep's metadata.cwe (str or list) to ["CWE-<n>", ...]."""
        ids: list[str] = []
        for item in cls._as_str_list(cwe):
            match = _CWE_RE.search(item)
            if match:
                ids.append(f"CWE-{match.group(1)}")
        return ids

    @staticmethod
    def _cwe_to_type(cwe_ids: list[str]) -> VulnerabilityType:
        for cid in cwe_ids:
            match = _CWE_RE.search(cid)
            if match and int(match.group(1)) in _CWE_TO_TYPE:
                return _CWE_TO_TYPE[int(match.group(1))]
        return VulnerabilityType.INFORMATION_DISCLOSURE

    def get_status(self) -> dict:
        return {
            "available": self.semgrep_available,
            "version": self._get_version() if self.semgrep_available else None,
            "ruleset": self.ruleset,
            "description": "Multi-language source-code SAST using the semgrep CLI",
        }
