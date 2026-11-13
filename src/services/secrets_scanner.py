"""Secrets Scanner Service (detect-secrets).

Real secret-detection engine (Yelp detect-secrets CLI) replacing the single
regex `hardcoded_password` pattern. Follows the TrivyScanner CLI-subprocess
pattern and maps every finding to a `HARDCODED_CREDENTIALS` `VulnerabilityMatch`.

Security note: detect-secrets only exposes a *hash* of the secret, never the
plaintext — `code_snippet` is intentionally left empty so no secret value ever
leaks into a scan response.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

from services.scanner_errors import ScannerExecutionError, load_json_report
from services.security_detector import (
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)

# detect-secrets exit codes (1.5.0, uv.lock; measured): `detect-secrets scan`
# exits 0 whether or not it finds secrets; 2 = argparse usage error. Only 0 is
# success.
_OK_EXIT_CODES = frozenset({0})

# `detect-secrets scan` report shape (1.5.0, measured): an object that ALWAYS has
#   {"version": str, "plugins_used": [..], "filters_used": [..],
#    "results": {"<relative path>": [{"type", "filename", "hashed_secret",
#                                     "is_verified", "line_number"}]},
#    "generated_at": str}
# It has NO errors field: measured, a missing or unreadable target exits 0 with
# empty stderr and is simply absent from `results`. So there is no tool-reported
# partial-run signal to map to `degraded`; the targets passed here are files the
# pattern engine already read successfully.
_REQUIRED_KEYS: dict[str, type] = {"results": dict}

# Severity by detector type. Provider-specific detectors match a credential by
# its SHAPE (an AWS key id, a PEM private key, a Slack token): a hit is very
# likely a real secret. The generic heuristics (keyword assignment, entropy,
# user:pass@ in a URL, an IP) fire on labels, hashes and ids just as readily,
# so a hit is a lead to review, not a confirmed leak. Unknown types stay HIGH.
_CRITICAL_DETECTORS = frozenset({"AWS Access Key", "Private Key"})
_GENERIC_DETECTORS = frozenset(
    {
        "Secret Keyword",
        "Hex High Entropy String",
        "Base64 High Entropy String",
        "Basic Auth Credentials",
        "Public IP (ipv4)",
    }
)


def severity_for_detector(secret_type: str) -> VulnerabilitySeverity:
    """detect-secrets detector type -> finding severity."""
    if secret_type in _CRITICAL_DETECTORS:
        return VulnerabilitySeverity.CRITICAL
    if secret_type in _GENERIC_DETECTORS:
        return VulnerabilitySeverity.MEDIUM
    return VulnerabilitySeverity.HIGH


class SecretsScanner:
    """Scanner for hardcoded secrets using the detect-secrets CLI."""

    def __init__(self) -> None:
        self.secrets_available = self._check_available()
        self.secrets_version = self._get_version() if self.secrets_available else None

    def _check_available(self) -> bool:
        try:
            result = subprocess.run(
                ["detect-secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["detect-secrets", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"Failed to get detect-secrets version: {e}")
        return None

    def is_available(self) -> bool:
        return self.secrets_available

    async def scan(
        self, file_paths: Sequence[str | Path], timeout: int = 120
    ) -> list[VulnerabilityMatch]:
        """Run detect-secrets over the given files and return mapped matches."""
        if not self.secrets_available:
            logger.warning("detect-secrets not available")
            return []

        abs_paths = [os.path.abspath(str(p)) for p in file_paths]
        if not abs_paths:
            return []

        # detect-secrets only scans files *within its working directory* tree, so
        # run it from the common base dir and pass paths relative to it; the
        # reported filenames are then re-joined back to absolute paths.
        base = self._common_base(abs_paths)
        rel_paths = [os.path.relpath(p, base) for p in abs_paths]

        try:
            cmd = ["detect-secrets", "scan", *rel_paths]
            logger.debug(f"Running detect-secrets on {len(rel_paths)} file(s) under {base}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout + 30, cwd=base)
            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"detect-secrets stderr: {stderr_text}")

            # Unexpected exit code, empty / non-JSON / null / wrong-shape stdout
            # -> ScannerExecutionError (failed). Returning [] there would be
            # indistinguishable from "no secrets found" — the single most
            # dangerous thing a secrets scanner can say.
            data = load_json_report(
                "detect-secrets",
                returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr_text,
                ok_exit_codes=_OK_EXIT_CODES,
                required=_REQUIRED_KEYS,
            )
            return self._map_secrets_report(data, base)
        except ScannerExecutionError:
            raise
        except TimeoutError as e:
            logger.error(f"detect-secrets scan timed out after {timeout}s")
            raise ScannerExecutionError("detect-secrets", -1, "timed out") from e
        except Exception as e:
            logger.error(f"Error running detect-secrets scan: {e}")
            # An engine that could not run must surface as failed (R215/R216).
            raise ScannerExecutionError("detect-secrets", -1, f"{type(e).__name__}: {e}") from e

    @staticmethod
    def _common_base(abs_paths: list[str]) -> str:
        """Directory to run detect-secrets from (and resolve results against)."""
        if len(abs_paths) == 1:
            return os.path.dirname(abs_paths[0])
        base = os.path.commonpath(abs_paths)
        return base if os.path.isdir(base) else os.path.dirname(base)

    def _parse_secrets_json(self, output: str, base: str = "") -> list[VulnerabilityMatch]:
        """Map a detect-secrets report to matches.

        Strict: output that is not a JSON object raises ``ScannerExecutionError``
        (it used to return ``[]``, i.e. "no secrets").
        """
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, ValueError) as e:
            raise ScannerExecutionError(
                "detect-secrets", 0, reason="produced output that is not JSON"
            ) from e
        if not isinstance(data, dict):
            raise ScannerExecutionError(
                "detect-secrets",
                0,
                reason=f"produced JSON {type(data).__name__} instead of a report object",
            )
        return self._map_secrets_report(data, base)

    def _map_secrets_report(self, data: dict, base: str = "") -> list[VulnerabilityMatch]:
        matches: list[VulnerabilityMatch] = []
        results = data.get("results", {})
        if not isinstance(results, dict):
            return matches

        for file_path, findings in results.items():
            abs_path = (
                os.path.normpath(os.path.join(base, str(file_path))) if base else str(file_path)
            )
            for f in findings or []:
                if not isinstance(f, dict):
                    continue
                try:
                    matches.append(self._to_match(abs_path, f))
                except Exception as e:  # pragma: no cover - defensive
                    logger.debug(f"Failed to map detect-secrets finding: {e}")

        return matches

    def _to_match(self, file_path: str, f: dict) -> VulnerabilityMatch:
        secret_type = str(f.get("type", "Secret"))
        line_number = int(f.get("line_number", 0) or 0)
        is_verified = bool(f.get("is_verified", False))

        return VulnerabilityMatch(
            engine=ScanEngine.DETECT_SECRETS,
            id=f"detect-secrets_{secret_type}_{file_path}_{line_number}",
            vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            severity=severity_for_detector(secret_type),
            confidence=(
                VulnerabilityConfidence.HIGH if is_verified else VulnerabilityConfidence.MEDIUM
            ),
            file_path=file_path,
            language="any",
            line_start=line_number,
            line_end=line_number,
            pattern_id=f"detect-secrets:{secret_type}",
            title=secret_type,
            description=f"Potential secret detected: {secret_type}",
            code_snippet="",  # never emit the secret value (detect-secrets only hashes it)
            cwe_ids=["CWE-798"],
            remediation_advice="Remove the hardcoded secret and load it from a secret manager or environment variable.",
        )

    def get_status(self) -> dict:
        return {
            "available": self.secrets_available,
            "version": self.secrets_version,
            "description": "Hardcoded-secret detection using the detect-secrets CLI",
        }
