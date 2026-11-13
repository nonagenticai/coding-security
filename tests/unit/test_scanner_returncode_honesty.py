"""A crashed scanner must never be reported as a clean scan.

Every CLI-backed scanner in this service runs its tool via
``utils.subprocess_runner.run_subprocess`` and parses stdout. If the tool exits
non-zero having written nothing usable, the tool DID NOT SCAN — parsing its
empty stdout yields zero findings, which is indistinguishable from "your code is
safe". That is the single most dangerous failure mode a security scanner has, so
each scanner must surface the non-zero exit rather than return an empty result.

``bandit``/``semgrep``/``grype``/``pip-audit`` already did this; these tests pin
the same contract for the five that did not (``detect-secrets``, ``trivy``
image, ``trivy config`` IaC, ``safety``, ``syft``) and for the two consumers
whose degradation handling was previously unreachable.

Note the deliberate asymmetry every test pair below encodes: non-zero **with**
parseable JSON is NOT a failure (several tools exit non-zero merely because they
found something), only non-zero **without** it.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from services.iac_scanner import IaCScanner
from services.safety_scanner import SafetyScanner
from services.scanner_errors import ScannerExecutionError
from services.secrets_scanner import SecretsScanner
from services.syft_scanner import SyftScanner
from services.trivy_scanner import TrivyScanner


def _proc(stdout: bytes, stderr: bytes = b"", returncode: int = 0):
    """Patch context yielding a fake child process with a real return code."""
    mock_proc = AsyncMock()
    mock_proc.returncode = returncode
    mock_proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return mock_proc


class _Run:
    """Patch ``create_subprocess_exec``/``wait_for`` for one canned invocation."""

    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0):
        self._proc = _proc(stdout, stderr, returncode)
        self._out = (stdout, stderr)
        self._patches: list = []

    def __enter__(self):
        self._patches = [
            patch("asyncio.create_subprocess_exec", return_value=self._proc),
            patch("asyncio.wait_for", return_value=self._out),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False


# --------------------------------------------------------------------------
# detect-secrets — feeds the SecurityDetector augmentation loop
# --------------------------------------------------------------------------


def _secrets() -> SecretsScanner:
    s = SecretsScanner.__new__(SecretsScanner)
    s.secrets_available = True
    s.secrets_version = None
    return s


class TestSecretsScannerHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_unparseable_raises(self, tmp_path):
        """A detect-secrets crash must not read as "no secrets in this file"."""
        target = tmp_path / "settings.py"
        target.write_text("x = 1\n")

        with _Run(b"", b"detect-secrets: unrecognized arguments", returncode=2):
            with pytest.raises(ScannerExecutionError) as exc:
                await _secrets().scan([str(target)])
        assert exc.value.tool == "detect-secrets"
        assert exc.value.returncode == 2

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_is_still_a_failure(self, tmp_path):
        """detect-secrets exits 0 with or without findings (1.5.0, measured), so a
        non-zero exit is an error even when a report parses (R216)."""
        target = tmp_path / "settings.py"
        target.write_text("x = 1\n")

        payload = json.dumps({"results": {}}).encode()
        with _Run(payload, b"", returncode=1):
            with pytest.raises(ScannerExecutionError) as exc:
                await _secrets().scan([str(target)])
        assert exc.value.returncode == 1

    @pytest.mark.asyncio
    async def test_clean_exit_zero_returns_empty(self, tmp_path):
        """The genuine-clean path still returns an empty list, not an error."""
        target = tmp_path / "settings.py"
        target.write_text("x = 1\n")

        payload = json.dumps({"results": {}}).encode()
        with _Run(payload, b"", returncode=0):
            assert await _secrets().scan([str(target)]) == []

    @pytest.mark.asyncio
    async def test_timeout_raises_rather_than_returning_clean(self, tmp_path):
        target = tmp_path / "settings.py"
        target.write_text("x = 1\n")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError):
                    await _secrets().scan([str(target)])


# --------------------------------------------------------------------------
# trivy config (IaC) — per-target invocation, so partial findings matter
# --------------------------------------------------------------------------


def _iac() -> IaCScanner:
    s = IaCScanner.__new__(IaCScanner)
    s.trivy_available = True
    return s


class TestIaCScannerHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_unparseable_raises(self, tmp_path):
        """A `trivy config` crash must not read as "no misconfigurations"."""
        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine\n")

        with _Run(b"", b"trivy: FATAL failed to init policy", returncode=1):
            with pytest.raises(ScannerExecutionError) as exc:
                await _iac().scan([str(target)])
        assert exc.value.tool == "trivy-iac"

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_is_still_a_failure(self, tmp_path):
        """`trivy config` without --exit-code exits 0 even with findings (v0.69.3,
        measured), so a non-zero exit is an error even when a report parses."""
        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine\n")

        payload = json.dumps({"SchemaVersion": 2, "Results": []}).encode()
        with _Run(payload, b"", returncode=1):
            with pytest.raises(ScannerExecutionError):
                await _iac().scan([str(target)])

    @pytest.mark.asyncio
    async def test_partial_findings_survive_a_failed_target(self, tmp_path):
        """One target erroring must not discard findings from targets that worked.

        Two Dockerfiles are scanned with one `trivy config` invocation each. The
        first succeeds with a real FAIL misconfiguration, the second crashes.
        The error must surface, AND the first file's finding must ride along on
        the exception instead of being thrown away.
        """
        good = tmp_path / "Dockerfile"
        good.write_text("FROM alpine\n")
        bad = tmp_path / "worker.dockerfile"
        bad.write_text("FROM alpine\n")

        ok_payload = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {
                                "AVDID": "AVD-DS-0002",
                                "ID": "DS002",
                                "Title": "Image user should not be root",
                                "Description": "Running as root",
                                "Severity": "HIGH",
                                "Status": "FAIL",
                                "Resolution": "USER nonroot",
                            }
                        ],
                    }
                ],
            }
        ).encode()

        calls = {"n": 0}

        async def fake_run(cmd, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return (0, ok_payload, b"")
            return (1, b"", b"trivy: FATAL scan failed")

        with patch("services.iac_scanner.run_subprocess", side_effect=fake_run):
            with pytest.raises(ScannerExecutionError) as exc:
                await _iac().scan([str(good), str(bad)])

        assert calls["n"] == 2, "a failing target must not abort the remaining targets"
        assert len(exc.value.partial_findings) == 1, (
            "the successful target's real finding must not be discarded"
        )
        assert exc.value.partial_findings[0].severity.value == "high"


# --------------------------------------------------------------------------
# trivy image
# --------------------------------------------------------------------------


def _trivy() -> TrivyScanner:
    s = TrivyScanner.__new__(TrivyScanner)
    s.trivy_available = True
    s.trivy_version = None
    return s


class TestTrivyImageScannerHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_unparseable_raises(self):
        """An unpullable image must not report "0 vulnerabilities found"."""
        with _Run(b"", b"FATAL failed to initialize a scanner: pull access denied", returncode=1):
            with pytest.raises(ScannerExecutionError) as exc:
                await _trivy().scan_image("registry/image:latest")
        assert exc.value.tool == "trivy"

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_parses(self):
        payload = json.dumps({"Results": []}).encode()
        with _Run(payload, b"", returncode=1):
            assert await _trivy().scan_image("registry/image:latest") == []

    @pytest.mark.asyncio
    async def test_timeout_raises_rather_than_returning_clean(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError):
                    await _trivy().scan_image("registry/image:latest")


# --------------------------------------------------------------------------
# safety
# --------------------------------------------------------------------------


def _safety() -> SafetyScanner:
    s = SafetyScanner.__new__(SafetyScanner)
    s.safety_available = True
    s.safety_version = None
    return s


class TestSafetyScannerHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_unparseable_propagates(self, tmp_path):
        """A failed `safety check` must not report the file as vulnerability-free.

        The error has to survive ``scan_requirements``' own except-handler, which
        previously converted every failure into an empty list.
        """
        req = tmp_path / "requirements.txt"
        req.write_text("django==2.2.0\n")

        with _Run(b"", b"safety: authentication required", returncode=1):
            with pytest.raises(ScannerExecutionError) as exc:
                await _safety().scan_requirements(str(req))
        assert exc.value.tool == "safety"

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_parses(self, tmp_path):
        """safety exits non-zero when it FINDS things — that must still parse."""
        req = tmp_path / "requirements.txt"
        req.write_text("django==2.2.0\n")

        with _Run(json.dumps([]).encode(), b"", returncode=64):
            assert await _safety().scan_requirements(str(req)) == []

    @pytest.mark.asyncio
    async def test_installed_packages_scan_propagates(self):
        with _Run(b"", b"safety: db fetch failed", returncode=1):
            with pytest.raises(ScannerExecutionError):
                await _safety().scan_installed_packages()


# --------------------------------------------------------------------------
# syft — result object carries an `errors` list, so record rather than raise
# --------------------------------------------------------------------------


def _syft() -> SyftScanner:
    s = SyftScanner.__new__(SyftScanner)
    s.syft_available = True
    s.syft_version = None
    return s


class TestSyftScannerHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_records_error(self):
        """`total_packages=0` must be accompanied by an error, not look genuine."""
        with _Run(b"", b"syft: failed to catalog image", returncode=1):
            result = await _syft().generate_sbom("registry/image:latest")

        assert result.total_packages == 0
        assert result.errors, "a failed syft run must not present as an empty-but-valid SBOM"
        assert "1" in result.errors[0]

    @pytest.mark.asyncio
    async def test_success_records_no_error(self):
        payload = json.dumps({"components": []}).encode()
        with _Run(payload, b"", returncode=0):
            result = await _syft().generate_sbom("registry/image:latest")

        assert result.errors == []


# --------------------------------------------------------------------------
# Consumer wiring: the degradation handling that was previously unreachable
# --------------------------------------------------------------------------


class TestDetectorFlagsDegradedOnEngineFailure:
    """`SecurityDetector` already caught ScannerExecutionError per engine to set
    ``scan_degraded`` — but detect-secrets and trivy-iac could never raise it, so
    for half the engine loop that handler was dead code. These pin it live."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("engine_attr", ["_secrets", "_iac"])
    async def test_engine_execution_failure_marks_scan_degraded(self, tmp_path, engine_attr):
        from services.security_detector import SecurityVulnerabilityDetector

        detector = SecurityVulnerabilityDetector()
        code_file = tmp_path / "clean.py"
        code_file.write_text("VALUE = 1\n")

        # Only the engine under test participates, and it fails to execute.
        for attr, flag in (
            ("_bandit", "bandit_available"),
            ("_semgrep", "semgrep_available"),
            ("_secrets", "secrets_available"),
            ("_iac", "trivy_available"),
        ):
            setattr(getattr(detector, attr), flag, attr == engine_attr)

        engine = getattr(detector, engine_attr)
        with patch.object(engine, "scan", side_effect=ScannerExecutionError("tool", 1, "boom")):
            result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.total_vulnerabilities_found == 0
        assert result.scan_degraded is True, (
            f"{engine_attr} failing to run must degrade the report, not read as clean"
        )

    @pytest.mark.asyncio
    async def test_partial_findings_from_failed_engine_are_kept(self, tmp_path):
        """Findings the engine did collect before failing must reach the report."""
        from services.security_detector import (
            SecurityVulnerabilityDetector,
            VulnerabilityConfidence,
            VulnerabilityMatch,
            VulnerabilitySeverity,
            VulnerabilityType,
        )

        detector = SecurityVulnerabilityDetector()
        code_file = tmp_path / "clean.py"
        code_file.write_text("VALUE = 1\n")

        for attr, flag in (
            ("_bandit", "bandit_available"),
            ("_semgrep", "semgrep_available"),
            ("_secrets", "secrets_available"),
            ("_iac", "trivy_available"),
        ):
            setattr(getattr(detector, attr), flag, attr == "_iac")

        partial = VulnerabilityMatch(
            id="trivy_config_AVD-DS-0002_Dockerfile_1",
            vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.HIGH,
            file_path=str(tmp_path / "Dockerfile"),
            language="dockerfile",
            line_start=1,
            line_end=1,
            pattern_id="AVD-DS-0002",
            code_snippet="FROM ubuntu:latest",
        )
        err = ScannerExecutionError("trivy-iac", 1, "boom", partial_findings=[partial])

        with patch.object(detector._iac, "scan", side_effect=err):
            result = await detector.analyze_security_vulnerabilities([str(code_file)])

        assert result.scan_degraded is True
        assert result.total_vulnerabilities_found == 1, (
            "a real finding collected before the failure must not be discarded"
        )
