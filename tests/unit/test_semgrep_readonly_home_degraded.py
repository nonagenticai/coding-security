"""Regression: every container scan was degraded/grade-F because semgrep crashed.

Measured live 2026-10-12: semgrep writes ``~/.semgrep/settings.yml`` at start-up;
the pod's root filesystem is read-only, so every run died with
``OSError: [Errno 30] Read-only file system: '/home/appuser/.semgrep'``. The
detector (correctly) turned that into ``scan_degraded=True`` — so a clean,
complete scan of one file answered ``grade F, degraded true`` and NO scan could
ever be graded on its findings.

Each test pairs a planted defect with a clean control.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from models.container_models import ContainerInfo, ContainerStatus
from models.security_api_models import ContainerSecurityScanRequest
from services.scanner_errors import ScannerExecutionError
from services.security_detector import SecurityVulnerabilityDetector
from services.security_scan_service import SecurityScanService
from services.semgrep_scanner import SemgrepScanner

_EMPTY_SEMGREP_JSON = b'{"version":"1.180.0","results":[],"errors":[],"paths":{"scanned":[]}}'
_READONLY_TRACEBACK = (
    b"Traceback (most recent call last):\n"
    + b'  File "/usr/local/bin/pysemgrep", line 10, in <module>\n' * 40
    + b"OSError: [Errno 30] Read-only file system: '/home/appuser/.semgrep'\n"
)


class _Proc:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._out = (stdout, stderr)

    async def communicate(self):
        return self._out


def _readonly_home_semgrep(captured: dict):
    """A fake semgrep that behaves like the real one on a read-only HOME.

    It succeeds only when SEMGREP_SETTINGS_FILE points at a writable location.
    """

    async def _exec(*cmd, **kwargs):
        env = kwargs.get("env") or {}
        captured["env"] = env
        settings = env.get("SEMGREP_SETTINGS_FILE")
        if not settings:
            return _Proc(1, b"", _READONLY_TRACEBACK)
        Path(settings).parent.mkdir(parents=True, exist_ok=True)
        Path(settings).write_text("anonymous_user_id: x\n")
        return _Proc(0, _EMPTY_SEMGREP_JSON)

    return _exec


class TestSemgrepWritableState:
    async def test_semgrep_runs_with_writable_settings_file(self, monkeypatch):
        """Clean control: the fixed scanner gives semgrep a writable settings path."""
        captured: dict = {}
        monkeypatch.setattr(
            "utils.subprocess_runner.asyncio.create_subprocess_exec",
            _readonly_home_semgrep(captured),
        )
        scanner = SemgrepScanner()
        scanner.semgrep_available = True

        assert await scanner.scan(["/x/clean.py"]) == []

        env = captured["env"]
        settings_dir = os.path.dirname(env["SEMGREP_SETTINGS_FILE"])
        assert os.access(settings_dir, os.W_OK)
        assert not env["SEMGREP_SETTINGS_FILE"].startswith(os.path.expanduser("~/.semgrep"))
        # update checks are off for every scanner child
        assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
        assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"

    async def test_semgrep_crash_still_raises_with_the_real_cause(self, monkeypatch):
        """Planted defect: a semgrep that genuinely crashes is still an execution
        error (degraded), and the message carries the traceback's LAST line."""

        async def _exec(*cmd, **kwargs):
            return _Proc(1, b"", _READONLY_TRACEBACK)

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _exec)
        scanner = SemgrepScanner()
        scanner.semgrep_available = True

        with pytest.raises(ScannerExecutionError) as exc:
            await scanner.scan(["/x/clean.py"])
        assert "Read-only file system" in str(exc.value)


class _CleanEngine:
    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        return []


class _CrashingEngine(_CleanEngine):
    async def scan(self, targets, **_kwargs):
        raise ScannerExecutionError("semgrep", 1, _READONLY_TRACEBACK.decode())


def _service_with_engines(semgrep_engine) -> SecurityScanService:
    detector = SecurityVulnerabilityDetector()
    detector._bandit = _CleanEngine()
    detector._secrets = _CleanEngine()
    detector._iac = _CleanEngine()
    detector._image = _CleanEngine()
    detector._semgrep = semgrep_engine
    svc = SecurityScanService.__new__(SecurityScanService)
    svc.detector = detector
    return svc


def _container(path: Path) -> ContainerInfo:
    return ContainerInfo(
        container_name="cv-test",
        api_endpoint="http://x",
        codebase_path=str(path),
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


class TestCleanCompleteScanGrade:
    async def test_clean_complete_scan_is_not_degraded_and_not_f(self, tmp_path):
        """Clean control: every engine ran, one clean file -> degraded false, grade A."""
        (tmp_path / "t4").mkdir()
        (tmp_path / "t4" / "clean.py").write_text("def add(a, b):\n    return a + b\n")
        svc = _service_with_engines(_CleanEngine())

        result = await svc.scan_container(
            _container(tmp_path), ContainerSecurityScanRequest(file_paths=["t4/clean.py"])
        )

        assert result.total_files_scanned == 1
        assert result.total_vulnerabilities == 0
        assert result.scan_degraded is False
        assert result.security_grade == "A"

    async def test_engine_crash_on_clean_file_is_degraded(self, tmp_path):
        """Planted defect: an engine that crashed means the scan is degraded."""
        (tmp_path / "clean.py").write_text("x = 1\n")
        svc = _service_with_engines(_CrashingEngine())

        result = await svc.scan_container(
            _container(tmp_path), ContainerSecurityScanRequest(file_paths=["clean.py"])
        )

        assert result.scan_degraded is True
        assert result.security_grade == "F"

    def test_grade_for_clean_complete_scan(self):
        svc = SecurityScanService.__new__(SecurityScanService)
        no_findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert svc._calculate_security_grade(0.0, 1, False, no_findings) == "A"
        assert svc._calculate_security_grade(0.0, 1, True, no_findings) == "F"
        assert svc._calculate_security_grade(0.0, 0, False, no_findings) == "F"
