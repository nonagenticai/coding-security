"""Tests for PipAuditScanner."""

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.pip_audit_scanner import PipAuditScanner, PipAuditVulnerability
from services.scanner_errors import ScannerExecutionError


def _make_scanner() -> PipAuditScanner:
    """Helper to create a PipAuditScanner without calling __init__ (avoids subprocess)."""
    scanner = PipAuditScanner.__new__(PipAuditScanner)
    scanner.pip_audit_available = False
    scanner.pip_audit_version = None
    return scanner


class TestPipAuditAvailability:
    def test_not_available(self):
        with patch.object(PipAuditScanner, "_check_pip_audit_available", return_value=False):
            scanner = PipAuditScanner()
            assert scanner.pip_audit_available is False
            assert scanner.get_status()["available"] is False

    def test_check_available_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner._check_pip_audit_available() is True

    def test_check_available_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert scanner._check_pip_audit_available() is False

    def test_check_available_file_not_found(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._check_pip_audit_available() is False

    def test_check_available_timeout(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pip-audit", 5)):
            assert scanner._check_pip_audit_available() is False

    def test_get_version_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="pip-audit 2.10.0\n")
            result = scanner._get_pip_audit_version()
            assert result == "pip-audit 2.10.0"

    def test_get_version_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = scanner._get_pip_audit_version()
            assert result is None

    def test_get_version_exception(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=Exception("boom")):
            result = scanner._get_pip_audit_version()
            assert result is None


class TestPipAuditJsonParsing:
    def test_parse_empty(self):
        scanner = _make_scanner()
        assert scanner._parse_pip_audit_json("") == []

    def test_parse_no_vulns(self):
        scanner = _make_scanner()
        data = {"dependencies": [{"name": "flask", "version": "3.0.0", "vulns": []}]}
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert result == []

    def test_parse_with_vulns(self):
        scanner = _make_scanner()
        data = {
            "dependencies": [
                {
                    "name": "django",
                    "version": "2.2.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-001",
                            "fix_versions": ["2.2.28"],
                            "aliases": ["CVE-2024-1234"],
                            "description": "SQL injection vulnerability",
                        }
                    ],
                }
            ]
        }
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].package_name == "django"
        assert result[0].vulnerability_id == "PYSEC-2024-001"
        assert result[0].fix_versions == ["2.2.28"]
        assert "CVE-2024-1234" in result[0].aliases

    def test_parse_malformed_json(self):
        scanner = _make_scanner()
        result = scanner._parse_pip_audit_json("NOT JSON {{")
        assert result == []

    def test_parse_unexpected_type(self):
        scanner = _make_scanner()
        result = scanner._parse_pip_audit_json('"just a string"')
        assert result == []

    def test_parse_multiple_deps_with_vulns(self):
        scanner = _make_scanner()
        data = {
            "dependencies": [
                {
                    "name": "django",
                    "version": "2.2.0",
                    "vulns": [
                        {"id": "PYSEC-2024-001", "fix_versions": ["2.2.28"]},
                    ],
                },
                {
                    "name": "flask",
                    "version": "1.0",
                    "vulns": [
                        {"id": "CVE-2024-5678", "fix_versions": ["2.0"]},
                    ],
                },
            ]
        }
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert len(result) == 2


class TestPipAuditScanMethods:
    @pytest.mark.asyncio
    async def test_scan_requirements_not_available(self):
        scanner = _make_scanner()
        result = await scanner.scan_requirements("requirements.txt")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_requirements_file_not_found(self):
        scanner = _make_scanner()
        scanner.pip_audit_available = True
        with pytest.raises(ValueError, match="Requirements file not found"):
            await scanner.scan_requirements("/nonexistent/requirements.txt")

    @pytest.mark.asyncio
    async def test_scan_requirements_valid_file(self, tmp_path):
        scanner = _make_scanner()
        scanner.pip_audit_available = True

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("django==2.2.0\n")

        with patch.object(
            scanner, "_run_pip_audit", new_callable=AsyncMock, return_value=[]
        ) as mock_run:
            result = await scanner.scan_requirements(str(req_file))
            assert result == []
            mock_run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_scan_installed_not_available(self):
        scanner = _make_scanner()
        result = await scanner.scan_installed_packages()
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_installed_available(self):
        scanner = _make_scanner()
        scanner.pip_audit_available = True

        with patch.object(scanner, "_run_pip_audit", new_callable=AsyncMock, return_value=[]):
            result = await scanner.scan_installed_packages()
            assert result == []

    @pytest.mark.asyncio
    async def test_check_package_not_available(self):
        scanner = _make_scanner()
        result = await scanner.check_package("django", "2.2.0")
        assert result == []

    @pytest.mark.asyncio
    async def test_check_package_available(self):
        scanner = _make_scanner()
        scanner.pip_audit_available = True

        with patch.object(
            scanner, "_run_pip_audit", new_callable=AsyncMock, return_value=[]
        ) as mock_run:
            result = await scanner.check_package("django", "2.2.0")
            assert result == []
            mock_run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_pip_audit_timeout(self):
        scanner = _make_scanner()
        scanner.pip_audit_available = True

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_exec.return_value = mock_proc

            # A timed-out scan is incomplete, not clean — it surfaces a
            # ScannerExecutionError so the report is marked degraded.
            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError):
                    await scanner._run_pip_audit(["--format", "json"])


class TestPipAuditVulnerabilityModel:
    def test_model_creation(self):
        vuln = PipAuditVulnerability(
            package_name="django",
            installed_version="2.2.0",
            vulnerability_id="PYSEC-2024-001",
            fix_versions=["2.2.28"],
            description="Test vulnerability",
            aliases=["CVE-2024-1234"],
        )
        assert vuln.package_name == "django"
        assert vuln.vulnerability_id == "PYSEC-2024-001"


class TestGetStatus:
    def test_status_unavailable(self):
        scanner = _make_scanner()
        status = scanner.get_status()
        assert status["available"] is False
        assert status["version"] is None

    def test_status_available(self):
        scanner = _make_scanner()
        scanner.pip_audit_available = True
        scanner.pip_audit_version = "pip-audit 2.10.0"
        status = scanner.get_status()
        assert status["available"] is True
        assert status["version"] == "pip-audit 2.10.0"

    def test_is_pip_audit_available(self):
        scanner = _make_scanner()
        assert scanner.is_pip_audit_available() is False
        scanner.pip_audit_available = True
        assert scanner.is_pip_audit_available() is True
