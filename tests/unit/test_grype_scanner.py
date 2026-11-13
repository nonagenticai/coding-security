"""Tests for GrypeScanner."""

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.grype_scanner import GrypeScanner
from services.scanner_errors import ScannerExecutionError


def _make_scanner() -> GrypeScanner:
    scanner = GrypeScanner.__new__(GrypeScanner)
    scanner.grype_available = False
    scanner.grype_version = None
    return scanner


class TestGrypeAvailability:
    def test_not_available(self):
        with patch.object(GrypeScanner, "_check_grype_available", return_value=False):
            scanner = GrypeScanner()
            assert scanner.grype_available is False

    def test_check_available_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner._check_grype_available() is True

    def test_check_available_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert scanner._check_grype_available() is False

    def test_check_available_file_not_found(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._check_grype_available() is False

    def test_check_available_timeout(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("grype", 5)):
            assert scanner._check_grype_available() is False

    def test_get_version_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="grype 0.87.0\n")
            result = scanner._get_grype_version()
            assert result == "grype 0.87.0"

    def test_get_version_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert scanner._get_grype_version() is None


class TestGrypeJsonParsing:
    def test_parse_empty(self):
        scanner = _make_scanner()
        assert scanner._parse_grype_json("") == []

    def test_parse_no_matches(self):
        scanner = _make_scanner()
        result = scanner._parse_grype_json(json.dumps({"matches": []}))
        assert result == []

    def test_parse_with_matches(self):
        scanner = _make_scanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-5678",
                        "severity": "CRITICAL",
                        "description": "Buffer overflow",
                        "fix": {"versions": ["1.2.3"]},
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1",
                        "type": "deb",
                    },
                }
            ]
        }
        result = scanner._parse_grype_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].vulnerability_id == "CVE-2024-5678"
        assert result[0].package_name == "openssl"
        assert result[0].fixed_version == "1.2.3"
        assert result[0].severity == "CRITICAL"

    def test_parse_no_fix_versions(self):
        scanner = _make_scanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-0001",
                        "severity": "HIGH",
                        "fix": {"versions": []},
                    },
                    "artifact": {"name": "lib", "version": "1.0", "type": "deb"},
                }
            ]
        }
        result = scanner._parse_grype_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].fixed_version is None

    def test_parse_malformed_json(self):
        scanner = _make_scanner()
        result = scanner._parse_grype_json("NOT JSON")
        assert result == []

    def test_parse_unexpected_type(self):
        scanner = _make_scanner()
        result = scanner._parse_grype_json('"string"')
        assert result == []


class TestGrypeScanImage:
    @pytest.mark.asyncio
    async def test_scan_not_available(self):
        scanner = _make_scanner()
        result = await scanner.scan_image("registry/image:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_timeout(self):
        scanner = _make_scanner()
        scanner.grype_available = True

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_exec.return_value = mock_proc

            # A timed-out scan is incomplete, not "clean" — it surfaces a
            # ScannerExecutionError so callers can mark the report degraded.
            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError):
                    await scanner.scan_image("registry/image:latest")

    @pytest.mark.asyncio
    async def test_scan_success(self):
        scanner = _make_scanner()
        scanner.grype_available = True

        json_output = json.dumps({"matches": []})
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(json_output.encode(), b"")):
                result = await scanner.scan_image("registry/image:latest")
                assert result == []

    @pytest.mark.asyncio
    async def test_nonzero_exit_unparseable_raises(self):
        """grype erroring (non-zero + non-JSON) surfaces a degradation signal."""
        scanner = _make_scanner()
        scanner.grype_available = True

        err = b"grype: failed to catalog image: pull access denied"
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", err))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(b"", err)):
                with pytest.raises(ScannerExecutionError):
                    await scanner.scan_image("registry/image:latest")

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_json_parses(self):
        """A non-zero exit with valid JSON just means findings — parse, do not raise."""
        scanner = _make_scanner()
        scanner.grype_available = True

        json_output = json.dumps({"matches": []})
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(json_output.encode(), b"")):
                result = await scanner.scan_image("registry/image:latest")
                assert result == []


class TestGrypeScanSbom:
    @pytest.mark.asyncio
    async def test_scan_sbom_not_available(self):
        scanner = _make_scanner()
        result = await scanner.scan_sbom("/tmp/sbom.json")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_sbom_success(self):
        scanner = _make_scanner()
        scanner.grype_available = True

        json_output = json.dumps({"matches": []})
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(json_output.encode(), b"")):
                result = await scanner.scan_sbom("/tmp/sbom.json")
                assert result == []


class TestGetStatus:
    def test_status_unavailable(self):
        scanner = _make_scanner()
        status = scanner.get_status()
        assert status["available"] is False
        assert status["version"] is None

    def test_status_available(self):
        scanner = _make_scanner()
        scanner.grype_available = True
        scanner.grype_version = "grype 0.87.0"
        status = scanner.get_status()
        assert status["available"] is True
        assert "Grype" in status["description"]

    def test_is_grype_available(self):
        scanner = _make_scanner()
        assert scanner.is_grype_available() is False
        scanner.grype_available = True
        assert scanner.is_grype_available() is True
