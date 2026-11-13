"""Tests for TrivyScanner."""

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.scanner_errors import ScannerExecutionError
from services.trivy_scanner import TrivyScanner


def _make_scanner() -> TrivyScanner:
    scanner = TrivyScanner.__new__(TrivyScanner)
    scanner.trivy_available = False
    scanner.trivy_version = None
    return scanner


class TestTrivyAvailability:
    def test_not_available(self):
        with patch.object(TrivyScanner, "_check_trivy_available", return_value=False):
            scanner = TrivyScanner()
            assert scanner.trivy_available is False

    def test_check_available_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner._check_trivy_available() is True

    def test_check_available_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert scanner._check_trivy_available() is False

    def test_check_available_file_not_found(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._check_trivy_available() is False

    def test_check_available_timeout(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trivy", 5)):
            assert scanner._check_trivy_available() is False

    def test_get_version_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Version: 0.58.2\n")
            result = scanner._get_trivy_version()
            assert result == "Version: 0.58.2"

    def test_get_version_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert scanner._get_trivy_version() is None


class TestTrivyJsonParsing:
    def test_parse_empty(self):
        scanner = _make_scanner()
        assert scanner._parse_trivy_json("") == []

    def test_parse_no_results(self):
        scanner = _make_scanner()
        result = scanner._parse_trivy_json(json.dumps({"Results": []}))
        assert result == []

    def test_parse_with_vulns(self):
        scanner = _make_scanner()
        data = {
            "Results": [
                {
                    "Target": "python:3.14-slim (debian 12.9)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "libssl3",
                            "InstalledVersion": "3.0.13-1",
                            "FixedVersion": "3.0.14-1",
                            "Severity": "HIGH",
                            "Title": "OpenSSL buffer overflow",
                            "Description": "Buffer overflow in SSL handshake",
                        }
                    ],
                }
            ]
        }
        result = scanner._parse_trivy_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].vulnerability_id == "CVE-2024-1234"
        assert result[0].package_name == "libssl3"
        assert result[0].severity == "HIGH"
        assert result[0].target == "python:3.14-slim (debian 12.9)"

    def test_parse_null_vulnerabilities(self):
        scanner = _make_scanner()
        data = {"Results": [{"Target": "test", "Vulnerabilities": None}]}
        result = scanner._parse_trivy_json(json.dumps(data))
        assert result == []

    def test_parse_malformed_json(self):
        scanner = _make_scanner()
        result = scanner._parse_trivy_json("NOT JSON")
        assert result == []

    def test_parse_unexpected_type(self):
        scanner = _make_scanner()
        result = scanner._parse_trivy_json('"just a string"')
        assert result == []


class TestTrivyScanImage:
    @pytest.mark.asyncio
    async def test_scan_not_available(self):
        scanner = _make_scanner()
        result = await scanner.scan_image("registry/image:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_timeout_raises_not_clean(self):
        """A timed-out trivy scan must RAISE, never return [].

        Returning [] is byte-identical to "image is clean" — the caller has no
        way to tell a scan that found nothing from a scan that never ran.
        """
        scanner = _make_scanner()
        scanner.trivy_available = True

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_exec.return_value = mock_proc

            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError) as exc:
                    await scanner.scan_image("registry/image:latest")

        assert exc.value.tool == "trivy"

    @pytest.mark.asyncio
    async def test_scan_nonzero_exit_unparseable_raises(self):
        """Non-zero exit with no parseable JSON = the scan did not happen."""
        scanner = _make_scanner()
        scanner.trivy_available = True

        with patch(
            "services.trivy_scanner.run_subprocess",
            new=AsyncMock(return_value=(1, b"", b"FATAL failed to download vuln DB")),
        ):
            with pytest.raises(ScannerExecutionError) as exc:
                await scanner.scan_image("registry/image:latest")

        assert exc.value.tool == "trivy"
        assert exc.value.returncode == 1
        assert "vuln DB" in exc.value.stderr

    @pytest.mark.asyncio
    async def test_scan_nonzero_exit_with_parseable_json_is_a_result(self):
        """A non-zero exit that still emitted a report is a real result, not an error."""
        scanner = _make_scanner()
        scanner.trivy_available = True
        payload = json.dumps({"Results": []}).encode()

        with patch(
            "services.trivy_scanner.run_subprocess",
            new=AsyncMock(return_value=(1, payload, b"")),
        ):
            assert await scanner.scan_image("registry/image:latest") == []

    @pytest.mark.asyncio
    async def test_scan_success(self):
        scanner = _make_scanner()
        scanner.trivy_available = True

        json_output = json.dumps({"Results": []})
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(json_output.encode(), b"")):
                result = await scanner.scan_image("registry/image:latest")
                assert result == []


class TestGetStatus:
    def test_status_unavailable(self):
        scanner = _make_scanner()
        status = scanner.get_status()
        assert status["available"] is False
        assert status["version"] is None

    def test_status_available(self):
        scanner = _make_scanner()
        scanner.trivy_available = True
        scanner.trivy_version = "Version: 0.58.2"
        status = scanner.get_status()
        assert status["available"] is True
        assert "Trivy" in status["description"]

    def test_is_trivy_available(self):
        scanner = _make_scanner()
        assert scanner.is_trivy_available() is False
        scanner.trivy_available = True
        assert scanner.is_trivy_available() is True
