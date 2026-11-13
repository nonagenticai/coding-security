"""Tests for SyftScanner."""

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.syft_scanner import SyftScanner


def _make_scanner() -> SyftScanner:
    scanner = SyftScanner.__new__(SyftScanner)
    scanner.syft_available = False
    scanner.syft_version = None
    return scanner


class TestSyftAvailability:
    def test_not_available(self):
        with patch.object(SyftScanner, "_check_syft_available", return_value=False):
            scanner = SyftScanner()
            assert scanner.syft_available is False

    def test_check_available_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner._check_syft_available() is True

    def test_check_available_failure(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert scanner._check_syft_available() is False

    def test_check_available_file_not_found(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._check_syft_available() is False

    def test_check_available_timeout(self):
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("syft", 5)):
            assert scanner._check_syft_available() is False

    def test_get_version_success(self):
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="syft 1.19.0\n")
            result = scanner._get_syft_version()
            assert result == "syft 1.19.0"


class TestCycloneDXParsing:
    def test_parse_empty(self):
        scanner = _make_scanner()
        assert scanner._parse_cyclonedx("") == []

    def test_parse_with_components(self):
        scanner = _make_scanner()
        data = {
            "components": [
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "type": "library",
                    "purl": "pkg:pypi/flask@3.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                },
                {
                    "name": "openssl",
                    "version": "3.0.13",
                    "type": "library",
                    "purl": "pkg:deb/debian/openssl@3.0.13",
                    "licenses": [],
                },
            ]
        }
        result = scanner._parse_cyclonedx(json.dumps(data))
        assert len(result) == 2
        assert result[0].name == "flask"
        assert result[0].purl == "pkg:pypi/flask@3.0.0"
        assert result[0].licenses == ["BSD-3-Clause"]

    def test_parse_malformed_json(self):
        scanner = _make_scanner()
        result = scanner._parse_cyclonedx("NOT JSON")
        assert result == []

    def test_parse_no_components(self):
        scanner = _make_scanner()
        result = scanner._parse_cyclonedx(json.dumps({}))
        assert result == []


class TestSPDXParsing:
    def test_parse_empty(self):
        scanner = _make_scanner()
        assert scanner._parse_spdx("") == []

    def test_parse_with_packages(self):
        scanner = _make_scanner()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-flask",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "licenseDeclared": "BSD-3-Clause",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/flask@3.0.0",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "document",
                    "versionInfo": "1.0",
                },
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1  # Document package skipped
        assert result[0].name == "flask"
        assert result[0].purl == "pkg:pypi/flask@3.0.0"
        assert result[0].licenses == ["BSD-3-Clause"]

    def test_parse_malformed_json(self):
        scanner = _make_scanner()
        result = scanner._parse_spdx("NOT JSON")
        assert result == []


class TestGenerateSbom:
    @pytest.mark.asyncio
    async def test_not_available(self):
        scanner = _make_scanner()
        result = await scanner.generate_sbom("registry/image:latest", container_name="test")
        assert result.total_packages == 0
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_success(self):
        scanner = _make_scanner()
        scanner.syft_available = True

        cyclonedx_output = json.dumps(
            {
                "components": [
                    {
                        "name": "flask",
                        "version": "3.0.0",
                        "type": "library",
                    }
                ]
            }
        )

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(cyclonedx_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch(
                "asyncio.wait_for",
                return_value=(cyclonedx_output.encode(), b""),
            ):
                result = await scanner.generate_sbom(
                    "registry/image:latest",
                    container_name="test",
                )
                assert result.total_packages == 1
                assert result.container_name == "test"

    @pytest.mark.asyncio
    async def test_timeout(self):
        scanner = _make_scanner()
        scanner.syft_available = True

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_exec.return_value = mock_proc

            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                result = await scanner.generate_sbom(
                    "registry/image:latest",
                    container_name="test",
                )
                assert result.total_packages == 0
                assert len(result.errors) > 0


class TestGenerateSbomFromSource:
    @pytest.mark.asyncio
    async def test_delegates_to_generate_sbom(self):
        scanner = _make_scanner()
        scanner.syft_available = False

        result = await scanner.generate_sbom_from_source("/app/src", container_name="test")
        assert result.total_packages == 0


class TestGetStatus:
    def test_status_unavailable(self):
        scanner = _make_scanner()
        status = scanner.get_status()
        assert status["available"] is False
        assert status["version"] is None

    def test_status_available(self):
        scanner = _make_scanner()
        scanner.syft_available = True
        scanner.syft_version = "syft 1.19.0"
        status = scanner.get_status()
        assert status["available"] is True
        assert "Syft" in status["description"]

    def test_is_syft_available(self):
        scanner = _make_scanner()
        assert scanner.is_syft_available() is False
        scanner.syft_available = True
        assert scanner.is_syft_available() is True
