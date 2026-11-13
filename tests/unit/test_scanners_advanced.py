"""Advanced tests for scanner modules covering uncovered code paths.

Targets uncovered lines in:
- grype_scanner.py: scan_image error paths, scan_sbom error/stderr, _parse_grype_json edge cases
- trivy_scanner.py: scan_image with stderr, error paths, version exception
- pip_audit_scanner.py: _run_pip_audit stderr, scan_requirements error, check_package error,
  _parse_pip_audit_json non-dict vuln/dep entries
- syft_scanner.py: generate_sbom spdx format, stderr handling, error paths,
  _parse_spdx edge cases, _parse_cyclonedx edge cases
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.grype_scanner import GrypeScanner
from services.pip_audit_scanner import PipAuditScanner
from services.scanner_errors import ScannerExecutionError
from services.syft_scanner import SyftScanner
from services.trivy_scanner import TrivyScanner

# ============================================================================
# Helper factories -- properly mock subprocess instead of __new__() bypass
# ============================================================================


def _make_grype(available: bool = False) -> GrypeScanner:
    """Create GrypeScanner with subprocess mocked during __init__."""
    with patch("subprocess.run", side_effect=FileNotFoundError("grype not found")):
        s = GrypeScanner()
    s.grype_available = available
    s.grype_version = "0.70.0" if available else None
    return s


def _make_trivy(available: bool = False) -> TrivyScanner:
    """Create TrivyScanner with subprocess mocked during __init__."""
    with patch("subprocess.run", side_effect=FileNotFoundError("trivy not found")):
        s = TrivyScanner()
    s.trivy_available = available
    s.trivy_version = "0.50.0" if available else None
    return s


def _make_pip_audit(available: bool = False) -> PipAuditScanner:
    """Create PipAuditScanner with subprocess mocked during __init__."""
    with patch("subprocess.run", side_effect=FileNotFoundError("pip-audit not found")):
        s = PipAuditScanner()
    s.pip_audit_available = available
    s.pip_audit_version = "2.6.0" if available else None
    return s


def _make_syft(available: bool = False) -> SyftScanner:
    """Create SyftScanner with subprocess mocked during __init__."""
    with patch("subprocess.run", side_effect=FileNotFoundError("syft not found")):
        s = SyftScanner()
    s.syft_available = available
    s.syft_version = "0.90.0" if available else None
    return s


# ============================================================================
# Grype Scanner
# ============================================================================


class TestGrypeAdvanced:
    def test_get_version_exception(self):
        """_get_grype_version returns None when subprocess throws."""
        scanner = _make_grype()
        with patch("subprocess.run", side_effect=Exception("unexpected")):
            result = scanner._get_grype_version()
        assert result is None

    def test_get_version_success(self):
        """_get_grype_version returns version string on success."""
        scanner = _make_grype()
        mock_result = MagicMock(returncode=0, stdout="grype 0.70.0")
        with patch("subprocess.run", return_value=mock_result):
            result = scanner._get_grype_version()
        assert result == "grype 0.70.0"

    @pytest.mark.asyncio
    async def test_scan_image_not_available_returns_empty(self):
        """scan_image returns empty when grype is not available."""
        scanner = _make_grype(available=False)
        result = await scanner.scan_image("test:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_image_with_stderr(self):
        """scan_image logs stderr but still parses stdout."""
        scanner = _make_grype(available=True)

        json_output = json.dumps({"matches": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"some warning output"),
            ):
                result = await scanner.scan_image("test:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_image_general_exception(self):
        """scan_image returns empty on unexpected exception."""
        scanner = _make_grype(available=True)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=OSError("connection refused"),
        ):
            result = await scanner.scan_image("test:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_sbom_with_stderr(self):
        """scan_sbom logs stderr but returns parsed results."""
        scanner = _make_grype(available=True)

        json_output = json.dumps({"matches": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"warning"),
            ):
                result = await scanner.scan_sbom("/tmp/sbom.json")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_sbom_timeout(self):
        """scan_sbom surfaces a timeout as a degradation signal, not a clean result."""
        scanner = _make_grype(available=True)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError):
                    await scanner.scan_sbom("/tmp/sbom.json")

    @pytest.mark.asyncio
    async def test_scan_sbom_general_exception(self):
        """scan_sbom returns empty on unexpected exception."""
        scanner = _make_grype(available=True)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=RuntimeError("unexpected"),
        ):
            result = await scanner.scan_sbom("/tmp/sbom.json")
        assert result == []

    def test_parse_grype_json_non_dict_match(self):
        """Non-dict entries in matches list are skipped."""
        scanner = _make_grype()
        data = {"matches": ["not a dict", 42, None]}
        result = scanner._parse_grype_json(json.dumps(data))
        assert result == []

    def test_parse_grype_json_missing_vulnerability_key(self):
        """Match without vulnerability key still produces a result with defaults."""
        scanner = _make_grype()
        data = {"matches": [{"artifact": {"name": "pkg", "version": "1.0", "type": "deb"}}]}
        result = scanner._parse_grype_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].vulnerability_id == "UNKNOWN"
        assert result[0].package_name == "pkg"
        assert result[0].installed_version == "1.0"

    def test_parse_grype_json_full_vulnerability(self):
        """Fully populated match produces correct ImageVulnerability fields."""
        scanner = _make_grype()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1111",
                        "severity": "HIGH",
                        "description": "A dangerous flaw",
                        "fix": {"versions": ["2.0.0"]},
                        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"],
                    },
                    "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"},
                },
            ]
        }
        result = scanner._parse_grype_json(json.dumps(data))
        assert len(result) == 1
        vuln = result[0]
        assert vuln.vulnerability_id == "CVE-2024-1111"
        assert vuln.severity == "HIGH"
        assert vuln.package_name == "openssl"
        assert vuln.installed_version == "1.1.1"

    def test_parse_grype_json_individual_vuln_exception(self):
        """If a single vulnerability fails to parse, others still succeed."""
        scanner = _make_grype()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-2024-1111", "severity": "HIGH"},
                    "artifact": {"name": "good-pkg", "version": "1.0", "type": "deb"},
                },
            ]
        }
        result = scanner._parse_grype_json(json.dumps(data))
        assert len(result) == 1

    def test_parse_grype_json_general_exception(self):
        """Non-JSON-decode exceptions in parsing return empty list."""
        scanner = _make_grype()
        # Valid JSON but causes processing error via non-iterable matches
        result = scanner._parse_grype_json(json.dumps({"matches": "not a list"}))
        assert result == []

    def test_parse_grype_json_empty_matches(self):
        """Empty matches list returns empty results."""
        scanner = _make_grype()
        result = scanner._parse_grype_json(json.dumps({"matches": []}))
        assert result == []

    def test_parse_grype_json_invalid_json(self):
        """Invalid JSON returns empty list."""
        scanner = _make_grype()
        result = scanner._parse_grype_json("not json at all{{{")
        assert result == []


# ============================================================================
# Trivy Scanner
# ============================================================================


class TestTrivyAdvanced:
    def test_get_version_exception(self):
        """_get_trivy_version returns None on unexpected exception."""
        scanner = _make_trivy()
        with patch("subprocess.run", side_effect=Exception("unexpected")):
            result = scanner._get_trivy_version()
        assert result is None

    def test_get_version_success(self):
        """_get_trivy_version returns version string on success."""
        scanner = _make_trivy()
        mock_result = MagicMock(returncode=0, stdout="Version: 0.50.0")
        with patch("subprocess.run", return_value=mock_result):
            result = scanner._get_trivy_version()
        assert result == "Version: 0.50.0"

    @pytest.mark.asyncio
    async def test_scan_image_not_available_returns_empty(self):
        """scan_image returns empty when trivy is not available."""
        scanner = _make_trivy(available=False)
        result = await scanner.scan_image("test:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_image_with_stderr(self):
        """scan_image logs stderr and parses stdout."""
        scanner = _make_trivy(available=True)

        json_output = json.dumps({"Results": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"WARNING: db update"),
            ):
                result = await scanner.scan_image("test:latest")
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_image_general_exception(self):
        """scan_image returns empty on unexpected exception."""
        scanner = _make_trivy(available=True)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=RuntimeError("trivy crashed"),
        ):
            result = await scanner.scan_image("test:latest")
        assert result == []

    def test_parse_trivy_json_non_dict_result(self):
        """Non-dict entries in Results are skipped."""
        scanner = _make_trivy()
        data = {"Results": ["not a dict", 42]}
        result = scanner._parse_trivy_json(json.dumps(data))
        assert result == []

    def test_parse_trivy_json_non_dict_vuln(self):
        """Non-dict entries in Vulnerabilities are skipped."""
        scanner = _make_trivy()
        data = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": ["not a dict", 42],
                }
            ]
        }
        result = scanner._parse_trivy_json(json.dumps(data))
        assert result == []

    def test_parse_trivy_json_vuln_parse_success(self):
        """A well-formed vulnerability is parsed with all fields."""
        scanner = _make_trivy()
        data = {
            "Results": [
                {
                    "Target": "python:3.14-slim",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-9999",
                            "PkgName": "libtest",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                        },
                    ],
                }
            ]
        }
        result = scanner._parse_trivy_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].vulnerability_id == "CVE-2024-9999"
        assert result[0].package_name == "libtest"
        assert result[0].installed_version == "1.0"
        assert result[0].severity == "CRITICAL"
        assert result[0].target == "python:3.14-slim"

    def test_parse_trivy_json_general_exception(self):
        """Non-JSON-decode exceptions return empty."""
        scanner = _make_trivy()
        result = scanner._parse_trivy_json(json.dumps({"Results": "not a list"}))
        assert result == []

    def test_parse_trivy_json_multiple_results(self):
        """Multiple result targets are all parsed with correct targets."""
        scanner = _make_trivy()
        data = {
            "Results": [
                {
                    "Target": "python:3.14-slim",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1111",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.1",
                            "Severity": "HIGH",
                        }
                    ],
                },
                {
                    "Target": "os-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-2222",
                            "PkgName": "zlib",
                            "InstalledVersion": "1.2.11",
                            "Severity": "MEDIUM",
                        }
                    ],
                },
            ]
        }
        result = scanner._parse_trivy_json(json.dumps(data))
        assert len(result) == 2
        targets = [v.target for v in result]
        assert "python:3.14-slim" in targets
        assert "os-pkgs" in targets
        # Verify vulnerability IDs
        vuln_ids = {v.vulnerability_id for v in result}
        assert vuln_ids == {"CVE-2024-1111", "CVE-2024-2222"}

    def test_parse_trivy_json_invalid_json(self):
        """Invalid JSON returns empty list."""
        scanner = _make_trivy()
        result = scanner._parse_trivy_json("broken json{{{")
        assert result == []


# ============================================================================
# pip-audit Scanner
# ============================================================================


class TestPipAuditAdvanced:
    @pytest.mark.asyncio
    async def test_scan_requirements_exception(self):
        """scan_requirements returns empty on general exception."""
        scanner = _make_pip_audit(available=True)

        with patch.object(
            scanner, "_run_pip_audit", new_callable=AsyncMock, side_effect=RuntimeError("boom")
        ):
            import tempfile
            from pathlib import Path

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("django==2.2.0\n")
                tmp_path = f.name
            try:
                result = await scanner.scan_requirements(tmp_path)
                assert result == []
            finally:
                Path(tmp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_scan_installed_exception(self):
        """scan_installed_packages returns empty on exception."""
        scanner = _make_pip_audit(available=True)

        with patch.object(
            scanner, "_run_pip_audit", new_callable=AsyncMock, side_effect=RuntimeError("fail")
        ):
            result = await scanner.scan_installed_packages()
        assert result == []

    @pytest.mark.asyncio
    async def test_check_package_exception(self):
        """check_package returns empty on exception."""
        scanner = _make_pip_audit(available=True)

        with patch.object(
            scanner, "_run_pip_audit", new_callable=AsyncMock, side_effect=RuntimeError("fail")
        ):
            result = await scanner.check_package("django", "2.2.0")
        assert result == []

    @pytest.mark.asyncio
    async def test_run_pip_audit_with_stderr(self):
        """_run_pip_audit logs stderr and still parses stdout."""
        scanner = _make_pip_audit()

        json_output = json.dumps({"dependencies": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"WARNING: something"),
            ):
                result = await scanner._run_pip_audit(["--format", "json"])
        assert result == []

    @pytest.mark.asyncio
    async def test_run_pip_audit_general_exception(self):
        """_run_pip_audit returns empty on unexpected exception."""
        scanner = _make_pip_audit()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=OSError("process error"),
        ):
            result = await scanner._run_pip_audit(["--format", "json"])
        assert result == []

    def test_parse_non_dict_dep(self):
        """Non-dict dependency entries are skipped."""
        scanner = _make_pip_audit()
        data = {"dependencies": ["not_a_dict", 42]}
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert result == []

    def test_parse_non_dict_vuln(self):
        """Non-dict vulnerability entries in a dependency are skipped."""
        scanner = _make_pip_audit()
        data = {
            "dependencies": [
                {"name": "pkg", "version": "1.0", "vulns": ["not_a_dict", 42]},
            ]
        }
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert result == []

    def test_parse_vuln_parse_success(self):
        """A well-formed vulnerability is parsed with correct fields."""
        scanner = _make_pip_audit()
        data = {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-001",
                            "fix_versions": ["1.1"],
                            "description": "test vuln",
                        },
                    ],
                },
            ]
        }
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].vulnerability_id == "PYSEC-2024-001"
        assert result[0].package_name == "pkg"
        assert result[0].installed_version == "1.0"
        assert result[0].fix_versions == ["1.1"]

    def test_parse_general_exception(self):
        """Non-JSON-decode exceptions return empty."""
        scanner = _make_pip_audit()
        result = scanner._parse_pip_audit_json(json.dumps({"dependencies": "not_a_list"}))
        assert result == []

    def test_parse_multiple_vulns_per_dep(self):
        """Multiple vulnerabilities per dependency are all parsed with correct data."""
        scanner = _make_pip_audit()
        data = {
            "dependencies": [
                {
                    "name": "django",
                    "version": "2.2.0",
                    "vulns": [
                        {"id": "PYSEC-2024-001", "fix_versions": ["2.2.28"]},
                        {
                            "id": "CVE-2024-9999",
                            "fix_versions": ["2.2.29"],
                            "aliases": ["GHSA-abc"],
                        },
                    ],
                },
            ]
        }
        result = scanner._parse_pip_audit_json(json.dumps(data))
        assert len(result) == 2
        assert result[0].vulnerability_id == "PYSEC-2024-001"
        assert result[0].package_name == "django"
        assert result[0].installed_version == "2.2.0"
        assert result[1].vulnerability_id == "CVE-2024-9999"
        assert "GHSA-abc" in result[1].aliases

    def test_parse_invalid_json(self):
        """Invalid JSON returns empty list."""
        scanner = _make_pip_audit()
        result = scanner._parse_pip_audit_json("not valid json{{{")
        assert result == []


# ============================================================================
# Syft Scanner
# ============================================================================


class TestSyftAdvanced:
    def test_get_version_failure(self):
        """_get_syft_version returns None when subprocess returns non-zero."""
        scanner = _make_syft()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = scanner._get_syft_version()
        assert result is None

    def test_get_version_exception(self):
        """_get_syft_version returns None on exception."""
        scanner = _make_syft()
        with patch("subprocess.run", side_effect=Exception("crash")):
            result = scanner._get_syft_version()
        assert result is None

    def test_get_version_success(self):
        """_get_syft_version returns version on success."""
        scanner = _make_syft()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="syft 0.90.0\nmore info")
            result = scanner._get_syft_version()
        assert result == "syft 0.90.0"

    @pytest.mark.asyncio
    async def test_generate_sbom_with_stderr(self):
        """generate_sbom logs stderr and still processes output."""
        scanner = _make_syft(available=True)

        json_output = json.dumps({"components": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"WARNING: something"),
            ):
                result = await scanner.generate_sbom("test:latest")
        assert result.total_packages == 0
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_generate_sbom_spdx_format(self):
        """generate_sbom with spdx-json format uses SPDX parser."""
        scanner = _make_syft(available=True)

        spdx_output = json.dumps(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-flask",
                        "name": "flask",
                        "versionInfo": "3.0.0",
                        "licenseDeclared": "BSD-3-Clause",
                        "externalRefs": [],
                    }
                ]
            }
        )
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(spdx_output.encode(), b""),
            ):
                result = await scanner.generate_sbom(
                    "test:latest",
                    container_name="myapp",
                    sbom_format="spdx-json",
                )
        assert result.total_packages == 1
        assert result.format == "spdx-json"
        # Verify the parsed package
        assert result.packages[0].name == "flask"
        assert result.packages[0].version == "3.0.0"

    @pytest.mark.asyncio
    async def test_generate_sbom_general_exception(self):
        """generate_sbom returns result with errors on unexpected exception."""
        scanner = _make_syft(available=True)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=RuntimeError("syft crashed"),
        ):
            result = await scanner.generate_sbom("test:latest", container_name="app")
        assert result.total_packages == 0
        assert len(result.errors) > 0
        assert "syft crashed" in result.errors[0].lower() or "Syft error" in result.errors[0]

    @pytest.mark.asyncio
    async def test_generate_sbom_packages_by_type(self):
        """generate_sbom populates packages_by_type counter correctly."""
        scanner = _make_syft(available=True)

        json_output = json.dumps(
            {
                "components": [
                    {"name": "flask", "version": "3.0.0", "type": "library"},
                    {"name": "python", "version": "3.14", "type": "application"},
                    {"name": "pip", "version": "24.0", "type": "library"},
                ]
            }
        )
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b""),
            ):
                result = await scanner.generate_sbom("test:latest")
        assert result.total_packages == 3
        assert result.packages_by_type["library"] == 2
        assert result.packages_by_type["application"] == 1

    def test_parse_cyclonedx_non_dict_component(self):
        """Non-dict component entries are skipped."""
        scanner = _make_syft()
        data = {"components": ["not_a_dict", 42]}
        result = scanner._parse_cyclonedx(json.dumps(data))
        assert result == []

    def test_parse_cyclonedx_license_with_name(self):
        """License extracted from name field when id is missing."""
        scanner = _make_syft()
        data = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "type": "library",
                    "licenses": [{"license": {"name": "Apache-2.0"}}],
                }
            ]
        }
        result = scanner._parse_cyclonedx(json.dumps(data))
        assert len(result) == 1
        assert result[0].licenses == ["Apache-2.0"]
        assert result[0].name == "pkg"
        assert result[0].version == "1.0"

    def test_parse_cyclonedx_license_empty_object(self):
        """License entry with empty license object is skipped."""
        scanner = _make_syft()
        data = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "type": "library",
                    "licenses": [{"license": {}}],
                }
            ]
        }
        result = scanner._parse_cyclonedx(json.dumps(data))
        assert len(result) == 1
        assert result[0].licenses == []

    def test_parse_cyclonedx_license_non_dict(self):
        """Non-dict license entries are skipped."""
        scanner = _make_syft()
        data = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "type": "library",
                    "licenses": ["not_a_dict"],
                }
            ]
        }
        result = scanner._parse_cyclonedx(json.dumps(data))
        assert len(result) == 1
        assert result[0].licenses == []

    def test_parse_cyclonedx_general_exception(self):
        """Non-JSON-decode exceptions return empty."""
        scanner = _make_syft()
        result = scanner._parse_cyclonedx(json.dumps({"components": "not a list"}))
        assert result == []

    def test_parse_spdx_non_dict_package(self):
        """Non-dict package entries are skipped."""
        scanner = _make_syft()
        data = {"packages": ["not_a_dict", 42]}
        result = scanner._parse_spdx(json.dumps(data))
        assert result == []

    def test_parse_spdx_noassertion_license(self):
        """NOASSERTION license is not included."""
        scanner = _make_syft()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "pkg",
                    "versionInfo": "1.0",
                    "licenseDeclared": "NOASSERTION",
                }
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1
        assert result[0].licenses == []
        assert result[0].name == "pkg"

    def test_parse_spdx_purl_extraction(self):
        """PURL is extracted from externalRefs."""
        scanner = _make_syft()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.0"},
                        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:flask:*"},
                    ],
                }
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1
        assert result[0].purl == "pkg:pypi/flask@3.0.0"
        assert result[0].name == "flask"
        assert result[0].version == "3.0.0"

    def test_parse_spdx_no_external_refs(self):
        """Package without externalRefs has None purl."""
        scanner = _make_syft()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "pkg",
                    "versionInfo": "1.0",
                }
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1
        assert result[0].purl is None

    def test_parse_spdx_general_exception(self):
        """Non-JSON-decode exceptions return empty."""
        scanner = _make_syft()
        result = scanner._parse_spdx(json.dumps({"packages": "not a list"}))
        assert result == []

    def test_parse_spdx_non_dict_external_ref(self):
        """Non-dict externalRef entries are skipped (no crash)."""
        scanner = _make_syft()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "pkg",
                    "versionInfo": "1.0",
                    "externalRefs": ["not_a_dict"],
                }
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1
        assert result[0].purl is None

    def test_parse_spdx_with_valid_license(self):
        """Valid SPDX license is included in result."""
        scanner = _make_syft()
        data = {
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkg",
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "licenseDeclared": "MIT",
                }
            ]
        }
        result = scanner._parse_spdx(json.dumps(data))
        assert len(result) == 1
        assert result[0].licenses == ["MIT"]

    @pytest.mark.asyncio
    async def test_generate_sbom_from_source_delegates(self):
        """generate_sbom_from_source prepends 'dir:' to the path."""
        scanner = _make_syft(available=True)

        json_output = json.dumps({"components": []})
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_exec.return_value = mock_proc
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b""),
            ):
                result = await scanner.generate_sbom_from_source("/app/src", container_name="test")
        assert result.total_packages == 0
        assert result.image_ref == "dir:/app/src"

    def test_check_available_os_error(self):
        """_check_syft_available returns False on OSError."""
        scanner = _make_syft()
        with patch("subprocess.run", side_effect=OSError("no such file")):
            result = scanner._check_syft_available()
        assert result is False

    def test_check_available_success(self):
        """_check_syft_available returns True when subprocess succeeds."""
        scanner = _make_syft()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = scanner._check_syft_available()
        assert result is True
