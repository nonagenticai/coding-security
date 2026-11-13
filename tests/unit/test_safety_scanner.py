"""Tests for SafetyScanner."""

import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.safety_scanner import SafetyScanner, SafetyVulnerability
from services.scanner_errors import ScannerExecutionError


class TestSafetyScanner:
    def test_safety_not_available(self):
        """Scanner works when safety CLI is not installed."""
        with patch.object(SafetyScanner, "_check_safety_available", return_value=False):
            scanner = SafetyScanner()
            assert scanner.safety_available is False
            assert scanner.get_status()["available"] is False

    @pytest.mark.parametrize(
        "description,expected_severity",
        [
            ("Remote code execution vulnerability", "critical"),
            ("SQL injection in query parser", "high"),
            ("Information disclosure via headers", "medium"),
            ("Minor issue", "low"),
        ],
        ids=["critical-rce", "high-sqli", "medium-disclosure", "low-default"],
    )
    def test_determine_severity(self, description, expected_severity):
        """Severity keyword matching maps descriptions to correct severity levels."""
        scanner = SafetyScanner.__new__(SafetyScanner)
        scanner.safety_available = False
        scanner.safety_version = None
        assert scanner._determine_severity(description) == expected_severity

    def test_parse_safety_json_empty(self):
        """Empty JSON output returns empty list."""
        scanner = SafetyScanner.__new__(SafetyScanner)
        scanner.safety_available = False
        scanner.safety_version = None
        assert scanner._parse_safety_json("") == []

    def test_parse_safety_json_list_format(self):
        """Parse list format from safety."""
        scanner = SafetyScanner.__new__(SafetyScanner)
        scanner.safety_available = False
        scanner.safety_version = None
        json_output = '[["django", "2.2.0", "<=2.2.0", "CVE-2021-12345", "Remote code execution"]]'
        result = scanner._parse_safety_json(json_output)
        assert len(result) == 1
        assert result[0].package_name == "django"
        assert result[0].cve_id == "CVE-2021-12345"

    def test_safety_vulnerability_model(self):
        """SafetyVulnerability model creation."""
        vuln = SafetyVulnerability(
            package_name="django",
            installed_version="2.2.0",
            vulnerable_spec="<=2.2.0",
            severity="critical",
            description="RCE vulnerability",
        )
        assert vuln.package_name == "django"
        assert vuln.severity == "critical"

    async def test_scan_requirements_not_available(self):
        """scan_requirements returns empty when safety not available."""
        with patch.object(SafetyScanner, "_check_safety_available", return_value=False):
            scanner = SafetyScanner()
            result = await scanner.scan_requirements("requirements.txt")
            assert result == []

    def test_extract_remediation(self):
        """Extract remediation from description."""
        scanner = SafetyScanner.__new__(SafetyScanner)
        scanner.safety_available = False
        scanner.safety_version = None
        result = scanner._extract_remediation("Upgrade to 3.2.1 to fix the issue")
        assert isinstance(result, str), "Expected a non-None remediation string"
        assert "3.2.1" in result


def _make_scanner() -> SafetyScanner:
    """Helper to create a SafetyScanner without calling __init__ (avoids subprocess)."""
    scanner = SafetyScanner.__new__(SafetyScanner)
    scanner.safety_available = False
    scanner.safety_version = None
    return scanner


class TestSafetyUnavailable:
    """Tests for scanner behaviour when safety CLI is not installed."""

    def test_safety_unavailable_returns_empty(self):
        """All scan methods return [] when safety is not available."""
        with patch.object(SafetyScanner, "_check_safety_available", return_value=False):
            scanner = SafetyScanner()
            assert scanner.safety_available is False
            assert scanner.is_safety_available() is False
            assert scanner.get_status()["available"] is False

    @pytest.mark.asyncio
    async def test_scan_requirements_unavailable(self):
        """scan_requirements returns [] when safety unavailable."""
        with patch.object(SafetyScanner, "_check_safety_available", return_value=False):
            scanner = SafetyScanner()
            result = await scanner.scan_requirements("requirements.txt")
            assert result == []

    @pytest.mark.asyncio
    async def test_scan_installed_unavailable(self):
        """scan_installed_packages returns [] when safety unavailable."""
        with patch.object(SafetyScanner, "_check_safety_available", return_value=False):
            scanner = SafetyScanner()
            result = await scanner.scan_installed_packages()
            assert result == []


class TestRunSafetyCheck:
    """Tests for _run_safety_check covering exit codes, JSON parsing, and errors."""

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_parseable_json(self):
        """safety returns exit code 64 (vulnerabilities found) with valid JSON on stdout."""
        scanner = _make_scanner()
        scanner.safety_available = True

        json_output = '[["requests", "2.20.0", "<=2.20.0", "CVE-2021-9999", "denial of service"]]'

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))
        mock_proc.returncode = 64

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for", return_value=(json_output.encode(), b"")):
                result = scanner._parse_safety_json(json_output)

        assert len(result) == 1
        assert result[0].package_name == "requests"

    def test_invalid_json_output(self):
        """Invalid JSON output returns empty list and logs an error."""
        scanner = _make_scanner()
        result = scanner._parse_safety_json("NOT VALID JSON {{{{")
        assert result == []

    @pytest.mark.asyncio
    async def test_cli_timeout_raises_rather_than_reporting_clean(self):
        """A timed-out safety check must NOT come back as an empty result.

        This test previously asserted `result == []` — i.e. it pinned the bug: a
        dependency scan that never completed was indistinguishable from one that
        completed and found nothing. For a vulnerability scanner that is the most
        dangerous thing it can say, so the timeout now surfaces as a
        ScannerExecutionError and the caller records the scan as degraded.
        """
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_exec.return_value = mock_proc

            with patch("asyncio.wait_for", side_effect=TimeoutError("timed out")):
                with pytest.raises(ScannerExecutionError) as exc:
                    await scanner._run_safety_check(["--file", "req.txt"])

        assert exc.value.tool == "safety"

    @pytest.mark.asyncio
    async def test_cli_file_not_found(self):
        """FileNotFoundError during CLI execution returns empty list."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("no such file")):
            result = await scanner._run_safety_check(["--file", "missing.txt"])

        assert result == []


class TestSeverityDerivation:
    """Tests for _determine_severity keyword matching."""

    @pytest.mark.parametrize(
        "description,expected_severity",
        [
            ("An RCE exploit in parser", "critical"),
            ("Privilege escalation via sudo", "critical"),
            ("Reflected XSS in form handler", "high"),
            ("DOS attack via large payload", "medium"),
            ("A minor cosmetic glitch", "low"),
        ],
        ids=["rce-critical", "privesc-critical", "xss-high", "dos-medium", "default-low"],
    )
    def test_severity_keyword_mapping(self, description, expected_severity):
        """Severity keywords in descriptions map to correct severity levels."""
        scanner = _make_scanner()
        assert scanner._determine_severity(description) == expected_severity


class TestRemediationExtraction:
    """Tests for _extract_remediation regex patterns."""

    @pytest.mark.parametrize(
        "description,expected_version",
        [
            ("Please upgrade to 2.5.1 to mitigate the issue", "2.5.1"),
            ("update to 1.0.3 immediately", "1.0.3"),
            ("use >= 3.0.0 for safety", "3.0.0"),
        ],
        ids=["upgrade-to", "update-to", "gte-pattern"],
    )
    def test_remediation_extracts_version(self, description, expected_version):
        """Version patterns in descriptions are extracted as remediation strings."""
        scanner = _make_scanner()
        result = scanner._extract_remediation(description)
        assert isinstance(result, str), f"Expected remediation string for: {description}"
        assert expected_version in result

    def test_remediation_none_when_no_match(self):
        """Returns None when no version pattern is found."""
        scanner = _make_scanner()
        result = scanner._extract_remediation("No version information available here")
        assert result is None


class TestEmptyRequirementsFile:
    """Tests for scanning edge cases."""

    @pytest.mark.asyncio
    async def test_empty_requirements_file(self):
        """scan_requirements with nonexistent file raises ValueError."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with pytest.raises(ValueError, match="Requirements file not found"):
            await scanner.scan_requirements("/nonexistent/requirements.txt")


class TestScanRequirementsAvailable:
    """Tests for scan_requirements when safety IS available."""

    @pytest.mark.asyncio
    async def test_scan_requirements_valid_file(self, tmp_path):
        """scan_requirements with valid file calls _run_safety_check."""
        scanner = _make_scanner()
        scanner.safety_available = True

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("django==2.2.0\n")

        with patch.object(
            scanner, "_run_safety_check", new_callable=AsyncMock, return_value=[]
        ) as mock_check:
            result = await scanner.scan_requirements(str(req_file))
            assert result == []
            mock_check.assert_awaited_once_with(["--file", str(req_file)])

    @pytest.mark.asyncio
    async def test_scan_requirements_exception_returns_empty(self, tmp_path):
        """scan_requirements catches exceptions and returns []."""
        scanner = _make_scanner()
        scanner.safety_available = True

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("django==2.2.0\n")

        with patch.object(
            scanner,
            "_run_safety_check",
            new_callable=AsyncMock,
            side_effect=RuntimeError("check failed"),
        ):
            result = await scanner.scan_requirements(str(req_file))
            assert result == []


class TestScanInstalledPackages:
    """Tests for scan_installed_packages."""

    @pytest.mark.asyncio
    async def test_scan_installed_packages_available(self):
        """scan_installed_packages when safety available calls _run_safety_check."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch.object(
            scanner, "_run_safety_check", new_callable=AsyncMock, return_value=[]
        ) as mock_check:
            result = await scanner.scan_installed_packages()
            assert result == []
            mock_check.assert_awaited_once_with([])

    @pytest.mark.asyncio
    async def test_scan_installed_packages_exception_returns_empty(self):
        """scan_installed_packages catches exceptions and returns []."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch.object(
            scanner,
            "_run_safety_check",
            new_callable=AsyncMock,
            side_effect=RuntimeError("explosion"),
        ):
            result = await scanner.scan_installed_packages()
            assert result == []


class TestCheckPackage:
    """Tests for check_package method."""

    @pytest.mark.asyncio
    async def test_check_package_unavailable(self):
        """check_package returns [] when safety not available."""
        scanner = _make_scanner()
        result = await scanner.check_package("django", "2.2.0")
        assert result == []

    @pytest.mark.asyncio
    async def test_check_package_available(self):
        """check_package creates temp file and calls _run_safety_check."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch.object(
            scanner, "_run_safety_check", new_callable=AsyncMock, return_value=[]
        ) as mock_check:
            result = await scanner.check_package("django", "2.2.0")
            assert result == []
            mock_check.assert_awaited_once()
            # Verify the temp file arg
            call_args = mock_check.call_args[0][0]
            assert call_args[0] == "--file"

    @pytest.mark.asyncio
    async def test_check_package_exception_returns_empty(self):
        """check_package catches exceptions and returns []."""
        scanner = _make_scanner()
        scanner.safety_available = True

        with patch.object(
            scanner,
            "_run_safety_check",
            new_callable=AsyncMock,
            side_effect=RuntimeError("package check boom"),
        ):
            result = await scanner.check_package("django", "2.2.0")
            assert result == []


class TestRunSafetyCheckAdditional:
    """Additional tests for _run_safety_check subprocess handling."""

    @pytest.mark.asyncio
    async def test_run_safety_check_with_stderr(self):
        """_run_safety_check handles stderr output from safety CLI."""
        scanner = _make_scanner()
        scanner.safety_available = True

        json_output = "[]"
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(json_output.encode(), b"some warning output")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b"some warning output"),
            ):
                result = await scanner._run_safety_check([])
                assert result == []

    @pytest.mark.asyncio
    async def test_run_safety_check_with_vulns_json(self):
        """_run_safety_check parses valid JSON with vulnerabilities."""
        scanner = _make_scanner()
        scanner.safety_available = True

        json_output = '[["flask", "1.0", "<=1.0", "CVE-2022-1234", "Remote code execution"]]'
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(json_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch(
                "asyncio.wait_for",
                return_value=(json_output.encode(), b""),
            ):
                result = await scanner._run_safety_check(["--file", "req.txt"])
                assert len(result) == 1
                assert result[0].package_name == "flask"
                assert result[0].cve_id == "CVE-2022-1234"


class TestIsSafetyAvailable:
    """Tests for is_safety_available method."""

    def test_is_safety_available_true(self):
        """is_safety_available returns True when safety_available is True."""
        scanner = _make_scanner()
        scanner.safety_available = True
        assert scanner.is_safety_available() is True

    def test_is_safety_available_false(self):
        """is_safety_available returns False when safety_available is False."""
        scanner = _make_scanner()
        assert scanner.is_safety_available() is False


class TestGetStatus:
    """Tests for get_status method."""

    def test_get_status_unavailable(self):
        """get_status returns correct dict when safety is unavailable."""
        scanner = _make_scanner()
        status = scanner.get_status()
        assert status["available"] is False
        assert status["version"] is None
        assert "description" in status

    def test_get_status_available(self):
        """get_status returns correct dict when safety is available."""
        scanner = _make_scanner()
        scanner.safety_available = True
        scanner.safety_version = "Safety, version 2.3.1"
        status = scanner.get_status()
        assert status["available"] is True
        assert status["version"] == "Safety, version 2.3.1"


class TestParseSafetyJsonFormats:
    """Tests for _parse_safety_json with various data formats."""

    def test_parse_dict_format(self):
        """Parse dict format from safety (e.g., {'vulnerabilities': [...]})."""
        scanner = _make_scanner()
        import json

        data = {
            "vulnerabilities": [
                ["requests", "2.20.0", "<=2.20.0", "CVE-2021-9999", "denial of service"]
            ]
        }
        result = scanner._parse_safety_json(json.dumps(data))
        assert len(result) == 1
        assert result[0].package_name == "requests"

    def test_parse_unexpected_type(self):
        """Unexpected JSON type (string) returns empty list."""
        scanner = _make_scanner()
        result = scanner._parse_safety_json('"just a string"')
        assert result == []

    def test_parse_list_with_non_vuln_items(self):
        """List with items that don't match vuln format are skipped."""
        scanner = _make_scanner()
        import json

        data = [42, "not-a-vuln", None]
        result = scanner._parse_safety_json(json.dumps(data))
        assert result == []


class TestParseVulnerabilityItem:
    """Tests for _parse_vulnerability_item with dict format."""

    def test_parse_dict_item(self):
        """Parse a dict-format vulnerability item."""
        scanner = _make_scanner()
        item = {
            "name": "django",
            "installed_version": "2.2.0",
            "vulnerable_spec": "<=2.2.0",
            "cve": "CVE-2021-33203",
            "description": "Information disclosure via headers",
            "fixed_in": "2.2.1",
        }
        result = scanner._parse_vulnerability_item(item)
        assert isinstance(result, SafetyVulnerability), (
            "Dict item should parse to SafetyVulnerability"
        )
        assert result.package_name == "django"
        assert result.installed_version == "2.2.0"
        assert result.cve_id == "CVE-2021-33203"
        assert result.safe_version == "2.2.1"
        assert result.severity == "medium"

    def test_parse_dict_item_missing_name(self):
        """Dict item without package name returns None."""
        scanner = _make_scanner()
        item = {
            "installed_version": "1.0",
            "affected_versions": "<=1.0",
        }
        result = scanner._parse_vulnerability_item(item)
        assert result is None

    def test_parse_dict_item_missing_version(self):
        """Dict item without installed_version returns None."""
        scanner = _make_scanner()
        item = {
            "package": "flask",
            "affected_versions": "<=1.0",
        }
        result = scanner._parse_vulnerability_item(item)
        assert result is None

    def test_parse_list_item_with_advisory_id(self):
        """List item where cve field is a safety advisory (not CVE)."""
        scanner = _make_scanner()
        item = ["django", "2.2.0", "<=2.2.0", "12345", "Minor bug fix"]
        result = scanner._parse_vulnerability_item(item)
        assert isinstance(result, SafetyVulnerability), "Advisory list item should parse"
        assert result.cve_id is None
        assert result.advisory_id == "12345"
        assert result.package_name == "django"

    def test_parse_list_item_short(self):
        """List item with exactly 4 elements (no description)."""
        scanner = _make_scanner()
        item = ["flask", "1.0", "<=1.0", "CVE-2020-1234"]
        result = scanner._parse_vulnerability_item(item)
        assert isinstance(result, SafetyVulnerability), "Short list item should parse"
        assert result.package_name == "flask"
        assert result.cve_id == "CVE-2020-1234"
        assert result.description == "Known vulnerability"

    def test_parse_invalid_item_type(self):
        """Non-list non-dict item returns None."""
        scanner = _make_scanner()
        assert scanner._parse_vulnerability_item(42) is None
        assert scanner._parse_vulnerability_item("string") is None

    def test_parse_exception_returns_none(self):
        """Exception during parsing returns None."""
        scanner = _make_scanner()
        # A list too short to match the expected format
        result = scanner._parse_vulnerability_item(["a", "b"])
        assert result is None


class TestCheckSafetyAvailable:
    """Tests for _check_safety_available and _get_safety_version."""

    def test_check_safety_available_success(self):
        """_check_safety_available returns True when subprocess succeeds."""
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert scanner._check_safety_available() is True

    def test_check_safety_available_failure(self):
        """_check_safety_available returns False when subprocess fails."""
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert scanner._check_safety_available() is False

    def test_check_safety_available_file_not_found(self):
        """_check_safety_available returns False when safety binary not found."""
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._check_safety_available() is False

    def test_check_safety_available_timeout(self):
        """_check_safety_available returns False on timeout."""
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("safety", 5)):
            assert scanner._check_safety_available() is False

    def test_get_safety_version_success(self):
        """_get_safety_version returns version string."""
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Safety, version 2.3.1\n")
            result = scanner._get_safety_version()
            assert result == "Safety, version 2.3.1"

    def test_get_safety_version_failure(self):
        """_get_safety_version returns None on failure."""
        scanner = _make_scanner()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = scanner._get_safety_version()
            assert result is None

    def test_get_safety_version_exception(self):
        """_get_safety_version returns None on exception."""
        scanner = _make_scanner()
        with patch("subprocess.run", side_effect=Exception("boom")):
            result = scanner._get_safety_version()
            assert result is None
