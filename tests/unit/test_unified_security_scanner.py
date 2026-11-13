"""Tests for UnifiedSecurityScanner (services.unified_security)."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.security_models import OSVVulnerability
from services.safety_scanner import SafetyVulnerability
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.unified_security import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
    UnifiedSecurityReport,
    UnifiedSecurityScanner,
)


def make_finding(
    id_: str = "f1",
    title: str = "Test finding",
    severity: SecurityFindingSeverity = SecurityFindingSeverity.HIGH,
    confidence: float = 0.8,
    source: SecurityFindingSource = SecurityFindingSource.PATTERN,
    cve_id: str | None = None,
    package_name: str | None = None,
    affected_version: str | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        id=id_,
        title=title,
        description="Test description",
        severity=severity,
        confidence=confidence,
        source=source,
        cve_id=cve_id,
        package_name=package_name,
        affected_version=affected_version,
    )


@pytest.fixture
def scanner():
    with (
        patch("services.unified_security.scanner.get_security_detector") as mock_det,
        patch("services.unified_security.scanner.SafetyScanner") as mock_safety,
        patch("services.unified_security.scanner.PipAuditScanner") as mock_pip_audit,
        patch("services.unified_security.scanner.TrivyScanner") as mock_trivy,
        patch("services.unified_security.scanner.GrypeScanner") as mock_grype,
    ):
        s = UnifiedSecurityScanner()
        s.pattern_detector = mock_det.return_value
        s.safety_scanner = mock_safety.return_value
        s.pip_audit_scanner = mock_pip_audit.return_value
        s.trivy_scanner = mock_trivy.return_value
        s.grype_scanner = mock_grype.return_value
        yield s


class TestComprehensiveScan:
    async def test_all_scanners_empty_score_100(self, scanner):
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")

        assert isinstance(report, UnifiedSecurityReport)
        assert report.security_score == 100.0
        assert report.total_vulnerabilities == 0
        assert report.container_name == "test-container"

    async def test_pattern_scanner_contributes_findings(self, scanner):
        pattern_findings = [make_finding(id_="p1", source=SecurityFindingSource.PATTERN)]
        scanner._run_pattern_detection = AsyncMock(return_value=pattern_findings)
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")

        assert report.total_vulnerabilities == 1
        assert report.by_source["pattern"] == 1
        assert report.security_score < 100.0

    async def test_osv_scanner_contributes_findings(self, scanner):
        osv_findings = [
            make_finding(id_="o1", source=SecurityFindingSource.OSV, package_name="django")
        ]
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=osv_findings)
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")

        assert report.total_vulnerabilities == 1
        assert report.by_source["osv"] == 1

    async def test_scanner_failure_partial_results(self, scanner):
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")
        # Should succeed even with no real scanners
        assert isinstance(report, UnifiedSecurityReport)

    async def test_clean_scan_not_degraded(self, scanner):
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")

        assert report.scan_degraded is False
        assert any("Excellent" in r for r in report.recommendations)

    async def test_scanner_error_marks_report_degraded_no_clean_claim(self, scanner):
        async def _failing_image_scan(container_name, errors):
            errors.append("image scan failed: boom")
            return []

        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = _failing_image_scan
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("test-container")

        # A scanner failed → zero findings is NOT a clean bill of health.
        assert report.scan_degraded is True
        assert report.total_vulnerabilities == 0
        assert not any("Excellent" in r for r in report.recommendations)
        assert any("INCOMPLETE" in r for r in report.recommendations)


class TestDeduplicateFindings:
    def test_unique_findings_pass_through(self, scanner):
        findings_a = [make_finding(id_="a", title="Finding A")]
        findings_b = [
            make_finding(
                id_="b", title="Finding B", source=SecurityFindingSource.OSV, package_name="pkg"
            )
        ]
        result = scanner._deduplicate_findings(findings_a, findings_b, [])
        assert len(result) == 2

    def test_same_cve_deduplicated(self, scanner):
        f1 = make_finding(
            id_="f1", cve_id="CVE-2024-0001", confidence=0.7, source=SecurityFindingSource.OSV
        )
        f2 = make_finding(
            id_="f2", cve_id="CVE-2024-0001", confidence=0.9, source=SecurityFindingSource.SAFETY
        )
        result = scanner._deduplicate_findings([], [f1], [f2])
        assert len(result) == 1

    def test_higher_confidence_wins(self, scanner):
        f_low = make_finding(
            id_="f1", cve_id="CVE-2024-0001", confidence=0.5, source=SecurityFindingSource.OSV
        )
        f_high = make_finding(
            id_="f2", cve_id="CVE-2024-0001", confidence=0.95, source=SecurityFindingSource.SAFETY
        )
        result = scanner._deduplicate_findings([], [f_low], [f_high])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_empty_inputs(self, scanner):
        result = scanner._deduplicate_findings([], [], [])
        assert result == []


class TestCalculateSecurityScore:
    def test_no_findings_returns_100(self, scanner):
        assert scanner._calculate_security_score([]) == 100.0

    def test_all_critical_low_score(self, scanner):
        findings = [
            make_finding(
                id_=f"c{i}",
                severity=SecurityFindingSeverity.CRITICAL,
                confidence=1.0,
            )
            for i in range(10)
        ]
        score = scanner._calculate_security_score(findings)
        assert score <= 0.0

    def test_mixed_severity_intermediate_score(self, scanner):
        findings = [
            make_finding(id_="h1", severity=SecurityFindingSeverity.HIGH, confidence=0.8),
            make_finding(id_="l1", severity=SecurityFindingSeverity.LOW, confidence=0.5),
        ]
        score = scanner._calculate_security_score(findings)
        assert 0 < score < 100

    def test_info_findings_no_impact(self, scanner):
        findings = [
            make_finding(id_="i1", severity=SecurityFindingSeverity.INFO, confidence=1.0),
        ]
        score = scanner._calculate_security_score(findings)
        assert score == 100.0


class TestGenerateRecommendations:
    def test_no_findings_positive_message(self, scanner):
        recs = scanner._generate_recommendations([])
        assert any("No security vulnerabilities" in r for r in recs)

    def test_critical_immediate_action(self, scanner):
        findings = [make_finding(severity=SecurityFindingSeverity.CRITICAL)]
        recs = scanner._generate_recommendations(findings)
        assert any("URGENT" in r for r in recs)

    def test_high_update_recs(self, scanner):
        findings = [make_finding(severity=SecurityFindingSeverity.HIGH)]
        recs = scanner._generate_recommendations(findings)
        assert any("High Priority" in r for r in recs)

    def test_degraded_no_findings_warns_not_excellent(self, scanner):
        recs = scanner._generate_recommendations([], degraded=True)
        assert not any("Excellent" in r for r in recs)
        assert any("INCOMPLETE" in r for r in recs)


class TestOsvVulnToFinding:
    def test_correct_field_mapping(self, scanner):
        osv_vuln = OSVVulnerability(
            id="GHSA-1234",
            summary="A serious vulnerability in requests library that allows RCE",
            details="Detailed description of the vulnerability",
            severity="CRITICAL",
            affected_versions=["2.0.0"],
            fixed_versions=["2.1.0"],
            cve_ids=["CVE-2024-9999"],
            references=["https://example.com"],
            package_name="requests",
            ecosystem="PyPI",
        )
        finding = scanner._osv_vuln_to_finding(osv_vuln)
        assert finding.id == "osv_GHSA-1234"
        assert finding.severity == SecurityFindingSeverity.CRITICAL
        assert finding.source == SecurityFindingSource.OSV
        assert finding.cve_id == "CVE-2024-9999"
        assert finding.package_name == "requests"
        assert finding.fixed_version == "2.1.0"
        assert finding.confidence == 0.9


class TestSafetyVulnToFinding:
    def test_correct_field_mapping(self, scanner):
        safety_vuln = SafetyVulnerability(
            package_name="django",
            installed_version="2.2.0",
            vulnerable_spec="<=2.2.10",
            cve_id="CVE-2020-9402",
            advisory_id="12345",
            severity="high",
            description="SQL injection vulnerability in Django GIS functions",
            remediation="Upgrade to Django 2.2.11 or later",
            safe_version="2.2.11",
        )
        finding = scanner._safety_vuln_to_finding(safety_vuln)
        assert finding.id == "safety_12345"
        assert finding.severity == SecurityFindingSeverity.HIGH
        assert finding.source == SecurityFindingSource.SAFETY
        assert finding.cve_id == "CVE-2020-9402"
        assert finding.package_name == "django"
        assert finding.affected_version == "2.2.0"
        assert finding.confidence == 0.85


# ---------------------------------------------------------------------------
# Helper: create a mock SecurityAnalysisResult with vulnerabilities_by_type
# ---------------------------------------------------------------------------
def _make_analysis_result(vuln_matches: list[VulnerabilityMatch] | None = None):
    """Build a mock SecurityAnalysisResult object."""
    result = MagicMock()
    if vuln_matches:
        result.vulnerabilities_by_type = {VulnerabilityType.SQL_INJECTION: vuln_matches}
    else:
        result.vulnerabilities_by_type = {}
    return result


def _make_vuln_match(
    *,
    id_: str = "vuln-1",
    title: str = "SQL Injection",
    description: str = "Possible SQL injection",
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    confidence: VulnerabilityConfidence = VulnerabilityConfidence.HIGH,
    file_path: str = "/app/main.py",
    line_start: int = 10,
    references: list[str] | None = None,
    remediation_advice: str = "Use parameterized queries",
    context_evidence: dict[str, Any] | None = None,
) -> VulnerabilityMatch:
    return VulnerabilityMatch(
        id=id_,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=severity,
        confidence=confidence,
        file_path=file_path,
        language="python",
        line_start=line_start,
        line_end=line_start + 5,
        title=title,
        description=description,
        remediation_advice=remediation_advice,
        references=references or [],
        context_evidence=context_evidence or {},
    )


# ---------------------------------------------------------------------------
# Tests for _run_pattern_detection
# ---------------------------------------------------------------------------
class TestRunPatternDetection:
    async def test_no_source_files(self, scanner):
        """When _resolve_container_files returns empty, findings are empty."""
        scanner._resolve_container_files = AsyncMock(return_value=[])
        errors: list[str] = []

        result = await scanner._run_pattern_detection("no-files-container", errors)

        assert result == []
        assert errors == []

    async def test_success_converts_to_findings(self, scanner):
        """VulnerabilityMatch objects are converted to SecurityFinding."""
        vuln = _make_vuln_match(id_="v1", title="SQLi detected")
        analysis = _make_analysis_result([vuln])

        scanner._resolve_container_files = AsyncMock(return_value=["/app/main.py"])
        scanner.pattern_detector.analyze_security_vulnerabilities = AsyncMock(return_value=analysis)
        errors: list[str] = []

        result = await scanner._run_pattern_detection("my-container", errors)

        assert len(result) == 1
        assert result[0].id == "pattern_v1"
        assert result[0].source == SecurityFindingSource.PATTERN
        assert result[0].title == "SQLi detected"
        assert result[0].file_path == "/app/main.py"
        assert errors == []

    async def test_cve_extraction(self, scanner):
        """CVE IDs in references are extracted to finding.cve_id."""
        vuln = _make_vuln_match(
            id_="v2",
            references=["CVE-2023-1234", "https://example.com"],
        )
        analysis = _make_analysis_result([vuln])

        scanner._resolve_container_files = AsyncMock(return_value=["/app/x.py"])
        scanner.pattern_detector.analyze_security_vulnerabilities = AsyncMock(return_value=analysis)
        errors: list[str] = []

        result = await scanner._run_pattern_detection("ctr", errors)

        assert result[0].cve_id == "CVE-2023-1234"

    async def test_detector_exception_appends_error(self, scanner):
        """Exception in pattern detector appends error, returns empty list."""
        scanner._resolve_container_files = AsyncMock(side_effect=RuntimeError("detector boom"))
        errors: list[str] = []

        result = await scanner._run_pattern_detection("bad-container", errors)

        assert result == []
        assert len(errors) == 1
        assert "Pattern detection failed" in errors[0]


# ---------------------------------------------------------------------------
# Tests for _run_osv_scan
# ---------------------------------------------------------------------------
class TestRunOsvScan:
    async def test_no_lockfiles(self, scanner):
        """When no lockfiles found, return empty list."""
        scanner._find_lockfiles = AsyncMock(return_value=[])
        errors: list[str] = []

        result = await scanner._run_osv_scan("container-no-lock", errors)

        assert result == []
        assert errors == []

    async def test_success_converts(self, scanner):
        """OSV vulnerabilities are converted to SecurityFinding."""
        osv_vuln = OSVVulnerability(
            id="GHSA-abcd",
            summary="Remote code execution in foobar package that is critical",
            severity="HIGH",
            affected_versions=["1.0.0"],
            fixed_versions=["1.1.0"],
            cve_ids=["CVE-2024-5555"],
            references=["https://example.com"],
            package_name="foobar",
            ecosystem="PyPI",
        )

        mock_osv = AsyncMock()
        mock_osv.scan_lockfile = AsyncMock(return_value=[osv_vuln])
        mock_osv.close = AsyncMock()

        scanner._find_lockfiles = AsyncMock(return_value=["/app/requirements.txt"])
        scanner.osv_scanner = mock_osv
        errors: list[str] = []

        result = await scanner._run_osv_scan("container", errors)

        assert len(result) == 1
        assert result[0].source == SecurityFindingSource.OSV
        assert result[0].cve_id == "CVE-2024-5555"
        assert result[0].package_name == "foobar"
        assert errors == []

    async def test_exception_appends_error(self, scanner):
        """Top-level exception in OSV scanning appends error."""
        scanner._find_lockfiles = AsyncMock(side_effect=RuntimeError("osv boom"))
        errors: list[str] = []

        result = await scanner._run_osv_scan("container", errors)

        assert result == []
        assert len(errors) == 1
        assert "OSV scanning failed" in errors[0]


# ---------------------------------------------------------------------------
# Tests for _run_safety_scan
# ---------------------------------------------------------------------------
class TestRunSafetyScan:
    async def test_non_python_skips(self, scanner):
        """When safety CLI is not available, scan is skipped."""
        scanner.safety_scanner.is_safety_available.return_value = False
        errors: list[str] = []

        result = await scanner._run_safety_scan("container", errors)

        assert result == []
        assert errors == []

    async def test_success_converts(self, scanner):
        """Safety vulnerabilities are converted to SecurityFinding."""
        safety_vuln = SafetyVulnerability(
            package_name="flask",
            installed_version="1.0",
            vulnerable_spec="<2.0",
            cve_id="CVE-2024-7777",
            advisory_id="99999",
            severity="critical",
            description="Critical SSTI vulnerability in Flask templating engine that allows RCE",
            remediation="Upgrade flask to 2.0+",
            safe_version="2.0.0",
        )

        scanner.safety_scanner.is_safety_available.return_value = True
        scanner._find_requirements_files = AsyncMock(return_value=["/app/requirements.txt"])
        scanner.safety_scanner.scan_requirements = AsyncMock(return_value=[safety_vuln])
        errors: list[str] = []

        result = await scanner._run_safety_scan("container", errors)

        assert len(result) == 1
        assert result[0].source == SecurityFindingSource.SAFETY
        assert result[0].cve_id == "CVE-2024-7777"
        assert result[0].severity == SecurityFindingSeverity.CRITICAL
        assert errors == []

    async def test_failure_appends_error(self, scanner):
        """Top-level exception in safety scanning appends error."""
        scanner.safety_scanner.is_safety_available.return_value = True
        scanner._find_requirements_files = AsyncMock(side_effect=RuntimeError("safety boom"))
        errors: list[str] = []

        result = await scanner._run_safety_scan("container", errors)

        assert result == []
        assert len(errors) == 1
        assert "Safety scanning failed" in errors[0]


# ---------------------------------------------------------------------------
# More deduplication tests
# ---------------------------------------------------------------------------
class TestDeduplicateFindingsExtended:
    def test_same_cve_from_osv_and_safety(self, scanner):
        """Two findings with same CVE from different sources deduplicate to one."""
        osv_f = make_finding(
            id_="o1",
            cve_id="CVE-2024-1111",
            confidence=0.9,
            source=SecurityFindingSource.OSV,
        )
        safety_f = make_finding(
            id_="s1",
            cve_id="CVE-2024-1111",
            confidence=0.85,
            source=SecurityFindingSource.SAFETY,
        )

        result = scanner._deduplicate_findings([], [osv_f], [safety_f])
        assert len(result) == 1
        # Higher confidence (OSV 0.9) wins
        assert result[0].confidence == 0.9

    def test_same_file_title_different_confidence(self, scanner):
        """Two pattern findings with same title but different confidence deduplicate.
        For unmatched findings (no CVE, no package), the first occurrence wins."""
        f1 = make_finding(id_="p1", title="Hardcoded password", confidence=0.6)
        f2 = make_finding(id_="p2", title="Hardcoded password", confidence=0.9)

        result = scanner._deduplicate_findings([f1, f2], [], [])
        # Both are unmatched (no CVE, no package_name), deduplication by
        # source_title_severity key means they collapse to 1.
        # First occurrence wins for unmatched findings.
        assert len(result) == 1
        assert result[0].confidence == 0.6

    def test_unique_non_cve_preserved(self, scanner):
        """Findings without CVE or package_name are preserved if titles differ."""
        f1 = make_finding(id_="p1", title="Hardcoded password")
        f2 = make_finding(id_="p2", title="Insecure random")

        result = scanner._deduplicate_findings([f1, f2], [], [])
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Tests for _count_by_source
# ---------------------------------------------------------------------------
class TestCountBySource:
    def test_empty(self, scanner):
        counts = scanner._count_by_source([])
        assert counts == {
            "pattern": 0,
            "osv": 0,
            "safety": 0,
            "pip_audit": 0,
            "trivy": 0,
            "grype": 0,
        }

    def test_mixed(self, scanner):
        findings = [
            make_finding(id_="p1", source=SecurityFindingSource.PATTERN),
            make_finding(id_="p2", source=SecurityFindingSource.PATTERN),
            make_finding(
                id_="o1",
                source=SecurityFindingSource.OSV,
                package_name="x",
            ),
            make_finding(
                id_="s1",
                source=SecurityFindingSource.SAFETY,
                package_name="y",
            ),
        ]
        counts = scanner._count_by_source(findings)
        assert counts["pattern"] == 2
        assert counts["osv"] == 1
        assert counts["safety"] == 1


# ---------------------------------------------------------------------------
# Tests for _count_by_severity
# ---------------------------------------------------------------------------
class TestCountBySeverity:
    def test_empty(self, scanner):
        counts = scanner._count_by_severity([])
        assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_mixed(self, scanner):
        findings = [
            make_finding(id_="c1", severity=SecurityFindingSeverity.CRITICAL),
            make_finding(id_="h1", severity=SecurityFindingSeverity.HIGH),
            make_finding(id_="h2", severity=SecurityFindingSeverity.HIGH),
            make_finding(id_="m1", severity=SecurityFindingSeverity.MEDIUM),
            make_finding(id_="l1", severity=SecurityFindingSeverity.LOW),
            make_finding(id_="i1", severity=SecurityFindingSeverity.INFO),
        ]
        counts = scanner._count_by_severity(findings)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 1


# ---------------------------------------------------------------------------
# More security score tests
# ---------------------------------------------------------------------------
class TestCalculateSecurityScoreExtended:
    def test_no_findings(self, scanner):
        assert scanner._calculate_security_score([]) == 100.0

    def test_critical_findings(self, scanner):
        """A single critical finding at full confidence: weight = 10*1.0 = 10,
        normalized = (10/10)*100 = 100, score = 100 - 100 = 0."""
        findings = [
            make_finding(
                id_="c1",
                severity=SecurityFindingSeverity.CRITICAL,
                confidence=1.0,
            )
        ]
        score = scanner._calculate_security_score(findings)
        assert score == 0.0

    def test_low_only(self, scanner):
        """A single low finding at full confidence: weight = 1*1.0 = 1,
        normalized = (1/10)*100 = 10, score = 100 - 10 = 90."""
        findings = [
            make_finding(
                id_="l1",
                severity=SecurityFindingSeverity.LOW,
                confidence=1.0,
            )
        ]
        score = scanner._calculate_security_score(findings)
        assert score == 90.0


# ---------------------------------------------------------------------------
# More recommendations tests
# ---------------------------------------------------------------------------
class TestGenerateRecommendationsExtended:
    def test_empty(self, scanner):
        recs = scanner._generate_recommendations([])
        assert len(recs) == 1
        assert "No security vulnerabilities" in recs[0]

    def test_critical_present(self, scanner):
        findings = [
            make_finding(id_="c1", severity=SecurityFindingSeverity.CRITICAL),
        ]
        recs = scanner._generate_recommendations(findings)
        assert any("URGENT" in r for r in recs)
        assert any("1 critical" in r for r in recs)

    def test_threshold_based(self, scanner):
        """With medium findings, should get medium priority recommendation."""
        findings = [
            make_finding(id_="m1", severity=SecurityFindingSeverity.MEDIUM),
            make_finding(id_="m2", severity=SecurityFindingSeverity.MEDIUM),
        ]
        recs = scanner._generate_recommendations(findings)
        assert any("Medium Priority" in r for r in recs)
        assert any("2 medium" in r for r in recs)
        # General recommendations always added
        assert any("CI/CD" in r for r in recs)


# ---------------------------------------------------------------------------
# More comprehensive_scan integration tests
# ---------------------------------------------------------------------------
class TestComprehensiveScanExtended:
    async def test_all_scanners_succeed(self, scanner):
        """All scanner methods contribute findings to the report."""
        pattern_f = make_finding(id_="p1", source=SecurityFindingSource.PATTERN)
        osv_f = make_finding(
            id_="o1",
            source=SecurityFindingSource.OSV,
            package_name="requests",
            cve_id="CVE-2024-0001",
        )
        safety_f = make_finding(
            id_="s1",
            source=SecurityFindingSource.SAFETY,
            package_name="django",
            cve_id="CVE-2024-0002",
        )

        scanner._run_pattern_detection = AsyncMock(return_value=[pattern_f])
        scanner._run_osv_scan = AsyncMock(return_value=[osv_f])
        scanner._run_safety_scan = AsyncMock(return_value=[safety_f])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("full-container")

        assert report.total_vulnerabilities == 3
        assert report.by_source["pattern"] == 1
        assert report.by_source["osv"] == 1
        assert report.by_source["safety"] == 1
        assert report.cve_count == 2
        assert report.security_score < 100.0
        assert len(report.recommendations) > 0

    async def test_one_scanner_fails_partial_report(self, scanner):
        """If one scanner adds errors, the report still includes findings from others."""
        pattern_f = make_finding(id_="p1", source=SecurityFindingSource.PATTERN)

        async def pattern_with_error(container_name, errors):
            errors.append("Pattern detection failed: timeout")
            return [pattern_f]

        scanner._run_pattern_detection = AsyncMock(side_effect=pattern_with_error)
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("partial-container")

        assert report.total_vulnerabilities == 1
        assert len(report.errors) == 1
        assert "Pattern detection failed" in report.errors[0]

    async def test_all_scanners_empty(self, scanner):
        """All scanners return nothing: score 100, zero vulns."""
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("empty-container")

        assert report.total_vulnerabilities == 0
        assert report.security_score == 100.0
        assert report.cve_count == 0
        assert report.by_source == {
            "pattern": 0,
            "osv": 0,
            "safety": 0,
            "pip_audit": 0,
            "trivy": 0,
            "grype": 0,
        }

    async def test_duration_set(self, scanner):
        """scan_duration_seconds is populated in the report."""
        scanner._run_pattern_detection = AsyncMock(return_value=[])
        scanner._run_osv_scan = AsyncMock(return_value=[])
        scanner._run_safety_scan = AsyncMock(return_value=[])
        scanner._run_pip_audit_scan = AsyncMock(return_value=[])
        scanner._run_image_scan = AsyncMock(return_value=[])
        scanner._enrich_findings_with_nvd = AsyncMock()

        report = await scanner.comprehensive_scan("timed-container")

        assert report.scan_duration_seconds >= 0.0


# ============================================================================
# File resolution helpers
# ============================================================================


class TestResolveContainerFiles:
    async def test_returns_source_files(self, scanner, tmp_path):
        (tmp_path / "main.py").write_text("x=1")
        (tmp_path / "lib.js").write_text("var x")
        (tmp_path / "readme.md").write_text("# hi")

        result = await scanner._resolve_container_files(str(tmp_path))
        extensions = {p.rsplit(".", 1)[-1] for p in result}
        assert "py" in extensions
        assert "js" in extensions
        assert "md" not in extensions

    async def test_nonexistent_path_returns_empty(self, scanner):
        result = await scanner._resolve_container_files("/does/not/exist")
        assert result == []


class TestFindLockfiles:
    async def test_finds_lockfiles(self, scanner, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "random.txt").write_text("nope")

        result = await scanner._find_lockfiles(str(tmp_path))
        names = {p.rsplit("/", 1)[-1] for p in result}
        assert "requirements.txt" in names
        assert "package-lock.json" in names
        assert "random.txt" not in names

    async def test_nonexistent_path_returns_empty(self, scanner):
        result = await scanner._find_lockfiles("/does/not/exist")
        assert result == []


class TestFindRequirementsFiles:
    async def test_finds_requirements(self, scanner, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        (tmp_path / "requirements-dev.txt").write_text("pytest==7.0")
        (tmp_path / "setup.py").write_text("setup()")

        result = await scanner._find_requirements_files(str(tmp_path))
        names = {p.rsplit("/", 1)[-1] for p in result}
        assert "requirements.txt" in names
        assert "setup.py" not in names

    async def test_nonexistent_path_returns_empty(self, scanner):
        result = await scanner._find_requirements_files("/does/not/exist")
        assert result == []


# ---------------------------------------------------------------------------
# Tests for _run_pip_audit_scan
# ---------------------------------------------------------------------------
from services.pip_audit_scanner import PipAuditVulnerability  # noqa: E402


class TestRunPipAuditScan:
    async def test_pip_audit_not_available_records_error(self, scanner):
        """When pip-audit is unavailable the scan did not run: record an error
        so the report is flagged degraded rather than passing as clean."""
        scanner.pip_audit_scanner.is_pip_audit_available.return_value = False
        errors: list[str] = []

        result = await scanner._run_pip_audit_scan("container", errors)

        assert result == []
        assert any("pip-audit unavailable" in e for e in errors)

    async def test_no_requirements_files_returns_empty(self, scanner):
        """When no requirements files found, return empty."""
        scanner.pip_audit_scanner.is_pip_audit_available.return_value = True
        scanner._find_requirements_files = AsyncMock(return_value=[])
        errors: list[str] = []

        result = await scanner._run_pip_audit_scan("container", errors)

        assert result == []
        assert errors == []

    async def test_success_converts_vulns_to_findings(self, scanner):
        """pip-audit vulnerabilities are converted to SecurityFinding."""
        vuln = PipAuditVulnerability(
            package_name="requests",
            installed_version="2.25.0",
            vulnerability_id="PYSEC-2023-74",
            fix_versions=["2.31.0"],
            description="HTTP redirect vulnerability in requests",
            aliases=["CVE-2023-32681"],
        )
        scanner.pip_audit_scanner.is_pip_audit_available.return_value = True
        scanner._find_requirements_files = AsyncMock(return_value=["/app/requirements.txt"])
        scanner.pip_audit_scanner.scan_requirements = AsyncMock(return_value=[vuln])
        errors: list[str] = []

        result = await scanner._run_pip_audit_scan("container", errors)

        assert len(result) == 1
        assert result[0].source == SecurityFindingSource.PIP_AUDIT
        assert result[0].package_name == "requests"
        assert result[0].cve_id == "CVE-2023-32681"
        assert result[0].fixed_version == "2.31.0"
        assert errors == []

    async def test_per_file_exception_appends_error(self, scanner):
        """Exception scanning a specific file appends an error but continues."""
        scanner.pip_audit_scanner.is_pip_audit_available.return_value = True
        scanner._find_requirements_files = AsyncMock(return_value=["/app/requirements.txt"])
        scanner.pip_audit_scanner.scan_requirements = AsyncMock(
            side_effect=RuntimeError("pip-audit crashed")
        )
        errors: list[str] = []

        result = await scanner._run_pip_audit_scan("container", errors)

        assert result == []
        assert len(errors) == 1
        assert "pip-audit scan failed" in errors[0]

    async def test_top_level_exception_appends_error(self, scanner):
        """Top-level exception in pip-audit scanning appends error."""
        scanner.pip_audit_scanner.is_pip_audit_available.return_value = True
        scanner._find_requirements_files = AsyncMock(side_effect=RuntimeError("find boom"))
        errors: list[str] = []

        result = await scanner._run_pip_audit_scan("container", errors)

        assert result == []
        assert len(errors) == 1
        assert "pip-audit scanning failed" in errors[0]


# ---------------------------------------------------------------------------
# Tests for _run_image_scan
# ---------------------------------------------------------------------------
from models.image_scan_models import ImageVulnerability  # noqa: E402


class TestRunImageScan:
    async def test_no_scanner_available_records_error(self, scanner):
        """When neither trivy nor grype is available the image CVE scan did not
        run: record an error so the report is flagged degraded, not clean."""
        scanner.trivy_scanner.is_trivy_available.return_value = False
        scanner.grype_scanner.is_grype_available.return_value = False
        errors: list[str] = []

        result = await scanner._run_image_scan("my-container", errors)

        assert result == []
        assert any("image" in e.lower() and "skipped" in e.lower() for e in errors)

    async def test_trivy_available_uses_trivy(self, scanner):
        """When trivy is available, use trivy and produce findings."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2023-1234",
            package_name="libssl",
            installed_version="1.1.1",
            fixed_version="1.1.2",
            severity="HIGH",
            title="OpenSSL vulnerability",
            description="A critical flaw in libssl",
        )
        scanner.trivy_scanner.is_trivy_available.return_value = True
        scanner.trivy_scanner.scan_image = AsyncMock(return_value=[vuln])
        errors: list[str] = []

        result = await scanner._run_image_scan("my-container", errors)

        assert len(result) == 1
        assert result[0].source == SecurityFindingSource.TRIVY
        assert result[0].cve_id == "CVE-2023-1234"
        assert result[0].severity == SecurityFindingSeverity.HIGH
        assert result[0].package_name == "libssl"
        assert errors == []

    async def test_trivy_unavailable_grype_fallback(self, scanner):
        """When trivy is unavailable, fall back to grype."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2024-9999",
            package_name="curl",
            installed_version="7.80.0",
            fixed_version="7.88.0",
            severity="MEDIUM",
            title="curl vulnerability",
            description="SSRF in curl",
        )
        scanner.trivy_scanner.is_trivy_available.return_value = False
        scanner.grype_scanner.is_grype_available.return_value = True
        scanner.grype_scanner.scan_image = AsyncMock(return_value=[vuln])
        errors: list[str] = []

        result = await scanner._run_image_scan("my-container", errors)

        assert len(result) == 1
        assert result[0].source == SecurityFindingSource.GRYPE
        assert result[0].cve_id == "CVE-2024-9999"
        assert result[0].severity == SecurityFindingSeverity.MEDIUM
        assert errors == []

    async def test_exception_appends_error(self, scanner):
        """Exception during image scanning appends error and returns empty."""
        scanner.trivy_scanner.is_trivy_available.return_value = True
        scanner.trivy_scanner.scan_image = AsyncMock(side_effect=RuntimeError("trivy crashed"))
        errors: list[str] = []

        result = await scanner._run_image_scan("my-container", errors)

        assert result == []
        assert len(errors) == 1
        assert "Image scanning failed" in errors[0]


# ---------------------------------------------------------------------------
# Tests for _enrich_findings_with_nvd
# ---------------------------------------------------------------------------
from services.nvd_client import NVDCVSSData  # noqa: E402


class TestEnrichFindingsWithNvd:
    async def test_no_cve_ids_is_noop(self, scanner):
        """When no findings have CVE IDs, NVD is never called."""
        findings = [
            make_finding(id_="p1", cve_id=None),
            make_finding(id_="p2", cve_id="PYSEC-123"),  # non-CVE ID
        ]
        errors: list[str] = []

        await scanner._enrich_findings_with_nvd(findings, errors)

        # No NVD client should have been created
        assert scanner.nvd_client is None
        assert errors == []

    async def test_successful_enrichment_populates_cvss(self, scanner):
        """NVD data is applied to matching findings."""
        finding = make_finding(id_="f1", cve_id="CVE-2023-9999")
        findings = [finding]
        errors: list[str] = []

        cvss_data = NVDCVSSData(
            cve_id="CVE-2023-9999",
            cvss_v31_score=8.5,
            cvss_v31_severity="HIGH",
        )
        mock_nvd = AsyncMock()
        mock_nvd.batch_get_cves = AsyncMock(return_value={"CVE-2023-9999": cvss_data})
        mock_nvd.close = AsyncMock()

        with patch("services.unified_security.sources.nvd.NVDClient") as mock_nvd_client_cls:
            with patch("services.unified_security.sources.nvd.get_settings") as mock_settings:
                mock_settings.return_value.nvd_api_key = "test-key"
                mock_nvd_client_cls.return_value = mock_nvd
                scanner.nvd_client = None

                await scanner._enrich_findings_with_nvd(findings, errors)

        assert finding.cvss_score == 8.5
        assert finding.cvss_severity == "HIGH"
        assert errors == []

    async def test_nvd_failure_appends_error_does_not_crash(self, scanner):
        """NVD enrichment failure appends error but does not raise."""
        finding = make_finding(id_="f1", cve_id="CVE-2023-0001")
        errors: list[str] = []

        with patch("services.unified_security.sources.nvd.NVDClient") as mock_nvd_client_cls:
            with patch("services.unified_security.sources.nvd.get_settings") as mock_settings:
                mock_settings.return_value.nvd_api_key = None
                mock_nvd = AsyncMock()
                mock_nvd.batch_get_cves = AsyncMock(side_effect=RuntimeError("NVD API down"))
                mock_nvd.close = AsyncMock()
                mock_nvd_client_cls.return_value = mock_nvd
                scanner.nvd_client = None

                await scanner._enrich_findings_with_nvd([finding], errors)

        assert len(errors) == 1
        assert "NVD enrichment failed" in errors[0]
        # finding should remain unenriched
        assert finding.cvss_score is None

    async def test_finding_without_matching_cve_not_enriched(self, scanner):
        """Findings whose CVE is not returned by NVD stay unenriched."""
        finding = make_finding(id_="f1", cve_id="CVE-2023-0002")
        errors: list[str] = []

        mock_nvd = AsyncMock()
        mock_nvd.batch_get_cves = AsyncMock(return_value={})  # empty dict
        mock_nvd.close = AsyncMock()

        with patch("services.unified_security.sources.nvd.NVDClient") as mock_nvd_client_cls:
            with patch("services.unified_security.sources.nvd.get_settings") as mock_settings:
                mock_settings.return_value.nvd_api_key = None
                mock_nvd_client_cls.return_value = mock_nvd
                scanner.nvd_client = None

                await scanner._enrich_findings_with_nvd([finding], errors)

        assert finding.cvss_score is None
        assert errors == []


# ---------------------------------------------------------------------------
# Tests for _pip_audit_vuln_to_finding
# ---------------------------------------------------------------------------
class TestPipAuditVulnToFinding:
    def test_cve_in_vulnerability_id(self, scanner):
        """CVE directly in vulnerability_id is used as cve_id."""
        vuln = PipAuditVulnerability(
            package_name="pillow",
            installed_version="9.0.0",
            vulnerability_id="CVE-2023-44271",
            fix_versions=["10.0.0"],
            description="Image processing vulnerability",
            aliases=[],
        )
        finding = scanner._pip_audit_vuln_to_finding(vuln)
        assert finding.cve_id == "CVE-2023-44271"
        assert finding.id == "pip_audit_CVE-2023-44271"
        assert finding.source == SecurityFindingSource.PIP_AUDIT
        assert finding.package_name == "pillow"
        assert finding.affected_version == "9.0.0"
        assert finding.fixed_version == "10.0.0"
        assert "10.0.0" in finding.remediation_advice

    def test_cve_in_aliases(self, scanner):
        """CVE extracted from aliases when vulnerability_id is a PYSEC ID."""
        vuln = PipAuditVulnerability(
            package_name="cryptography",
            installed_version="3.0.0",
            vulnerability_id="PYSEC-2023-42",
            fix_versions=["41.0.0"],
            description="Weak key generation",
            aliases=["GHSA-xxxx-yyyy-zzzz", "CVE-2023-23931"],
        )
        finding = scanner._pip_audit_vuln_to_finding(vuln)
        assert finding.cve_id == "CVE-2023-23931"

    def test_no_cve_gives_none(self, scanner):
        """When neither vulnerability_id nor aliases contain a CVE, cve_id is None."""
        vuln = PipAuditVulnerability(
            package_name="mylib",
            installed_version="1.0.0",
            vulnerability_id="PYSEC-2023-100",
            fix_versions=[],
            description="Some vulnerability",
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )
        finding = scanner._pip_audit_vuln_to_finding(vuln)
        assert finding.cve_id is None

    def test_no_fix_versions_generic_advice(self, scanner):
        """When no fix_versions, remediation advice is generic."""
        vuln = PipAuditVulnerability(
            package_name="somelib",
            installed_version="0.5.0",
            vulnerability_id="PYSEC-2023-200",
            fix_versions=[],
            description="",
            aliases=[],
        )
        finding = scanner._pip_audit_vuln_to_finding(vuln)
        assert finding.fixed_version is None
        assert "patched version" in finding.remediation_advice

    def test_severity_is_medium(self, scanner):
        """pip-audit findings default to MEDIUM severity."""
        vuln = PipAuditVulnerability(
            package_name="pkg",
            installed_version="1.0",
            vulnerability_id="PYSEC-2023-1",
            fix_versions=[],
            description="",
            aliases=[],
        )
        finding = scanner._pip_audit_vuln_to_finding(vuln)
        assert finding.severity == SecurityFindingSeverity.MEDIUM
        assert finding.confidence == 0.9


# ---------------------------------------------------------------------------
# Tests for _image_vuln_to_finding
# ---------------------------------------------------------------------------
class TestImageVulnToFinding:
    def test_trivy_source(self, scanner):
        """scanner_name='trivy' produces TRIVY source."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2023-5678",
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1l",
            severity="CRITICAL",
            title="OpenSSL critical flaw",
            description="Remote code execution in OpenSSL",
        )
        finding = scanner._image_vuln_to_finding(vuln, "trivy")
        assert finding.source == SecurityFindingSource.TRIVY
        assert finding.id == "trivy_CVE-2023-5678"
        assert finding.severity == SecurityFindingSeverity.CRITICAL
        assert finding.cve_id == "CVE-2023-5678"
        assert finding.package_name == "openssl"
        assert finding.fixed_version == "1.1.1l"
        assert finding.confidence == 0.95

    def test_grype_source(self, scanner):
        """scanner_name='grype' produces GRYPE source."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2024-1111",
            package_name="zlib",
            installed_version="1.2.11",
            fixed_version="1.2.13",
            severity="HIGH",
            title="zlib heap overflow",
            description="Heap overflow in zlib inflate",
        )
        finding = scanner._image_vuln_to_finding(vuln, "grype")
        assert finding.source == SecurityFindingSource.GRYPE
        assert finding.id == "grype_CVE-2024-1111"
        assert finding.severity == SecurityFindingSeverity.HIGH

    def test_severity_mapping_low(self, scanner):
        """LOW severity maps correctly."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2024-2222",
            package_name="bash",
            installed_version="5.0",
            severity="LOW",
        )
        finding = scanner._image_vuln_to_finding(vuln, "trivy")
        assert finding.severity == SecurityFindingSeverity.LOW

    def test_unknown_severity_defaults_to_medium(self, scanner):
        """Unknown severity strings default to MEDIUM."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2024-3333",
            package_name="curl",
            installed_version="7.80.0",
            severity="UNKNOWN",
        )
        finding = scanner._image_vuln_to_finding(vuln, "trivy")
        assert finding.severity == SecurityFindingSeverity.MEDIUM

    def test_non_cve_vulnerability_id_gives_none_cve_id(self, scanner):
        """Non-CVE vulnerability_id results in cve_id=None."""
        vuln = ImageVulnerability(
            vulnerability_id="GHSA-abcd-1234-efgh",
            package_name="libexpat",
            installed_version="2.4.0",
            severity="MEDIUM",
        )
        finding = scanner._image_vuln_to_finding(vuln, "trivy")
        assert finding.cve_id is None

    def test_no_fixed_version_generic_advice(self, scanner):
        """When fixed_version is None, remediation is generic."""
        vuln = ImageVulnerability(
            vulnerability_id="CVE-2024-4444",
            package_name="libc",
            installed_version="2.31",
            fixed_version=None,
            severity="HIGH",
        )
        finding = scanner._image_vuln_to_finding(vuln, "trivy")
        assert finding.fixed_version is None
        assert "patched version" in finding.remediation_advice


# ---------------------------------------------------------------------------
# Tests for recommendations with pip_audit and image scanner sources
# ---------------------------------------------------------------------------
class TestGenerateRecommendationsPipAuditAndImage:
    def test_pip_audit_source_recommendation(self, scanner):
        """pip_audit findings trigger pip-audit-specific recommendation."""
        findings = [
            make_finding(
                id_="pa1",
                source=SecurityFindingSource.PIP_AUDIT,
                package_name="requests",
            )
        ]
        recs = scanner._generate_recommendations(findings)
        assert any("pip-audit" in r for r in recs)
        assert any("pip-audit --fix" in r for r in recs)

    def test_trivy_source_recommendation(self, scanner):
        """Trivy findings trigger container image recommendation."""
        findings = [
            make_finding(
                id_="t1",
                source=SecurityFindingSource.TRIVY,
                package_name="openssl",
            )
        ]
        recs = scanner._generate_recommendations(findings)
        assert any("Container Image" in r for r in recs)

    def test_grype_source_recommendation(self, scanner):
        """Grype findings trigger container image recommendation."""
        findings = [
            make_finding(
                id_="g1",
                source=SecurityFindingSource.GRYPE,
                package_name="libssl",
            )
        ]
        recs = scanner._generate_recommendations(findings)
        assert any("Container Image" in r for r in recs)


# ---------------------------------------------------------------------------
# Tests for exception branches in file resolution helpers
# ---------------------------------------------------------------------------
class TestFileResolutionExceptionBranches:
    async def test_resolve_container_files_exception_returns_empty(self, scanner):
        """Exception in _resolve_container_files returns []."""
        with patch("services.unified_security.container_files.Path") as mock_path_cls:
            mock_path_cls.return_value.exists.side_effect = OSError("permission denied")
            result = await scanner._resolve_container_files("/some/path")
        assert result == []

    async def test_find_lockfiles_exception_returns_empty(self, scanner):
        """Exception in _find_lockfiles returns []."""
        with patch("services.unified_security.container_files.Path") as mock_path_cls:
            mock_path_cls.return_value.exists.side_effect = OSError("permission denied")
            result = await scanner._find_lockfiles("/some/path")
        assert result == []

    async def test_find_requirements_files_exception_returns_empty(self, scanner):
        """Exception in _find_requirements_files returns []."""
        with patch("services.unified_security.container_files.Path") as mock_path_cls:
            mock_path_cls.return_value.exists.side_effect = OSError("permission denied")
            result = await scanner._find_requirements_files("/some/path")
        assert result == []


# ---------------------------------------------------------------------------
# Tests for get_unified_security_scanner singleton
# ---------------------------------------------------------------------------
import services.unified_security.scanner as uss_module  # noqa: E402
from services.unified_security import get_unified_security_scanner  # noqa: E402


class TestGetUnifiedSecurityScanner:
    def test_returns_instance(self):
        """get_unified_security_scanner returns an UnifiedSecurityScanner."""
        with (
            patch("services.unified_security.scanner.get_security_detector"),
            patch("services.unified_security.scanner.SafetyScanner"),
            patch("services.unified_security.scanner.PipAuditScanner"),
            patch("services.unified_security.scanner.TrivyScanner"),
            patch("services.unified_security.scanner.GrypeScanner"),
        ):
            # Reset the singleton so we exercise the creation path
            uss_module._unified_scanner = None
            instance = get_unified_security_scanner()
            assert isinstance(instance, UnifiedSecurityScanner)

    def test_returns_same_instance_on_repeated_calls(self):
        """Second call returns the same singleton."""
        with (
            patch("services.unified_security.scanner.get_security_detector"),
            patch("services.unified_security.scanner.SafetyScanner"),
            patch("services.unified_security.scanner.PipAuditScanner"),
            patch("services.unified_security.scanner.TrivyScanner"),
            patch("services.unified_security.scanner.GrypeScanner"),
        ):
            uss_module._unified_scanner = None
            first = get_unified_security_scanner()
            second = get_unified_security_scanner()
            assert first is second
