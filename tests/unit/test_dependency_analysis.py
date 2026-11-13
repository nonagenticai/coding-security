"""Tests for DependencyAnalyzer (dependency_analysis.py) risk scoring and reporting."""

import pytest

from models.architecture_models import DependencyRiskReport, Vulnerability
from models.package_manager_models import ExternalPackage
from services.dependency_analysis import DependencyAnalyzer


def make_vuln(
    vuln_id: str = "GHSA-0001",
    severity: str = "HIGH",
    summary: str = "A vulnerability",
    package_name: str = "",
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary=summary,
        details="",
        affected_versions=[],
        fixed_versions=[],
        references=[],
        published_date="",
        modified_date="",
        package_name=package_name,
    )


def make_package(
    name: str = "mypackage",
    version: str = "1.0.0",
    ecosystem: str = "pypi",
    license_: str = "MIT",
    severity: str | None = None,
    current_version: str | None = None,
    latest_version: str | None = None,
) -> ExternalPackage:
    return ExternalPackage(
        name=name,
        version=version,
        ecosystem=ecosystem,
        license=license_,
        severity=severity,
        current_version=current_version,
        latest_version=latest_version,
    )


@pytest.fixture
def analyzer():
    return DependencyAnalyzer()


class TestCalculateRiskScore:
    def test_empty_vulns_returns_zero(self, analyzer):
        assert analyzer.calculate_risk_score([]) == 0.0

    def test_single_critical_returns_10(self, analyzer):
        vulns = [make_vuln(severity="CRITICAL")]
        score = analyzer.calculate_risk_score(vulns)
        # noisy-OR: p_crit=1.0 => 10 * (1 - (1 - 1.0)) = 10.0
        assert score == 10.0

    def test_mixed_severities(self, analyzer):
        vulns = [
            make_vuln(vuln_id="v1", severity="CRITICAL"),
            make_vuln(vuln_id="v2", severity="LOW"),
        ]
        score = analyzer.calculate_risk_score(vulns)
        # noisy-OR: product = (1 - 1.0) * (1 - 0.2) = 0.0
        # score = 10 * (1 - 0.0) = 10.0 — the CRITICAL saturates; the LOW cannot
        # dilute it (old averaging bug gave 6.6).
        assert score == pytest.approx(10.0, abs=0.01)

    def test_unknown_severity_ignored(self, analyzer):
        vulns = [make_vuln(severity="UNKNOWN")]
        score = analyzer.calculate_risk_score(vulns)
        # p_unknown=0.0 => product stays 1.0 => 10 * (1 - 1.0) = 0.0
        assert score == 0.0

    def test_critical_not_diluted_by_lows(self, analyzer):
        """A CRITICAL plus ten LOWs still saturates to 10.0 (no averaging dilution)."""
        vulns = [make_vuln(vuln_id="crit", severity="CRITICAL")]
        vulns += [make_vuln(vuln_id=f"low{i}", severity="LOW") for i in range(10)]
        assert analyzer.calculate_risk_score(vulns) == 10.0

    def test_adding_unknown_does_not_change_score(self, analyzer):
        """UNKNOWN contributes p=0.0, so it never moves the score."""
        high_only = analyzer.calculate_risk_score([make_vuln(severity="HIGH")])
        high_plus_unknown = analyzer.calculate_risk_score(
            [make_vuln(vuln_id="h", severity="HIGH"), make_vuln(vuln_id="u", severity="UNKNOWN")]
        )
        assert high_only == high_plus_unknown

    def test_calculate_risk_score_single_critical_is_exactly_10(self, analyzer):
        """Pins p_crit == 1.0: any single CRITICAL saturates the score to exactly 10.0."""
        assert analyzer.calculate_risk_score([make_vuln(severity="CRITICAL")]) == 10.0


class TestGenerateRiskReport:
    def test_correct_report_structure(self, analyzer):
        packages = [make_package(name="django")]
        vulns = [make_vuln(summary="Critical RCE in django", package_name="django")]
        report = analyzer.generate_risk_report("test-codebase", packages, vulns)

        assert isinstance(report, DependencyRiskReport)
        assert report.codebase_id == "test-codebase"
        assert report.risk_score > 0
        assert report.summary.total_packages == 1
        assert report.summary.total_vulnerabilities == 1
        assert report.summary.vulnerable_packages == 1

    def test_empty_codebase_id_raises(self, analyzer):
        with pytest.raises(ValueError, match="Codebase ID cannot be empty"):
            analyzer.generate_risk_report("  ", [], [])

    def test_no_vulns_zero_risk(self, analyzer):
        packages = [make_package()]
        report = analyzer.generate_risk_report("codebase", packages, [])
        assert report.risk_score == 0.0


class TestGenerateSummary:
    def test_severity_counts(self, analyzer):
        vulns = [
            make_vuln(vuln_id="v1", severity="CRITICAL"),
            make_vuln(vuln_id="v2", severity="HIGH"),
            make_vuln(vuln_id="v3", severity="HIGH"),
            make_vuln(vuln_id="v4", severity="LOW"),
        ]
        summary = analyzer.generate_summary([], vulns)
        assert summary.critical_vulnerabilities == 1
        assert summary.high_vulnerabilities == 2
        assert summary.low_vulnerabilities == 1
        assert summary.moderate_vulnerabilities == 0
        assert summary.total_vulnerabilities == 4

    def test_ecosystem_breakdown(self, analyzer):
        packages = [
            make_package(name="pkg1", ecosystem="pypi"),
            make_package(name="pkg2", ecosystem="npm"),
            make_package(name="pkg3", ecosystem="pypi"),
        ]
        breakdown = analyzer.get_ecosystem_breakdown(packages)
        assert breakdown == {"pypi": 2, "npm": 1}


class TestGenerateRiskReportExtended:
    """Extended tests for generate_risk_report covering all severity types and edge cases."""

    def test_generate_risk_report_all_severities(self, analyzer):
        """Report correctly accounts for CRITICAL, HIGH, MODERATE, and LOW vulns."""
        packages = [make_package(name="django")]
        vulns = [
            make_vuln(
                vuln_id="v1",
                severity="CRITICAL",
                summary="critical in django",
                package_name="django",
            ),
            make_vuln(
                vuln_id="v2", severity="HIGH", summary="high in django", package_name="django"
            ),
            make_vuln(
                vuln_id="v3",
                severity="MODERATE",
                summary="moderate in django",
                package_name="django",
            ),
            make_vuln(vuln_id="v4", severity="LOW", summary="low in django", package_name="django"),
        ]
        report = analyzer.generate_risk_report("codebase-1", packages, vulns)

        assert report.summary.critical_vulnerabilities == 1
        assert report.summary.high_vulnerabilities == 1
        assert report.summary.moderate_vulnerabilities == 1
        assert report.summary.low_vulnerabilities == 1
        assert report.summary.total_vulnerabilities == 4
        assert report.risk_score > 0

    def test_generate_risk_report_empty_vulnerabilities(self, analyzer):
        """Report with packages but zero vulnerabilities yields risk_score 0."""
        packages = [make_package(name="pkg1"), make_package(name="pkg2")]
        report = analyzer.generate_risk_report("codebase-2", packages, [])

        assert report.risk_score == 0.0
        assert report.summary.total_packages == 2
        assert report.summary.total_vulnerabilities == 0
        assert report.summary.critical_vulnerabilities == 0

    def test_generate_risk_report_empty_codebase_id_raises(self, analyzer):
        """Empty string (after strip) raises ValueError."""
        with pytest.raises(ValueError, match="Codebase ID cannot be empty"):
            analyzer.generate_risk_report("", [], [])


class TestCalculateRiskScoreExtended:
    """Extended risk score calculation tests."""

    def test_calculate_risk_score_no_vulns(self, analyzer):
        """Empty vulnerability list returns 0.0."""
        assert analyzer.calculate_risk_score([]) == 0.0

    def test_low_volume_accumulates_bounded(self, analyzer):
        """Many LOWs accumulate under noisy-OR toward (never past) 10.0."""
        # 11 vulns all LOW (p=0.2): product = 0.8**11 = 0.0859
        # score = round(10 * (1 - 0.0859), 1) = 9.1
        vulns = [make_vuln(vuln_id=f"v{i}", severity="LOW") for i in range(11)]
        score = analyzer.calculate_risk_score(vulns)
        assert score == pytest.approx(9.1, abs=0.01)

    def test_risk_score_floor_is_zero(self, analyzer):
        """All UNKNOWN severity vulns result in score 0.0 (weight is 0)."""
        vulns = [make_vuln(vuln_id=f"v{i}", severity="UNKNOWN") for i in range(5)]
        score = analyzer.calculate_risk_score(vulns)
        assert score == 0.0

    def test_risk_score_cap_is_100(self, analyzer):
        """Score is capped at 10.0 even with many critical vulnerabilities."""
        # 20 CRITICAL: product = (1 - 1.0)**20 = 0.0 => 10 * (1 - 0.0) = 10.0
        vulns = [make_vuln(vuln_id=f"v{i}", severity="CRITICAL") for i in range(20)]
        score = analyzer.calculate_risk_score(vulns)
        assert score == 10.0


class TestGenerateSummaryExtended:
    """Extended summary generation tests."""

    def test_generate_summary_ecosystem_counts(self, analyzer):
        """get_ecosystem_breakdown correctly counts per-ecosystem packages."""
        packages = [
            make_package(name="a", ecosystem="pypi"),
            make_package(name="b", ecosystem="pypi"),
            make_package(name="c", ecosystem="npm"),
            make_package(name="d", ecosystem="maven"),
        ]
        breakdown = analyzer.get_ecosystem_breakdown(packages)
        assert breakdown == {"pypi": 2, "npm": 1, "maven": 1}


class TestCategorizeVulnerabilities:
    """Tests for categorize_vulnerabilities_by_severity."""

    def test_categorize_vulnerabilities_all_severities(self, analyzer):
        """All four severity levels are counted correctly."""
        vulns = [
            make_vuln(vuln_id="v1", severity="CRITICAL"),
            make_vuln(vuln_id="v2", severity="CRITICAL"),
            make_vuln(vuln_id="v3", severity="HIGH"),
            make_vuln(vuln_id="v4", severity="MODERATE"),
            make_vuln(vuln_id="v5", severity="LOW"),
            make_vuln(vuln_id="v6", severity="LOW"),
            make_vuln(vuln_id="v7", severity="LOW"),
        ]
        cats = analyzer.categorize_vulnerabilities_by_severity(vulns)
        assert cats["critical_vulnerabilities"] == 2
        assert cats["high_vulnerabilities"] == 1
        assert cats["moderate_vulnerabilities"] == 1
        assert cats["low_vulnerabilities"] == 3


class TestAnalyzeDependencyHealth:
    """Tests for analyze_dependency_health."""

    def test_analyze_dependency_health_no_packages(self, analyzer):
        """Empty package list returns perfect health score."""
        result = analyzer.analyze_dependency_health([])
        assert result["total_packages"] == 0
        assert result["health_score"] == 10.0

    def test_analyze_dependency_health_mixed(self, analyzer):
        """Mixed outdated, vulnerable, and unlicensed packages lower health score."""
        packages = [
            # Outdated (current != latest)
            make_package(
                name="pkg-outdated",
                current_version="1.0.0",
                latest_version="2.0.0",
                license_="MIT",
            ),
            # Vulnerable (severity HIGH)
            make_package(
                name="pkg-vuln",
                severity="HIGH",
                license_="MIT",
            ),
            # Unlicensed (license is "unknown")
            make_package(
                name="pkg-unlicensed",
                license_="unknown",
            ),
            # Healthy package
            make_package(
                name="pkg-ok",
                license_="MIT",
            ),
        ]
        result = analyzer.analyze_dependency_health(packages)

        assert result["total_packages"] == 4
        assert result["outdated_packages"] == 1
        assert result["packages_with_vulnerabilities"] == 1
        assert result["unlicensed_packages"] == 1
        # health_score = 10.0 - (1/4)*3.0 - (1/4)*5.0 - (1/4)*2.0 = 10.0 - 0.75 - 1.25 - 0.5 = 7.5
        assert result["health_score"] == 7.5
        assert result["outdated_percentage"] == 25.0
        assert result["vulnerable_percentage"] == 25.0
        assert result["unlicensed_percentage"] == 25.0


class TestIdentifyHighRiskPackages:
    """Tests for identify_high_risk_packages."""

    def test_no_high_risk(self, analyzer):
        """Safe packages with no vulns return empty list."""
        packages = [make_package(name="safe-pkg", license_="MIT")]
        result = analyzer.identify_high_risk_packages(packages, [])
        assert result == []

    def test_critical_vuln_flagged(self, analyzer):
        """Package with critical vulnerability is identified as high risk."""
        packages = [make_package(name="django", version="2.2.0")]
        vulns = [
            make_vuln(
                vuln_id="django-vuln",
                severity="CRITICAL",
                summary="critical in django",
                package_name="django",
            )
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        assert len(result) >= 1
        assert result[0]["name"] == "django"
        assert result[0]["risk_score"] >= 3.0

    def test_outdated_and_unlicensed(self, analyzer):
        """Outdated + unlicensed package exceeds threshold."""
        packages = [
            make_package(
                name="old-pkg",
                current_version="1.0.0",
                latest_version="2.0.0",
                license_="unknown",
            ),
        ]
        # No vulns but risk_score = 1.0 (outdated) + 0.5 (unlicensed) = 1.5, under threshold
        result = analyzer.identify_high_risk_packages(packages, [])
        # 1.5 < 2.0, so not flagged
        assert len(result) == 0

    def test_multiple_vulns_accumulate(self, analyzer):
        """Multiple vulns on same package accumulate risk."""
        packages = [make_package(name="django", version="2.2.0")]
        vulns = [
            make_vuln(
                vuln_id="django-v1",
                severity="CRITICAL",
                summary="rce in django",
                package_name="django",
            ),
            make_vuln(
                vuln_id="django-v2", severity="HIGH", summary="xss in django", package_name="django"
            ),
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        assert len(result) >= 1
        assert result[0]["risk_score"] >= 5.0  # 3.0 + 2.0

    def test_sorted_by_risk_desc(self, analyzer):
        """Results sorted by risk_score descending."""
        packages = [
            make_package(name="django", version="2.2.0"),
            make_package(name="flask", version="1.0.0"),
        ]
        vulns = [
            make_vuln(
                vuln_id="django-crit",
                severity="CRITICAL",
                summary="in django",
                package_name="django",
            ),
            make_vuln(
                vuln_id="flask-high", severity="HIGH", summary="in flask", package_name="flask"
            ),
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        if len(result) >= 2:
            assert result[0]["risk_score"] >= result[1]["risk_score"]

    def test_max_20_results(self, analyzer):
        """At most 20 high-risk packages returned."""
        packages = [
            make_package(
                name=f"pkg{i}",
                current_version="1.0.0",
                latest_version="2.0.0",
                license_="unknown",
                severity="HIGH",
            )
            for i in range(25)
        ]
        vulns = [
            make_vuln(
                vuln_id=f"pkg{i}-vuln",
                severity="HIGH",
                summary=f"in pkg{i}",
                package_name=f"pkg{i}",
            )
            for i in range(25)
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        assert len(result) <= 20

    def test_moderate_only_package_surfaces(self, analyzer):
        """A package with only MODERATE vulns now scores (5 * 1.0 = 5.0) and lists."""
        packages = [make_package(name="jinja2", version="3.0.0")]
        vulns = [
            make_vuln(
                vuln_id=f"jinja-{i}",
                severity="MODERATE",
                summary="moderate in jinja2",
                package_name="jinja2",
            )
            for i in range(5)
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        assert len(result) == 1
        assert result[0]["name"] == "jinja2"
        assert result[0]["risk_score"] == 5.0
        assert result[0]["vulnerability_count"] == 5

    def test_severity_breakdown_emitted(self, analyzer):
        """Emitted dict carries a per-severity breakdown across all four buckets."""
        packages = [make_package(name="django", version="2.2.0")]
        vulns = [
            make_vuln(vuln_id="c", severity="CRITICAL", package_name="django"),
            make_vuln(vuln_id="h", severity="HIGH", package_name="django"),
            make_vuln(vuln_id="m", severity="MODERATE", package_name="django"),
            make_vuln(vuln_id="l1", severity="LOW", package_name="django"),
            make_vuln(vuln_id="l2", severity="LOW", package_name="django"),
        ]
        result = analyzer.identify_high_risk_packages(packages, vulns)
        assert len(result) == 1
        assert result[0]["severity_breakdown"] == {
            "critical": 1,
            "high": 1,
            "moderate": 1,
            "low": 2,
            "unknown": 0,
        }


class TestCorrelationExactIdentity:
    """Bug 1: correlate vuln↔package on exact ``package_name``, not free-text substrings."""

    def test_short_names_do_not_substring_false_match(self, analyzer):
        """Short real package names (os/re/io) must not match unrelated CVE text."""
        packages = [make_package(name="os"), make_package(name="re"), make_package(name="io")]
        # A django CVE whose id/summary contain "os", "re", "io" as substrings —
        # the old substring correlation attributed it to all three.
        vuln = make_vuln(
            vuln_id="GHSA-remote-position",
            severity="CRITICAL",
            summary="Remote position in a version string",
            package_name="django",
        )
        assert analyzer._get_vulnerable_packages_count(packages, [vuln]) == 0
        high_risk = analyzer.identify_high_risk_packages(packages, [vuln])
        assert all(pkg["name"] not in {"os", "re", "io"} for pkg in high_risk)

    def test_exact_package_name_matches(self, analyzer):
        """The owning package (by stamped package_name) is correctly attributed."""
        packages = [make_package(name="django", version="2.2.0")]
        vuln = make_vuln(severity="CRITICAL", summary="unrelated text", package_name="django")
        assert analyzer._get_vulnerable_packages_count(packages, [vuln]) == 1
        high_risk = analyzer.identify_high_risk_packages(packages, [vuln])
        assert high_risk[0]["name"] == "django"

    def test_empty_package_name_never_matches(self, analyzer):
        """A vuln with no stamped package_name is attributed to no package."""
        packages = [make_package(name="django")]
        vuln = make_vuln(severity="CRITICAL", summary="critical in django", package_name="")
        assert analyzer._get_vulnerable_packages_count(packages, [vuln]) == 0


class TestSeverityVocabNormalization:
    """Bug 2: MEDIUM and mixed-case severities normalize to the canonical vocab."""

    def test_medium_scores_as_moderate(self, analyzer):
        """MEDIUM (industry standard) weights like MODERATE (4.0), not 0.0."""
        medium = analyzer.calculate_risk_score([make_vuln(severity="MEDIUM")])
        moderate = analyzer.calculate_risk_score([make_vuln(severity="MODERATE")])
        assert medium == moderate
        assert medium > 0.0

    def test_mixed_case_severity_counted(self, analyzer):
        vulns = [
            make_vuln(vuln_id="v1", severity="Medium"),
            make_vuln(vuln_id="v2", severity="high"),
            make_vuln(vuln_id="v3", severity="Critical"),
        ]
        summary = analyzer.generate_summary([], vulns)
        assert summary.moderate_vulnerabilities == 1
        assert summary.high_vulnerabilities == 1
        assert summary.critical_vulnerabilities == 1
        assert summary.total_vulnerabilities == 3

    def test_categorize_counts_medium_and_case(self, analyzer):
        vulns = [
            make_vuln(vuln_id="v1", severity="MEDIUM"),
            make_vuln(vuln_id="v2", severity="medium"),
            make_vuln(vuln_id="v3", severity="Low"),
        ]
        cats = analyzer.categorize_vulnerabilities_by_severity(vulns)
        assert cats["moderate_vulnerabilities"] == 2
        assert cats["low_vulnerabilities"] == 1

    def test_unknown_severity_still_floors_to_zero(self, analyzer):
        """The UNKNOWN→0.0 floor is preserved; unrecognized vocab is not coerced upward."""
        assert analyzer.calculate_risk_score([make_vuln(severity="BOGUS")]) == 0.0
        assert analyzer.calculate_risk_score([make_vuln(severity="UNKNOWN")]) == 0.0

    def test_health_counts_medium_as_vulnerable(self, analyzer):
        packages = [make_package(name="p", severity="MEDIUM")]
        result = analyzer.analyze_dependency_health(packages)
        assert result["packages_with_vulnerabilities"] == 1
