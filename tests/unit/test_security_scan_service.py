"""Tests for SecurityScanService (security_scan_service.py)."""

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from models.container_models import ContainerInfo, ContainerStatus
from models.security_api_models import (
    ContainerSecurityReport,
    ContainerSecurityScanRequest,
    FileSecurityResult,
    ScanFindingViolation,
    SecurityScanResult,
    SeverityLevel,
)
from models.security_models import SecurityLevel
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from services.security_scan_service import SecurityScanService


def make_container_info(
    name: str = "test-container",
    codebase_path: str = "/tmp/test-repo",
) -> ContainerInfo:
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path=codebase_path,
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def make_scan_request(container_name: str = "test-container") -> ContainerSecurityScanRequest:
    return ContainerSecurityScanRequest(
        container_name=container_name,
    )


def make_violation(
    vuln_type: str = "sql_injection",
    severity: SecurityLevel = SecurityLevel.HIGH,
    line_number: int = 42,
    engine: str = "pattern",
) -> ScanFindingViolation:
    return ScanFindingViolation.model_validate(
        {
            "engine": engine,
            "type": vuln_type,
            "severity": severity,
            "line_number": line_number,
            "pattern_matched": "test-pattern",
            "description": "Test vulnerability found",
            "suggested_fix": "Fix the code",
        }
    )


def make_file_result(
    file_path: str = "app/main.py",
    language: str = "python",
    vuln_count: int = 1,
    highest_severity: str = "high",
    risk_score: float = 7.0,
    violations: list[ScanFindingViolation] | None = None,
) -> FileSecurityResult:
    if violations is None:
        violations = [make_violation()] if vuln_count > 0 else []
    return FileSecurityResult(
        file_path=file_path,
        language=language,
        vulnerabilities_found=vuln_count,
        highest_severity=highest_severity,
        violations=violations,
        risk_score=risk_score,
    )


def make_scan_result(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    info: int = 0,
    risk_score: float = 0.0,
    grade: str = "A",
    file_results: list[FileSecurityResult] | None = None,
) -> SecurityScanResult:
    total = critical + high + medium + low + info
    return SecurityScanResult(
        container_name="test-container",
        scan_timestamp=datetime.now(UTC),
        scan_duration_seconds=1.0,
        total_files_scanned=10,
        total_vulnerabilities=total,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        info_count=info,
        overall_risk_score=risk_score,
        security_grade=grade,
        file_results=file_results or [],
        vulnerability_summary={},
        affected_files=["app/main.py"] if total > 0 else [],
    )


def make_vuln_match(
    vuln_type: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    file_path: str = "/tmp/test-repo/app/main.py",
    language: str = "python",
    line_start: int = 10,
    line_end: int = 12,
    pattern_id: str = "test-pattern",
    description: str = "Test vulnerability",
    remediation_advice: str = "Fix the code",
    engine: str = "pattern",
) -> VulnerabilityMatch:
    return VulnerabilityMatch(
        engine=engine,
        id="vuln-001",
        vulnerability_type=vuln_type,
        severity=severity,
        confidence=VulnerabilityConfidence.HIGH,
        file_path=file_path,
        language=language,
        line_start=line_start,
        line_end=line_end,
        pattern_id=pattern_id,
        description=description,
        remediation_advice=remediation_advice,
    )


@dataclass
class MockAnalysisResult:
    """Lightweight stand-in for SecurityAnalysisResult."""

    total_files_analyzed: int = 5
    total_vulnerabilities_found: int = 0
    analysis_time_seconds: float = 0.5
    vulnerabilities_by_type: dict = field(default_factory=dict)
    vulnerabilities_by_severity: dict = field(default_factory=dict)
    overall_risk_score: float = 0.0
    files_failed_to_parse: int = 0
    scan_degraded: bool = False
    degraded_reasons: list = field(default_factory=list)
    engine_status: dict = field(default_factory=dict)
    base_images: list = field(default_factory=list)


@pytest.fixture
def service():
    with patch("services.security_scan_service.get_security_detector") as mock_det:
        svc = SecurityScanService()
        svc.detector = mock_det.return_value
        yield svc


NO_FINDINGS = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

ALL_ENGINES_OK = {
    "pattern": {"status": "ok", "reason": None},
    "bandit": {"status": "ok", "reason": None},
    "semgrep": {"status": "ok", "reason": None},
    "detect-secrets": {"status": "ok", "reason": None},
    "trivy-iac": {"status": "ok", "reason": None},
    "trivy-image": {"status": "ok", "reason": None},
}


class TestCalculateSecurityGrade:
    # Risk-threshold behaviour is only reached when coverage is non-zero, the
    # scan is not degraded, and no finding sits above the risk-based ladder.
    def test_zero_risk_grade_a(self, service):
        assert service._calculate_security_grade(0.0, 10, False, NO_FINDINGS) == "A"

    def test_ten_risk_grade_a(self, service):
        assert service._calculate_security_grade(10.0, 10, False, NO_FINDINGS) == "A"

    def test_low_risk_grade_b(self, service):
        assert service._calculate_security_grade(20.0, 10, False, NO_FINDINGS) == "B"

    def test_medium_risk_grade_c(self, service):
        assert service._calculate_security_grade(40.0, 10, False, NO_FINDINGS) == "C"

    def test_high_risk_grade_d(self, service):
        assert service._calculate_security_grade(60.0, 10, False, NO_FINDINGS) == "D"

    def test_very_high_risk_grade_f(self, service):
        assert service._calculate_security_grade(100.0, 10, False, NO_FINDINGS) == "F"

    def test_zero_files_never_grades_a(self, service):
        """The fake-green killer: risk_score 0 but zero files scanned → F, never A."""
        assert service._calculate_security_grade(0.0, 0, False, NO_FINDINGS) == "F"

    def test_degraded_never_grades_a(self, service):
        """A degraded scan with a clean risk score must grade F, not A."""
        assert service._calculate_security_grade(0.0, 10, True, NO_FINDINGS) == "F"

    def test_coverage_gate_beats_low_risk(self, service):
        """Coverage gate is applied BEFORE the risk thresholds."""
        assert service._calculate_security_grade(5.0, 0, True, NO_FINDINGS) == "F"

    # Severity floor: a per-file risk average must never bury a real finding.
    def test_one_critical_grades_f_even_at_zero_risk(self, service):
        """The openplanner case: 5 criticals diluted to 0.98/100 must not grade A."""
        counts = {**NO_FINDINGS, "critical": 5}
        assert service._calculate_security_grade(0.98, 994, False, counts) == "F"

    def test_one_high_caps_grade_at_d_even_at_zero_risk(self, service):
        counts = {**NO_FINDINGS, "high": 1}
        assert service._calculate_security_grade(0.0, 10, False, counts) == "D"

    def test_floor_never_improves_a_worse_ladder_grade(self, service):
        """A high finding caps at D but must not lift an F back to D."""
        counts = {**NO_FINDINGS, "high": 1}
        assert service._calculate_security_grade(100.0, 10, False, counts) == "F"

    def test_medium_findings_keep_the_risk_ladder(self, service):
        counts = {**NO_FINDINGS, "medium": 10}
        assert service._calculate_security_grade(20.0, 10, False, counts) == "B"

    def test_finding_grade_ignores_coverage(self, service):
        """finding_grade answers "how bad were the findings", not "was coverage complete"."""
        counts = {**NO_FINDINGS, "high": 1}
        assert service._calculate_finding_grade(counts, 0.0) == "D"


class TestAssembleGrades:
    """Per-area grades are assembled from the findings of each engine group."""

    async def test_mixed_result_separates_code_and_base_image_grades(self, service):
        code_high = make_vuln_match(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            engine="pattern",
            file_path="/tmp/test-repo/app/main.py",
        )
        image_critical = make_vuln_match(
            vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            severity=VulnerabilitySeverity.CRITICAL,
            engine="trivy-image",
            file_path="/tmp/test-repo/Dockerfile",
            language="dockerfile",
            line_start=1,
            line_end=1,
        )
        analysis = MockAnalysisResult(
            total_files_analyzed=994,
            total_vulnerabilities_found=2,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [code_high],
                VulnerabilityType.HARDCODED_CREDENTIALS: [image_critical],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.HIGH: [code_high],
                VulnerabilitySeverity.CRITICAL: [image_critical],
            },
            overall_risk_score=0.98,
            engine_status=dict(ALL_ENGINES_OK),
        )

        result = await service._assemble_scan_result(
            analysis, make_container_info(), datetime.now(UTC)
        )

        assert result.finding_grade == "F"
        assert result.code_grade == "D"  # high in the code area caps at D
        assert result.base_image_grade == "F"  # critical in the image area
        assert result.security_grade == "F"
        assert result.scan_degraded is False

    async def test_unmeasured_area_fails_closed(self, service):
        """An unresolved area must never read as clean, even with no findings."""
        engine_status = dict(ALL_ENGINES_OK)
        engine_status["trivy-image"] = {
            "status": "degraded",
            "reason": "base image not resolvable",
        }
        analysis = MockAnalysisResult(
            total_files_analyzed=10,
            overall_risk_score=0.0,
            scan_degraded=True,
            degraded_reasons=["base image not resolvable"],
            engine_status=engine_status,
        )

        result = await service._assemble_scan_result(
            analysis, make_container_info(), datetime.now(UTC)
        )

        assert result.code_grade == "A"  # code engines all completed
        assert result.base_image_grade == "F"  # image area unmeasured
        assert result.security_grade == "F"  # coverage gate still wins

    async def test_incomplete_fetch_fails_every_area_closed(self, service):
        """An unknown file set is unmeasured in every area, not just in summary.

        Measured on the openplanner branch scan (2026-11-05): 823 of ~990 files
        fetched, no Dockerfile in the set, every engine "ok". The runner set
        ``scan_degraded`` AFTER assembly, so the payload said degraded=true while
        security_grade was D and base_image_grade was A — a clean grade over
        files that were never fetched.
        """
        analysis = MockAnalysisResult(
            total_files_analyzed=823,
            overall_risk_score=0.12,
            engine_status=dict(ALL_ENGINES_OK),
        )

        result = await service._assemble_scan_result(
            analysis,
            make_container_info(),
            datetime.now(UTC),
            force_degraded=True,
        )

        assert result.scan_degraded is True
        assert result.security_grade == "F"
        assert result.code_grade == "F"
        assert result.base_image_grade == "F"

    @staticmethod
    def _image_match(cve: str, package: str, references: list[str]):
        match = make_vuln_match(
            vuln_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=VulnerabilitySeverity.HIGH,
            engine="trivy-image",
            file_path="/tmp/test-repo/Dockerfile",
            language="dockerfile",
            line_start=1,
            line_end=1,
            pattern_id=cve,
        )
        match.package_name = package
        match.installed_version = "2.6.1"
        match.fixed_version = "2.6.2"
        match.fix_available = True
        match.image_ref = "python:3.12-slim"
        match.references = list(references)
        return match

    async def test_cve_summary_and_per_file_ids_from_base_image_findings(self, service):
        """cve_count/cve_references and FileSecurityResult.cve_ids are filled
        from trivy-image findings, deduped across packages, and only for
        CVE-shaped ids."""
        apt = self._image_match("CVE-2026-109518", "apt", ["https://avd/109518"])
        bash = self._image_match("CVE-2026-109518", "bash", ["https://nvd/109518"])
        libssl = self._image_match("CVE-2011-3374", "libssl", [])
        advisory = self._image_match("GHSA-aaaa-bbbb-cccc", "curl", [])
        code_high = make_vuln_match(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            engine="pattern",
            file_path="/tmp/test-repo/app/main.py",
        )
        analysis = MockAnalysisResult(
            total_files_analyzed=10,
            total_vulnerabilities_found=5,
            vulnerabilities_by_type={
                VulnerabilityType.VULNERABLE_DEPENDENCY: [apt, bash, libssl, advisory],
                VulnerabilityType.SQL_INJECTION: [code_high],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.HIGH: [apt, bash, libssl, advisory, code_high],
            },
            overall_risk_score=7.5,
            engine_status=dict(ALL_ENGINES_OK),
        )

        result = await service._assemble_scan_result(
            analysis, make_container_info(), datetime.now(UTC)
        )

        # Two distinct CVEs; the GHSA advisory is not a CVE id.
        assert result.cve_count == 2
        by_id = {ref.cve_id: ref for ref in result.cve_references}
        assert set(by_id) == {"CVE-2026-109518", "CVE-2011-3374"}
        # Occurrences of one CVE across packages union their references.
        assert by_id["CVE-2026-109518"].references == [
            "https://avd/109518",
            "https://nvd/109518",
        ]
        assert by_id["CVE-2026-109518"].severity == SeverityLevel.HIGH

        dockerfile = next(f for f in result.file_results if f.file_path == "Dockerfile")
        assert dockerfile.cve_ids == ["CVE-2011-3374", "CVE-2026-109518"]
        apt_violation = next(
            v
            for v in dockerfile.violations
            if v.pattern_matched == "CVE-2026-109518" and v.package_name == "apt"
        )
        assert apt_violation.installed_version == "2.6.1"
        assert apt_violation.fixed_version == "2.6.2"
        assert apt_violation.fix_available is True
        assert apt_violation.image_ref == "python:3.12-slim"

        code_file = next(f for f in result.file_results if f.file_path == "app/main.py")
        assert code_file.cve_ids == []
        code_violation = code_file.violations[0]
        assert code_violation.package_name is None
        assert code_violation.fix_available is None

    async def test_base_image_coverage_is_machine_readable(self, service):
        """The coverage gaps are rows with statuses, not prose in degraded_reasons."""
        analysis = MockAnalysisResult(
            total_files_analyzed=10,
            overall_risk_score=0.0,
            base_images=[
                {
                    "ref": "python:3.12-slim",
                    "dockerfile": "/tmp/test-repo/Dockerfile",
                    "line": 2,
                    "status": "scanned",
                    "error": None,
                },
                {
                    "ref": "caddy:2.11.7-alpine",
                    "dockerfile": "/tmp/test-repo/web/Dockerfile",
                    "line": 1,
                    "status": "unresolved",
                    "error": "not in the registry mirror",
                },
            ],
            engine_status=dict(ALL_ENGINES_OK),
        )

        result = await service._assemble_scan_result(
            analysis, make_container_info(), datetime.now(UTC)
        )

        assert [
            (image.ref, image.dockerfile, image.line, image.status) for image in result.base_images
        ] == [
            ("python:3.12-slim", "Dockerfile", 2, "scanned"),
            ("caddy:2.11.7-alpine", "web/Dockerfile", 1, "unresolved"),
        ]
        assert result.base_images[1].error == "not in the registry mirror"
        # An unresolved image forces the scan degraded even when the analysis
        # result itself did not record a degradation.
        assert result.scan_degraded is True
        assert "base image coverage incomplete" in result.degraded_reasons

    async def test_degraded_code_engine_fails_code_grade_closed(self, service):
        engine_status = dict(ALL_ENGINES_OK)
        engine_status["semgrep"] = {"status": "failed", "reason": "tool missing"}
        analysis = MockAnalysisResult(
            total_files_analyzed=10,
            overall_risk_score=0.0,
            scan_degraded=True,
            degraded_reasons=["engine semgrep is not installed"],
            engine_status=engine_status,
        )

        result = await service._assemble_scan_result(
            analysis, make_container_info(), datetime.now(UTC)
        )

        assert result.code_grade == "F"
        assert result.base_image_grade == "A"


class TestIdentifySecurityHotspots:
    def test_files_with_3_plus_vulns_flagged(self, service):
        file_results = [
            make_file_result(
                file_path="hotspot.py",
                vuln_count=4,
                violations=[make_violation() for _ in range(4)],
            ),
            make_file_result(file_path="clean.py", vuln_count=1),
        ]
        scan_result = make_scan_result(
            high=5, risk_score=50.0, grade="C", file_results=file_results
        )
        hotspots = service._identify_security_hotspots(scan_result)
        assert len(hotspots) == 1
        assert hotspots[0].file_path == "hotspot.py"
        assert hotspots[0].vulnerability_count == 4

    def test_no_hotspots_when_few_vulns(self, service):
        file_results = [
            make_file_result(file_path="a.py", vuln_count=2),
            make_file_result(file_path="b.py", vuln_count=1),
        ]
        scan_result = make_scan_result(
            high=3, risk_score=20.0, grade="B", file_results=file_results
        )
        hotspots = service._identify_security_hotspots(scan_result)
        assert len(hotspots) == 0


class TestGenerateRecommendations:
    def test_critical_vulns_urgent(self, service):
        scan_result = make_scan_result(critical=2, risk_score=80.0, grade="F")
        recs = service._generate_recommendations(scan_result)
        assert any("URGENT" in r for r in recs)

    def test_high_vulns_priority(self, service):
        scan_result = make_scan_result(high=3, risk_score=40.0, grade="C")
        recs = service._generate_recommendations(scan_result)
        assert any("High Priority" in r for r in recs)

    def test_no_vulns_positive(self, service):
        scan_result = make_scan_result(risk_score=0.0, grade="A")
        recs = service._generate_recommendations(scan_result)
        assert any("Excellent" in r or "No vulnerabilities" in r for r in recs)

    def test_poor_grade_review_recommendation(self, service):
        scan_result = make_scan_result(high=5, risk_score=60.0, grade="D")
        recs = service._generate_recommendations(scan_result)
        assert any("Security Grade D" in r for r in recs)


class TestGenerateSecurityReport:
    async def test_report_structure(self, service):
        container_info = make_container_info()
        file_results = [
            make_file_result(
                file_path="a.py",
                vuln_count=2,
                violations=[
                    make_violation(vuln_type="sql_injection", severity=SecurityLevel.CRITICAL),
                    make_violation(vuln_type="xss", severity=SecurityLevel.HIGH),
                ],
            ),
        ]
        scan_result = make_scan_result(
            critical=1,
            high=1,
            risk_score=35.0,
            grade="C",
            file_results=file_results,
        )
        scan_result.affected_files = ["a.py"]

        report = await service.generate_security_report(container_info, scan_result)

        assert isinstance(report, ContainerSecurityReport)
        assert report.container_name == "test-container"
        assert report.severity_distribution.critical == 1
        assert report.severity_distribution.high == 1
        assert report.severity_distribution.medium == 0
        assert report.severity_distribution.low == 0
        assert report.affected_files_count == 1
        assert report.security_grade == "C"
        assert report.security_score >= 0
        # Report should include recommendations
        assert isinstance(report.recommendations, list)
        assert len(report.recommendations) > 0


# ============================================================================
# _resolve_container_file_paths
# ============================================================================


class TestResolveContainerFilePaths:
    async def test_explicit_valid_paths(self, service, tmp_path):
        """Explicit file paths that exist are resolved to absolute paths."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('hello')")
        (tmp_path / "src" / "util.py").write_text("x = 1")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(
            container, ["src/app.py", "src/util.py"], None
        )
        assert len(result) == 2
        assert all(str(tmp_path) in p for p in result)

    async def test_mixed_valid_invalid(self, service, tmp_path):
        """Only existing files are returned; missing files are skipped."""
        (tmp_path / "exists.py").write_text("x = 1")
        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(
            container, ["exists.py", "does_not_exist.py"], None
        )
        assert len(result) == 1
        assert result[0].endswith("exists.py")

    async def test_no_paths_scans_extensions(self, service, tmp_path):
        """When no explicit paths given, walks directory for supported extensions."""
        (tmp_path / "main.py").write_text("x = 1")
        (tmp_path / "lib.js").write_text("var x;")
        (tmp_path / "notes.txt").write_text("just a note")
        (tmp_path / "data.json").write_text("{}")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        assert len(result) == 2
        extensions = {p.rsplit(".", 1)[-1] for p in result}
        assert extensions == {"py", "js"}

    async def test_no_paths_includes_iac_manifests(self, service, tmp_path):
        """The whole-codebase walk must collect IaC manifests so the trivy-config
        iac_scanner producer receives them — without this the IaC engine is inert
        in the primary scan path (the bug that blocked the E3.15 live-fire)."""
        (tmp_path / "app.py").write_text("x = 1")  # source
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\nUSER root\n")
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
        (tmp_path / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\n")
        # A real CloudFormation template (content-sniffed -> collected).
        (tmp_path / "stack.json").write_text(
            '{"AWSTemplateFormatVersion":"2010-09-09","Resources":{"B":{"Type":"AWS::S3::Bucket"}}}'
        )
        # A non-CloudFormation JSON + a plain text file -> NOT collected.
        (tmp_path / "pkg.json").write_text('{"name":"x","version":"1.0.0"}')
        (tmp_path / "notes.txt").write_text("note")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        names = {os.path.basename(p) for p in result}
        assert names == {"app.py", "Dockerfile", "main.tf", "deploy.yaml", "stack.json"}
        assert "pkg.json" not in names  # generic json is never an IaC target
        assert "notes.txt" not in names

    async def test_excludes_only_denylisted_hidden_dirs(self, service, tmp_path):
        """Hidden VCS/cache/build dirs stay out; CI-definition dirs are walked.

        The allowlist form matters for ``max_files``: walking ``.next``,
        ``.cache`` or ``.yarn`` would flood the walk and could push real source
        out of the limit.
        """
        for d in [
            ".git",
            ".venv",
            ".terraform",
            ".mypy_cache",
            ".ruff_cache",
            ".pytest_cache",
            ".tox",
            ".repos",
            ".next",
            ".cache",
            ".yarn",
            ".gradle",
            ".idea",
            ".hg",
        ]:
            sub = tmp_path / d
            sub.mkdir()
            (sub / "excluded.py").write_text("x = 1")
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("on: push\n")
        circleci = tmp_path / ".circleci"
        circleci.mkdir()
        (circleci / "config.yml").write_text("version: 2\n")
        gitlab = tmp_path / ".gitlab" / "ci"
        gitlab.mkdir(parents=True)
        (gitlab / "test.yml").write_text("test:\n  script: echo hi\n")
        (tmp_path / ".secrets.baseline").write_text('{"version": "1.5.0"}')
        (tmp_path / "visible.py").write_text("y = 2")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        rel = {os.path.relpath(p, tmp_path) for p in result}
        assert rel == {
            "visible.py",
            os.path.join(".github", "workflows", "ci.yml"),
            os.path.join(".circleci", "config.yml"),
            os.path.join(".gitlab", "ci", "test.yml"),
        }

    async def test_walks_ci_workflows_and_dotenv_files(self, service, tmp_path):
        """A repo whose secrets live only in CI definitions / dotenv files is
        scanned: the old blanket dot prune hid exactly those files."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("env:\n  API_TOKEN: abc123\n")
        nested_workflows = tmp_path / "frontend" / ".github" / "workflows"
        nested_workflows.mkdir(parents=True)
        (nested_workflows / "ci.yml").write_text("env:\n  TOKEN: def456\n")
        actions = tmp_path / ".github" / "actions" / "setup"
        actions.mkdir(parents=True)
        (actions / "action.yml").write_text("runs:\n  using: composite\n")
        (tmp_path / ".gitlab-ci.yml").write_text("job:\n  script: echo hi\n")
        (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n")
        circleci = tmp_path / ".circleci"
        circleci.mkdir()
        (circleci / "config.yml").write_text("version: 2\n")
        gitlab = tmp_path / ".gitlab" / "ci"
        gitlab.mkdir(parents=True)
        (gitlab / "pipeline.yml").write_text("test:\n  script: echo hi\n")
        (tmp_path / ".env").write_text("DB_PASSWORD=hunter2\n")
        (tmp_path / ".env.local").write_text("API_KEY=xyz\n")
        (tmp_path / "svc").mkdir()
        (tmp_path / "svc" / ".env.production").write_text("SECRET=1\n")
        (tmp_path / "app.py").write_text("x = 1\n")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        rel = {os.path.relpath(p, tmp_path) for p in result}
        assert rel == {
            os.path.join(".github", "workflows", "ci.yml"),
            os.path.join("frontend", ".github", "workflows", "ci.yml"),
            os.path.join(".github", "actions", "setup", "action.yml"),
            ".gitlab-ci.yml",
            ".pre-commit-config.yaml",
            os.path.join(".circleci", "config.yml"),
            os.path.join(".gitlab", "ci", "pipeline.yml"),
            ".env",
            ".env.local",
            os.path.join("svc", ".env.production"),
            "app.py",
        }

    async def test_discovers_web_component_extensions(self, service, tmp_path):
        """JSX/TSX/Vue/Svelte/MJS/CJS source is discovered (it was never routed)."""
        names = ["App.jsx", "App.tsx", "App.vue", "App.svelte", "index.mjs", "index.cjs"]
        for name in names:
            (tmp_path / name).write_text("x\n")
        (tmp_path / "notes.txt").write_text("note\n")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        assert {os.path.basename(p) for p in result} == set(names)

    async def test_excludes_build_dirs(self, service, tmp_path):
        """Known non-code directories (node_modules, __pycache__, build, etc.) are excluded."""
        for d in ["node_modules", "venv", "__pycache__", "build", "dist", "target"]:
            sub = tmp_path / d
            sub.mkdir()
            (sub / "file.py").write_text("x = 1")
        (tmp_path / "app.py").write_text("y = 2")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, None)
        assert len(result) == 1
        assert result[0].endswith("app.py")

    async def test_max_files_truncation(self, service, tmp_path):
        """Results are truncated when exceeding max_files."""
        for i in range(10):
            (tmp_path / f"file_{i}.py").write_text(f"x = {i}")

        container = make_container_info(codebase_path=str(tmp_path))
        result = await service._resolve_container_file_paths(container, None, 3)
        assert len(result) == 3


# ============================================================================
# _filter_by_severity
# ============================================================================


class TestFilterBySeverity:
    def test_critical_only(self, service):
        """Filtering for critical keeps only critical matches in both by_severity and by_type."""
        critical_match = make_vuln_match(severity=VulnerabilitySeverity.CRITICAL)
        high_match = make_vuln_match(severity=VulnerabilitySeverity.HIGH)
        analysis = MockAnalysisResult(
            total_vulnerabilities_found=2,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [critical_match, high_match],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.CRITICAL: [critical_match],
                VulnerabilitySeverity.HIGH: [high_match],
            },
        )
        result = service._filter_by_severity(analysis, ["critical"])
        assert result.total_vulnerabilities_found == 1
        assert VulnerabilitySeverity.HIGH not in result.vulnerabilities_by_severity
        assert VulnerabilitySeverity.CRITICAL in result.vulnerabilities_by_severity
        assert len(result.vulnerabilities_by_severity[VulnerabilitySeverity.CRITICAL]) == 1
        # Type dict should only contain critical matches
        for vuln_list in result.vulnerabilities_by_type.values():
            for v in vuln_list:
                assert v.severity == VulnerabilitySeverity.CRITICAL

    def test_multiple_levels(self, service):
        """Filtering for multiple severity levels keeps all matching, removes others."""
        critical_match = make_vuln_match(severity=VulnerabilitySeverity.CRITICAL)
        medium_match = make_vuln_match(severity=VulnerabilitySeverity.MEDIUM)
        low_match = make_vuln_match(severity=VulnerabilitySeverity.LOW)
        analysis = MockAnalysisResult(
            total_vulnerabilities_found=3,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [critical_match],
                VulnerabilityType.XSS: [medium_match, low_match],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.CRITICAL: [critical_match],
                VulnerabilitySeverity.MEDIUM: [medium_match],
                VulnerabilitySeverity.LOW: [low_match],
            },
        )
        result = service._filter_by_severity(analysis, ["critical", "medium"])
        assert result.total_vulnerabilities_found == 2
        assert VulnerabilitySeverity.LOW not in result.vulnerabilities_by_severity
        assert VulnerabilitySeverity.CRITICAL in result.vulnerabilities_by_severity
        assert VulnerabilitySeverity.MEDIUM in result.vulnerabilities_by_severity
        # Verify XSS type only has medium (low was filtered)
        xss_vulns = result.vulnerabilities_by_type.get(VulnerabilityType.XSS, [])
        assert len(xss_vulns) == 1
        assert xss_vulns[0].severity == VulnerabilitySeverity.MEDIUM

    def test_empty_filter_keeps_nothing(self, service):
        """Empty severity filter list keeps nothing (no severities match)."""
        match = make_vuln_match(severity=VulnerabilitySeverity.HIGH)
        analysis = MockAnalysisResult(
            total_vulnerabilities_found=1,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [match],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.HIGH: [match],
            },
        )
        result = service._filter_by_severity(analysis, [])
        assert result.total_vulnerabilities_found == 0
        assert result.vulnerabilities_by_severity == {}
        assert all(v == [] for v in result.vulnerabilities_by_type.values())


# ============================================================================
# _build_file_results
# ============================================================================


class TestBuildFileResults:
    async def test_groups_by_file(self, service):
        """Vulnerabilities from different files are grouped into separate FileSecurityResult entries."""
        v1 = make_vuln_match(
            file_path="/tmp/test-repo/a.py",
            vuln_type=VulnerabilityType.SQL_INJECTION,
        )
        v2 = make_vuln_match(
            file_path="/tmp/test-repo/b.py",
            vuln_type=VulnerabilityType.XSS,
        )
        v3 = make_vuln_match(
            file_path="/tmp/test-repo/a.py",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
        )
        analysis = MockAnalysisResult(
            total_vulnerabilities_found=3,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [v1],
                VulnerabilityType.XSS: [v2],
                VulnerabilityType.COMMAND_INJECTION: [v3],
            },
        )
        results = await service._build_file_results(analysis, "/tmp/test-repo")
        assert len(results) == 2
        paths = {r.file_path for r in results}
        assert paths == {"a.py", "b.py"}
        # a.py should have 2 vulnerabilities
        a_result = next(r for r in results if r.file_path == "a.py")
        assert a_result.vulnerabilities_found == 2

    async def test_normalizes_relative_paths(self, service):
        """File paths are normalized relative to codebase_path."""
        v = make_vuln_match(file_path="/project/root/src/deep/module.py")
        analysis = MockAnalysisResult(
            total_vulnerabilities_found=1,
            vulnerabilities_by_type={VulnerabilityType.SQL_INJECTION: [v]},
        )
        results = await service._build_file_results(analysis, "/project/root")
        assert len(results) == 1
        assert results[0].file_path == "src/deep/module.py"


# ============================================================================
# _calculate_severity_counts
# ============================================================================


class TestCalculateSeverityCounts:
    def test_all_levels(self, service):
        """All five severity levels are counted correctly."""
        analysis = MockAnalysisResult(
            vulnerabilities_by_severity={
                VulnerabilitySeverity.CRITICAL: [make_vuln_match()] * 2,
                VulnerabilitySeverity.HIGH: [make_vuln_match()] * 3,
                VulnerabilitySeverity.MEDIUM: [make_vuln_match()] * 1,
                VulnerabilitySeverity.LOW: [make_vuln_match()] * 4,
                VulnerabilitySeverity.INFO: [make_vuln_match()] * 5,
            },
        )
        counts = service._calculate_severity_counts(analysis)
        assert counts == {
            "critical": 2,
            "high": 3,
            "medium": 1,
            "low": 4,
            "info": 5,
        }


# ============================================================================
# _build_vulnerability_summary
# ============================================================================


class TestBuildVulnerabilitySummary:
    def test_groups_by_type(self, service):
        """Summary groups counts by vulnerability type, excluding empty lists."""
        analysis = MockAnalysisResult(
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [make_vuln_match()] * 3,
                VulnerabilityType.XSS: [make_vuln_match()] * 1,
                VulnerabilityType.COMMAND_INJECTION: [],  # empty, should be excluded
            },
        )
        summary = service._build_vulnerability_summary(analysis)
        assert summary == {
            "sql_injection": 3,
            "cross_site_scripting": 1,
        }
        assert "command_injection" not in summary


# ============================================================================
# _identify_security_hotspots (new tests)
# ============================================================================


class TestIdentifySecurityHotspotsExtended:
    def test_threshold_3_plus(self, service):
        """Files with exactly 3 vulnerabilities are included as hotspots."""
        file_results = [
            make_file_result(
                file_path="exactly_three.py",
                vuln_count=3,
                violations=[make_violation() for _ in range(3)],
            ),
            make_file_result(file_path="two.py", vuln_count=2),
        ]
        scan_result = make_scan_result(
            high=5, risk_score=40.0, grade="C", file_results=file_results
        )
        hotspots = service._identify_security_hotspots(scan_result)
        assert len(hotspots) == 1
        assert hotspots[0].file_path == "exactly_three.py"

    def test_ordering_by_count(self, service):
        """Hotspots are sorted by vulnerability count descending."""
        file_results = [
            make_file_result(
                file_path="small.py",
                vuln_count=3,
                violations=[make_violation() for _ in range(3)],
            ),
            make_file_result(
                file_path="big.py",
                vuln_count=7,
                violations=[make_violation() for _ in range(7)],
            ),
            make_file_result(
                file_path="medium.py",
                vuln_count=5,
                violations=[make_violation() for _ in range(5)],
            ),
        ]
        scan_result = make_scan_result(
            high=15, risk_score=70.0, grade="D", file_results=file_results
        )
        hotspots = service._identify_security_hotspots(scan_result)
        assert len(hotspots) == 3
        assert hotspots[0].file_path == "big.py"
        assert hotspots[1].file_path == "medium.py"
        assert hotspots[2].file_path == "small.py"


# ============================================================================
# _extract_top_priorities
# ============================================================================


class TestExtractTopPriorities:
    def test_critical_and_high_only(self, service):
        """Only CRITICAL and HIGH severity violations are extracted."""
        violations = [
            make_violation(severity=SecurityLevel.CRITICAL, line_number=1),
            make_violation(severity=SecurityLevel.HIGH, line_number=2),
            make_violation(severity=SecurityLevel.MEDIUM, line_number=3),
            make_violation(severity=SecurityLevel.LOW, line_number=4),
        ]
        file_results = [
            make_file_result(
                vuln_count=4,
                violations=violations,
            ),
        ]
        scan_result = make_scan_result(
            critical=1,
            high=1,
            medium=1,
            low=1,
            risk_score=50.0,
            grade="C",
            file_results=file_results,
        )
        priorities = service._extract_top_priorities(scan_result)
        assert len(priorities) == 2
        severities = {p.severity for p in priorities}
        assert severities == {SecurityLevel.CRITICAL, SecurityLevel.HIGH}

    def test_empty_when_no_critical_high(self, service):
        """Returns empty list when no critical or high violations exist."""
        violations = [
            make_violation(severity=SecurityLevel.MEDIUM, line_number=1),
            make_violation(severity=SecurityLevel.LOW, line_number=2),
        ]
        file_results = [
            make_file_result(vuln_count=2, violations=violations),
        ]
        scan_result = make_scan_result(
            medium=1,
            low=1,
            risk_score=10.0,
            grade="A",
            file_results=file_results,
        )
        priorities = service._extract_top_priorities(scan_result)
        assert priorities == []


# ============================================================================
# _generate_recommendations (new tests)
# ============================================================================


class TestGenerateRecommendationsExtended:
    def test_critical_findings(self, service):
        """Critical count triggers URGENT recommendation with the count."""
        scan_result = make_scan_result(critical=5, risk_score=90.0, grade="F")
        recs = service._generate_recommendations(scan_result)
        urgent = [r for r in recs if "URGENT" in r]
        assert len(urgent) == 1
        assert "5" in urgent[0]

    def test_high_findings(self, service):
        """High count triggers High Priority recommendation with the count."""
        scan_result = make_scan_result(high=7, risk_score=50.0, grade="C")
        recs = service._generate_recommendations(scan_result)
        high_recs = [r for r in recs if "High Priority" in r]
        assert len(high_recs) == 1
        assert "7" in high_recs[0]

    def test_poor_grade(self, service):
        """Grade F triggers comprehensive security review recommendation."""
        scan_result = make_scan_result(high=10, risk_score=80.0, grade="F")
        recs = service._generate_recommendations(scan_result)
        assert any("Security Grade F" in r for r in recs)

    def test_clean_scan(self, service):
        """Zero vulnerabilities triggers positive message and no CI/CD recommendations."""
        scan_result = make_scan_result(risk_score=0.0, grade="A")
        recs = service._generate_recommendations(scan_result)
        assert any("Excellent" in r for r in recs)
        assert not any("CI/CD" in r for r in recs)


# ============================================================================
# _calculate_security_grade — boundary tests
# ============================================================================


class TestCalculateSecurityGradeBoundaries:
    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (0, "A"),
            (10, "A"),
            (11, "B"),
            (25, "B"),
            (26, "C"),
            (50, "C"),
            (51, "D"),
            (75, "D"),
            (76, "F"),
        ],
    )
    def test_boundary_values(self, service, score, expected_grade):
        # Non-zero coverage, not degraded, no findings above the ladder →
        # risk thresholds apply. The severity floor is exercised separately.
        assert service._calculate_security_grade(score, 10, False, NO_FINDINGS) == expected_grade


# ============================================================================
# scan_container
# ============================================================================


class TestScanContainer:
    async def test_unfiltered_success(self, service, tmp_path):
        """Full scan without severity filter returns expected result."""
        (tmp_path / "app.py").write_text("import os")
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(container_name="test-container")

        vuln = make_vuln_match(
            file_path=str(tmp_path / "app.py"),
            severity=VulnerabilitySeverity.HIGH,
        )
        mock_analysis = MockAnalysisResult(
            total_files_analyzed=1,
            total_vulnerabilities_found=1,
            overall_risk_score=30.0,
            vulnerabilities_by_type={VulnerabilityType.SQL_INJECTION: [vuln]},
            vulnerabilities_by_severity={VulnerabilitySeverity.HIGH: [vuln]},
        )
        service.detector.analyze_security_vulnerabilities = AsyncMock(return_value=mock_analysis)

        result = await service.scan_container(container, scan_request)

        assert result.container_name == "test-container"
        assert result.total_vulnerabilities == 1
        assert result.high_count == 1
        # Risk 30 → C on the ladder, but a high finding caps the grade at D.
        assert result.security_grade == "D"
        assert result.overall_risk_score == 30.0
        assert len(result.file_results) == 1

    async def test_severity_filtered(self, service, tmp_path):
        """Scan with severity filter excludes non-matching vulnerabilities."""
        (tmp_path / "app.py").write_text("import os")
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(
            container_name="test-container",
            severity_filter=["critical"],
        )

        critical_vuln = make_vuln_match(
            file_path=str(tmp_path / "app.py"),
            severity=VulnerabilitySeverity.CRITICAL,
        )
        high_vuln = make_vuln_match(
            file_path=str(tmp_path / "app.py"),
            severity=VulnerabilitySeverity.HIGH,
        )
        mock_analysis = MockAnalysisResult(
            total_files_analyzed=1,
            total_vulnerabilities_found=2,
            overall_risk_score=50.0,
            vulnerabilities_by_type={
                VulnerabilityType.SQL_INJECTION: [critical_vuln, high_vuln],
            },
            vulnerabilities_by_severity={
                VulnerabilitySeverity.CRITICAL: [critical_vuln],
                VulnerabilitySeverity.HIGH: [high_vuln],
            },
        )
        service.detector.analyze_security_vulnerabilities = AsyncMock(return_value=mock_analysis)

        result = await service.scan_container(container, scan_request)

        # After filtering, only the critical vuln remains
        assert result.total_vulnerabilities == 1
        assert result.critical_count == 1
        assert result.high_count == 0

    async def test_empty_result(self, service, tmp_path):
        """Scan with no vulnerabilities returns clean result."""
        (tmp_path / "clean.py").write_text("x = 1")
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(container_name="test-container")

        mock_analysis = MockAnalysisResult(
            total_files_analyzed=1,
            total_vulnerabilities_found=0,
            overall_risk_score=0.0,
            vulnerabilities_by_type={},
            vulnerabilities_by_severity={},
        )
        service.detector.analyze_security_vulnerabilities = AsyncMock(return_value=mock_analysis)

        result = await service.scan_container(container, scan_request)

        assert result.total_vulnerabilities == 0
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.security_grade == "A"
        assert result.file_results == []
        assert result.affected_files == []
        # A clean scan that examined everything is not degraded.
        assert result.scan_degraded is False

    async def test_degraded_scan_grades_f_not_a(self, service, tmp_path):
        """A degraded analysis (clean risk score, but coverage lost) must grade F,
        never A. This is the fake-green the oracle gate must never accept."""
        (tmp_path / "clean.py").write_text("x = 1")
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(container_name="test-container")

        mock_analysis = MockAnalysisResult(
            total_files_analyzed=0,
            total_vulnerabilities_found=0,
            overall_risk_score=0.0,
            vulnerabilities_by_type={},
            vulnerabilities_by_severity={},
            files_failed_to_parse=2,
            scan_degraded=True,
        )
        service.detector.analyze_security_vulnerabilities = AsyncMock(return_value=mock_analysis)

        result = await service.scan_container(container, scan_request)

        # Zero coverage + degraded → grade F, and the flag surfaces so the oracle
        # gate can fail closed.
        assert result.security_grade == "F"
        assert result.scan_degraded is True

    async def test_no_files_discovered_grades_f(self, service, tmp_path):
        """When file discovery finds nothing (empty codebase), scan_container
        returns the worst honest result — grade F, degraded — WITHOUT ever
        invoking the detector (which would otherwise grade A on zero files)."""
        # Empty directory → _resolve_container_file_paths returns [].
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(container_name="test-container")

        # If the guard fails, this mock would grade A — assert it is never called.
        detector_mock = AsyncMock()
        service.detector.analyze_security_vulnerabilities = detector_mock

        result = await service.scan_container(container, scan_request)

        assert result.total_files_scanned == 0
        assert result.security_grade == "F"
        assert result.scan_degraded is True
        assert result.overall_risk_score == 100.0
        detector_mock.assert_not_awaited()

    async def test_real_vulnerabilities_grade_on_severity_floor(self, service, tmp_path):
        """A scan that examines real files with a real critical finding grades F,
        not the diluted risk ladder's D (regression guard for the severity floor)."""
        (tmp_path / "app.py").write_text("import os")
        container = make_container_info(codebase_path=str(tmp_path))
        scan_request = ContainerSecurityScanRequest(container_name="test-container")

        vuln = make_vuln_match(
            file_path=str(tmp_path / "app.py"),
            severity=VulnerabilitySeverity.CRITICAL,
        )
        mock_analysis = MockAnalysisResult(
            total_files_analyzed=3,
            total_vulnerabilities_found=1,
            overall_risk_score=60.0,
            vulnerabilities_by_type={VulnerabilityType.SQL_INJECTION: [vuln]},
            vulnerabilities_by_severity={VulnerabilitySeverity.CRITICAL: [vuln]},
            scan_degraded=False,
        )
        service.detector.analyze_security_vulnerabilities = AsyncMock(return_value=mock_analysis)

        result = await service.scan_container(container, scan_request)

        assert result.total_files_scanned == 3
        assert result.scan_degraded is False
        # risk 60 alone → D, but a critical finding floors the grade at F.
        assert result.security_grade == "F"
        assert result.finding_grade == "F"


# ============================================================================
# generate_security_report — counts and language breakdown
# ============================================================================


class TestGenerateSecurityReportExtended:
    async def test_counts_and_language_breakdown(self, service):
        """Report includes correct affected/clean file counts and language breakdown."""
        container = make_container_info()
        file_results = [
            make_file_result(
                file_path="a.py",
                language="python",
                vuln_count=2,
                violations=[
                    make_violation(vuln_type="sql_injection", severity=SecurityLevel.CRITICAL),
                    make_violation(vuln_type="xss", severity=SecurityLevel.HIGH),
                ],
            ),
            make_file_result(
                file_path="b.js",
                language="javascript",
                vuln_count=1,
                violations=[
                    make_violation(vuln_type="command_injection", severity=SecurityLevel.MEDIUM),
                ],
            ),
        ]
        scan_result = make_scan_result(
            critical=1,
            high=1,
            medium=1,
            risk_score=40.0,
            grade="C",
            file_results=file_results,
        )
        scan_result.affected_files = ["a.py", "b.js"]

        report = await service.generate_security_report(container, scan_result)

        assert report.affected_files_count == 2
        assert report.clean_files_count == 8  # total_files_scanned(10) - 2
        assert report.language_breakdown == {"python": 2, "javascript": 1}


# ============================================================================
# _build_language_breakdown
# ============================================================================


class TestBuildLanguageBreakdown:
    def test_counts_extensions(self, service):
        """Language breakdown sums vulnerability counts per language."""
        file_results = [
            make_file_result(file_path="a.py", language="python", vuln_count=3),
            make_file_result(file_path="b.py", language="python", vuln_count=2),
            make_file_result(file_path="c.js", language="javascript", vuln_count=1),
            make_file_result(file_path="d.go", language="go", vuln_count=0),
        ]
        scan_result = make_scan_result(
            high=6,
            risk_score=50.0,
            grade="C",
            file_results=file_results,
        )
        breakdown = service._build_language_breakdown(scan_result)
        assert breakdown == {"python": 5, "javascript": 1}
        # go file had 0 vulns, should not appear
        assert "go" not in breakdown
