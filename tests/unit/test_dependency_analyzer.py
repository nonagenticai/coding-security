"""Tests for ArchitectureDependencyAnalyzer orchestrator (dependency_analyzer.py)."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from models.architecture_models import (
    DependencyRiskReport,
    DependencyRiskSummary,
    Vulnerability,
)
from models.package_manager_models import ExternalPackage
from services.dependency_analyzer import ArchitectureDependencyAnalyzer
from services.dependency_visualization import PartialDependencyState


def _dep_vuln(vuln_id: str, severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary="s",
        details="d",
        affected_versions=[],
        fixed_versions=[],
        references=[],
        published_date="2026-01-01",
        modified_date="2026-01-01",
        package_name="requests",
    )


@pytest.fixture
def mock_analyzer():
    """Create an ArchitectureDependencyAnalyzer with mocked sub-components."""
    with (
        patch("services.dependency_analyzer.DependencyExtractor") as mock_ext,
        patch("services.dependency_analyzer.DependencyGraphBuilder") as mock_gb,
        patch("services.dependency_analyzer.DependencyAnalyzer") as mock_da,
        patch("services.dependency_analyzer.CircularDependencyDetector") as mock_cd,
        patch("services.dependency_analyzer.DependencyVulnerabilityScanner") as mock_vs,
    ):
        # Per-scan outcome attributes of the real scanner (a clean, complete scan).
        mock_vs.return_value.lookup_errors = []
        mock_vs.return_value.package_vulnerabilities = {}
        analyzer = ArchitectureDependencyAnalyzer(timeout=10, enable_cache=False)
        # Store mocks for assertions (dynamic attrs for test convenience)
        setattr(analyzer, "_mock_extractor", mock_ext.return_value)
        setattr(analyzer, "_mock_graph_builder", mock_gb.return_value)
        setattr(analyzer, "_mock_dep_analyzer", mock_da.return_value)
        setattr(analyzer, "_mock_circular", mock_cd.return_value)
        setattr(analyzer, "_mock_vuln_scanner", mock_vs.return_value)
        yield analyzer


class TestInit:
    def test_creates_sub_components(self):
        with (
            patch("services.dependency_analyzer.DependencyExtractor") as mock_ext,
            patch("services.dependency_analyzer.DependencyGraphBuilder") as mock_gb,
            patch("services.dependency_analyzer.DependencyAnalyzer") as mock_da,
            patch("services.dependency_analyzer.CircularDependencyDetector") as mock_cd,
            patch("services.dependency_analyzer.DependencyVulnerabilityScanner") as mock_vs,
        ):
            _analyzer = ArchitectureDependencyAnalyzer(
                timeout=15, enable_cache=True, cache_ttl_hours=12
            )
            mock_ext.assert_called_once()
            mock_gb.assert_called_once_with(timeout=15)
            mock_da.assert_called_once()
            mock_cd.assert_called_once()
            mock_vs.assert_called_once_with(timeout=15, enable_cache=True, cache_ttl_hours=12)


class TestAnalyze:
    async def test_empty_repo_returns_empty_report(self, mock_analyzer, tmp_path):
        mock_analyzer._mock_extractor.extract_dependencies.return_value = []
        report = await mock_analyzer.analyze(tmp_path, "test-codebase")
        assert isinstance(report, DependencyRiskReport)
        assert report.risk_score == 0.0
        assert report.summary.total_packages == 0

    async def test_nonexistent_path_raises(self, mock_analyzer):
        with pytest.raises(ValueError, match="does not exist"):
            await mock_analyzer.analyze(Path("/nonexistent/path"), "test-codebase")

    async def test_empty_codebase_id_raises(self, mock_analyzer, tmp_path):
        with pytest.raises(ValueError, match="Codebase ID cannot be empty"):
            await mock_analyzer.analyze(tmp_path, "  ")

    async def test_orchestrates_full_pipeline(self, mock_analyzer, tmp_path):
        packages = [ExternalPackage(name="fastapi", version="0.115.0", ecosystem="pypi")]
        mock_analyzer._mock_extractor.extract_dependencies.return_value = packages
        mock_analyzer._mock_vuln_scanner.scan_vulnerabilities = AsyncMock(return_value=[])

        expected_report = DependencyRiskReport(
            codebase_id="test-codebase",
            generated_at="2026-01-01T00:00:00",
            packages=packages,
            vulnerabilities=[],
            risk_score=0.0,
            summary=DependencyRiskSummary(
                total_packages=1,
                vulnerable_packages=0,
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                moderate_vulnerabilities=0,
                low_vulnerabilities=0,
            ),
        )
        mock_analyzer._mock_dep_analyzer.generate_risk_report.return_value = expected_report

        report = await mock_analyzer.analyze(tmp_path, "test-codebase")

        mock_analyzer._mock_extractor.extract_dependencies.assert_called_once_with(tmp_path)
        mock_analyzer._mock_vuln_scanner.scan_vulnerabilities.assert_called_once_with(
            packages, partial=None
        )
        mock_analyzer._mock_dep_analyzer.generate_risk_report.assert_called_once()
        assert report.codebase_id == "test-codebase"

    async def test_extractor_failure_raises_runtime_error(self, mock_analyzer, tmp_path):
        mock_analyzer._mock_extractor.extract_dependencies.side_effect = RuntimeError(
            "extraction failed"
        )
        with pytest.raises(RuntimeError, match="Dependency analysis failed"):
            await mock_analyzer.analyze(tmp_path, "test-codebase")

    async def test_include_transitive_builds_graph(self, mock_analyzer, tmp_path):
        packages = [ExternalPackage(name="fastapi", version="0.115.0", ecosystem="pypi")]
        mock_analyzer._mock_extractor.extract_dependencies.return_value = packages
        mock_analyzer._mock_graph_builder.build_dependency_graph = AsyncMock(return_value=packages)
        mock_analyzer._mock_vuln_scanner.scan_vulnerabilities = AsyncMock(return_value=[])
        expected_report = DependencyRiskReport(
            codebase_id="test",
            generated_at="2026-01-01T00:00:00",
            packages=packages,
            vulnerabilities=[],
            risk_score=0.0,
            summary=DependencyRiskSummary(
                total_packages=1,
                vulnerable_packages=0,
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                moderate_vulnerabilities=0,
                low_vulnerabilities=0,
            ),
        )
        mock_analyzer._mock_dep_analyzer.generate_risk_report.return_value = expected_report

        report = await mock_analyzer.analyze(tmp_path, "test", include_transitive=True, max_depth=5)
        mock_analyzer._mock_graph_builder.build_dependency_graph.assert_called_once_with(
            packages, 5
        )
        assert report.codebase_id == "test"


class TestConvenienceMethods:
    """Tests for convenience methods that delegate to sub-components."""

    def test_get_outdated_packages(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_extractor.get_outdated_packages.return_value = packages
        result = mock_analyzer.get_outdated_packages(packages)
        mock_analyzer._mock_extractor.get_outdated_packages.assert_called_once_with(packages)
        assert result == packages

    def test_get_vulnerable_packages(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_extractor.get_vulnerable_packages.return_value = packages
        result = mock_analyzer.get_vulnerable_packages(packages)
        mock_analyzer._mock_extractor.get_vulnerable_packages.assert_called_once_with(packages)
        assert result == packages

    async def test_analyze_transitive_dependencies(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_graph_builder.analyze_transitive_dependencies = AsyncMock(
            return_value=packages
        )
        result = await mock_analyzer.analyze_transitive_dependencies(packages, max_depth=2)
        mock_analyzer._mock_graph_builder.analyze_transitive_dependencies.assert_called_once_with(
            packages, 2
        )
        assert result == packages

    def test_detect_circular_dependencies(self, mock_analyzer):
        packages = [ExternalPackage(name="a", version="1.0", ecosystem="pypi")]
        dep_map = {"a": ["b"], "b": ["a"]}
        mock_analyzer._mock_circular.detect_circular_dependencies.return_value = [["a", "b", "a"]]
        result = mock_analyzer.detect_circular_dependencies(packages, dep_map)
        assert result == [["a", "b", "a"]]

    def test_detect_circular_dependencies_no_map(self, mock_analyzer):
        packages = [ExternalPackage(name="a", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_circular.detect_circular_dependencies.return_value = []
        result = mock_analyzer.detect_circular_dependencies(packages)
        mock_analyzer._mock_circular.detect_circular_dependencies.assert_called_once_with(
            packages, {}
        )
        assert result == []

    def test_analyze_dependency_health(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        expected = {"health_score": 10.0}
        mock_analyzer._mock_dep_analyzer.analyze_dependency_health.return_value = expected
        result = mock_analyzer.analyze_dependency_health(packages)
        assert result == expected

    def test_get_ecosystem_breakdown(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        expected = {"pypi": 1}
        mock_analyzer._mock_dep_analyzer.get_ecosystem_breakdown.return_value = expected
        result = mock_analyzer.get_ecosystem_breakdown(packages)
        assert result == expected

    def test_identify_high_risk_packages(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_dep_analyzer.identify_high_risk_packages.return_value = []
        result = mock_analyzer.identify_high_risk_packages(packages, [])
        assert result == []

    def test_clear_vulnerability_cache(self, mock_analyzer):
        mock_analyzer.clear_vulnerability_cache()
        mock_analyzer._mock_vuln_scanner.clear_cache.assert_called_once()

    def test_get_cache_stats(self, mock_analyzer):
        expected = {"hits": 0, "misses": 0}
        mock_analyzer._mock_vuln_scanner.get_cache_stats.return_value = expected
        result = mock_analyzer.get_cache_stats()
        assert result == expected


class TestLegacyMethods:
    """Tests for legacy method aliases."""

    def test_deduplicate_packages(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_extractor.deduplicate_packages.return_value = packages
        result = mock_analyzer._deduplicate_packages(packages)
        assert result == packages

    def test_calculate_risk_score(self, mock_analyzer):
        mock_analyzer._mock_dep_analyzer.calculate_risk_score.return_value = 5.0
        result = mock_analyzer._calculate_risk_score([])
        assert result == 5.0

    def test_generate_summary(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        expected = DependencyRiskSummary(
            total_packages=1,
            vulnerable_packages=0,
            total_vulnerabilities=0,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            moderate_vulnerabilities=0,
            low_vulnerabilities=0,
        )
        mock_analyzer._mock_dep_analyzer.generate_summary.return_value = expected
        result = mock_analyzer._generate_summary(packages, [])
        assert result == expected

    async def test_query_osv_vulnerabilities(self, mock_analyzer):
        packages = [ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")]
        mock_analyzer._mock_vuln_scanner.scan_vulnerabilities = AsyncMock(return_value=[])
        result = await mock_analyzer._query_osv_vulnerabilities(packages)
        assert result == []


class TestBuildPartialReport:
    """The degraded-report builder consumed on the runner's timeout branch."""

    def _real_analyzer(self):
        # A real analyzer so build_partial_report exercises the real dedup +
        # risk scoring (sub-component constructors are network-free).
        return ArchitectureDependencyAnalyzer(timeout=5, enable_cache=False)

    def test_surfaces_partial_findings_deduped_and_degraded(self):
        analyzer = self._real_analyzer()
        partial = PartialDependencyState(
            packages=[ExternalPackage(name="requests", version="2.0.0", ecosystem="pypi")],
            vulnerabilities=[
                _dep_vuln("CVE-1", "CRITICAL"),
                _dep_vuln("CVE-1", "CRITICAL"),  # duplicate id — must collapse
                _dep_vuln("CVE-2", "HIGH"),
            ],
        )

        report = analyzer.build_partial_report("c1", partial)

        assert report.scan_degraded is True
        assert report.codebase_id == "c1"
        assert {v.id for v in report.vulnerabilities} == {"CVE-1", "CVE-2"}  # deduped
        assert len(report.vulnerabilities) == 2
        assert len(report.packages) == 1
        assert report.risk_score == 10.0  # a CRITICAL saturates the noisy-OR score

    def test_zero_progress_is_honest_not_a_pass(self):
        analyzer = self._real_analyzer()

        report = analyzer.build_partial_report("c1", PartialDependencyState())

        assert report.scan_degraded is True  # degraded — never a clean pass
        assert report.vulnerabilities == []
        assert report.risk_score == 0.0
        assert report.summary.total_packages == 0
