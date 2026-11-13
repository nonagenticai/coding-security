"""
Dependency Analysis Module

Main orchestrator for comprehensive dependency analysis including vulnerability
scanning, risk assessment, and security reporting using multiple package managers.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from models.architecture_models import (
    DependencyRiskReport,
    DependencyRiskSummary,
    ExternalPackage,
    Vulnerability,
    mark_degraded,
)
from models.package_manager_models import PackageVulnerability
from services.circular_detection import CircularDependencyDetector
from services.dependency_analysis import DependencyAnalyzer
from services.dependency_extraction import DependencyExtractor
from services.dependency_graph import DependencyGraphBuilder
from services.dependency_visualization import (
    DependencyVulnerabilityScanner,
    PartialDependencyState,
)

logger = logging.getLogger(__name__)

# Worst-wins ordering for a package's severity. UNKNOWN (a record OSV published
# with no usable rating) ranks above LOW so an unrated advisory is never hidden by
# the ``!= "low"`` filter behind a co-located LOW one — same stance as
# ``dependency_upgrade._severity_at_or_above`` ("unknown is high enough to surface").
_PACKAGE_SEVERITY_RANK: dict[str, int] = {
    "LOW": 1,
    "UNKNOWN": 2,
    "MODERATE": 3,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _max_severity(vulnerabilities: list[Vulnerability]) -> str:
    """Return the most severe rating among ``vulnerabilities`` (non-empty)."""
    return max(
        (v.severity.upper() for v in vulnerabilities),
        key=lambda sev: _PACKAGE_SEVERITY_RANK.get(sev, _PACKAGE_SEVERITY_RANK["UNKNOWN"]),
    )


def attach_vulnerabilities(
    packages: list[ExternalPackage],
    vulnerabilities_by_package: dict[str, list[Vulnerability]],
) -> list[ExternalPackage]:
    """Copy each package's OSV findings onto the package itself.

    ``severity`` becomes the MAX severity of the package's vulnerabilities;
    ``vulnerabilities`` lists each one with ITS OWN fixed versions (empty = no
    known fix). The package-level ``fixed_versions`` union is set only when EVERY
    vulnerability has a fix — otherwise it is None, because a union would hide
    the unfixed CVE. A package with no known vulnerability is returned unchanged
    (severity stays None) — severities are never invented.
    """
    enriched: list[ExternalPackage] = []
    for package in packages:
        version = package.version or package.current_version or ""
        # A name can resolve to several versions: only this version's records apply
        # (a record without a version stamp applies to every version of the name).
        vulns = [
            v
            for v in vulnerabilities_by_package.get(package.name) or []
            if not v.package_version or v.package_version == version
        ]
        if not vulns:
            enriched.append(package)
            continue
        per_vuln: dict[str, PackageVulnerability] = {}
        for vuln in sorted(vulns, key=lambda v: v.id):
            if vuln.id in per_vuln:
                continue
            per_vuln[vuln.id] = PackageVulnerability(
                id=vuln.id,
                severity=vuln.severity.upper(),
                fixed_versions=list(dict.fromkeys(vuln.fixed_versions)),
            )
        fixed: list[str] | None = []
        for entry in per_vuln.values():
            if not entry.fixed_versions:
                fixed = None
                break
            fixed.extend(v for v in entry.fixed_versions if v not in fixed)
        enriched.append(
            package.model_copy(
                update={
                    "severity": _max_severity(vulns),
                    "vulnerability_ids": list(per_vuln),
                    "vulnerabilities": list(per_vuln.values()),
                    "fixed_versions": fixed,
                }
            )
        )
    return enriched


class ArchitectureDependencyAnalyzer:
    """
    Main orchestrator for dependency analysis and risk assessment.

    Coordinates between extraction, graph building, vulnerability scanning,
    and analysis modules to provide comprehensive dependency insights.
    """

    def __init__(
        self,
        timeout: int = 30,
        enable_cache: bool = True,
        cache_ttl_hours: int = 24,
    ) -> None:
        """
        Initialize the dependency analyzer orchestrator.

        Args:
            timeout: HTTP timeout for vulnerability scanning in seconds
            enable_cache: Whether to enable vulnerability result caching
            cache_ttl_hours: Time-to-live for cached vulnerability results in hours
        """
        # Initialize component modules
        self.extractor = DependencyExtractor()
        self.graph_builder = DependencyGraphBuilder(timeout=timeout)
        self.analyzer = DependencyAnalyzer()
        self.circular_detector = CircularDependencyDetector()
        self.vulnerability_scanner = DependencyVulnerabilityScanner(
            timeout=timeout,
            enable_cache=enable_cache,
            cache_ttl_hours=cache_ttl_hours,
        )

        logger.info(
            "ArchitectureDependencyAnalyzer initialized with timeout: %ds, cache: %s",
            timeout,
            enable_cache,
        )

    async def analyze(
        self,
        repo: Path,
        codebase_id: str,
        include_transitive: bool = False,
        max_depth: int = 3,
        partial: PartialDependencyState | None = None,
    ) -> DependencyRiskReport:
        """
        Analyze dependencies in the repository and assess security risks.

        Args:
            repo: Path to the repository to analyze
            codebase_id: Unique identifier for the codebase
            include_transitive: Whether to include transitive dependencies in analysis
            max_depth: Maximum depth for transitive dependency resolution
            partial: Optional caller-held accumulator. When supplied, the
                resolved package set and each vulnerability are recorded into it
                live during the (cancellable) scan, so a ``wait_for`` timeout can
                recover a degraded report via ``build_partial_report`` instead of
                discarding the work. Defaults to ``None`` (sync callers unaffected).

        Returns:
            Comprehensive dependency risk report

        Raises:
            ValueError: If repo path is invalid or codebase_id is empty
            RuntimeError: If dependency analysis fails
        """
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo}")

        if not codebase_id.strip():
            raise ValueError("Codebase ID cannot be empty")

        logger.info(
            "Starting dependency analysis for codebase '%s' at path: %s",
            codebase_id,
            repo,
        )

        try:
            # Step 1: Extract dependencies
            packages = self.extractor.extract_dependencies(repo)
            unparsed = self._unparsed_manifests()

            if not packages:
                logger.warning("No dependencies found in repository at %s", repo)
                report = self._create_empty_report(codebase_id)
                if unparsed:
                    # "0 packages" is NOT "nothing to check" when the repo
                    # declares dependencies in a format we could not read.
                    mark_degraded(report, self._unparsed_reason(unparsed))
                return report

            # Step 2: Optionally build dependency graph with transitive dependencies
            if include_transitive:
                logger.info(
                    "Building dependency graph with transitive dependencies (max depth: %d)",
                    max_depth,
                )
                packages = await self.graph_builder.build_dependency_graph(packages, max_depth)

            # Record the resolved package set on the accumulator BEFORE the
            # cancellable vulnerability scan, so a timeout still reports what was
            # found (mirrors the container path aliasing ``partial.parsed_files``).
            if partial is not None:
                partial.packages = packages

            # Step 3: Scan for vulnerabilities
            vulnerabilities = await self.vulnerability_scanner.scan_vulnerabilities(
                packages, partial=partial
            )
            logger.info(
                "Found %d vulnerabilities across all packages",
                len(vulnerabilities),
            )

            # Step 4: Stamp each package with its own findings, so package-level
            # consumers (``get_vulnerable_packages`` filters on ``severity``) see
            # them. Before this nothing on the path set ``severity`` and
            # /vulnerable could never return a row (coding-security#103).
            packages = attach_vulnerabilities(
                packages, self.vulnerability_scanner.package_vulnerabilities
            )

            # Step 5: Generate risk report
            report = self.analyzer.generate_risk_report(codebase_id, packages, vulnerabilities)
            if unparsed:
                # Packages in a manifest we could not parse were never looked
                # up: the grade covers less than the repo holds.
                mark_degraded(report, self._unparsed_reason(unparsed))
            if self.vulnerability_scanner.lookup_errors:
                # The grade covers fewer packages than the repo holds: an OSV
                # outage must read as degraded, never as a clean scan.
                errors = self.vulnerability_scanner.lookup_errors
                mark_degraded(
                    report,
                    f"vulnerability lookup incomplete for {len(errors)} package(s)/batch(es): "
                    + "; ".join(errors[:3]),
                )

            logger.info(
                "Dependency analysis completed. Found %d packages, %d vulnerabilities, risk score: %.1f",
                len(packages),
                len(vulnerabilities),
                report.risk_score,
            )

            return report

        except Exception as e:
            logger.error(
                "Dependency analysis failed for codebase '%s': %s",
                codebase_id,
                e,
                exc_info=True,
            )
            raise RuntimeError(f"Dependency analysis failed: {e}") from e

    def build_partial_report(
        self, codebase_id: str, partial: PartialDependencyState
    ) -> DependencyRiskReport:
        """Build a degraded report from a timed-out scan's accumulated findings.

        The dependency analog of the container path's ``build_partial_result`` /
        ``result_from_partial``: deduplicate whatever vulnerabilities completed
        before the timeout, score them over the packages found so far, and flag
        ``scan_degraded`` so the caller stores a degraded ``completed`` record
        instead of a ``failed`` one that discards the work. Zero progress yields
        an honest empty degraded report (never a clean pass).
        """
        deduped = self.vulnerability_scanner._deduplicate_vulnerabilities(partial.vulnerabilities)
        report = self.analyzer.generate_risk_report(codebase_id, partial.packages, deduped)
        mark_degraded(report, "scan exceeded the time budget before completion")
        return report

    def _unparsed_manifests(self) -> list[str]:
        """Manifests the extractor could not resolve during the last ``analyze``.

        Attribute-probed (not type-asserted) so a duck-typed or mocked
        extractor needs no new method, and a non-list value is treated as
        "nothing reported" rather than truthy.
        """
        value = getattr(self.extractor, "unparsed_manifests", [])
        return [str(item) for item in value] if isinstance(value, list) else []

    @staticmethod
    def _unparsed_reason(unparsed: list[str]) -> str:
        return "unparsed dependency manifests: " + ", ".join(unparsed)

    def _create_empty_report(self, codebase_id: str) -> DependencyRiskReport:
        """Create an empty report when no dependencies are found."""
        return DependencyRiskReport(
            codebase_id=codebase_id,
            generated_at=datetime.now(UTC).isoformat(),
            packages=[],
            vulnerabilities=[],
            risk_score=0.0,
            summary=DependencyRiskSummary(
                total_packages=0,
                vulnerable_packages=0,
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                moderate_vulnerabilities=0,
                low_vulnerabilities=0,
            ),
        )

    @property
    def vulnerability_lookup_errors(self) -> list[str]:
        """OSV lookups that FAILED during the last ``analyze`` (empty = complete)."""
        return list(self.vulnerability_scanner.lookup_errors)

    # Convenience methods that delegate to component modules

    def get_outdated_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Get packages that have newer versions available."""
        return self.extractor.get_outdated_packages(packages)

    def get_vulnerable_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Get packages with known vulnerabilities."""
        return self.extractor.get_vulnerable_packages(packages)

    async def analyze_transitive_dependencies(
        self, packages: list[ExternalPackage], max_depth: int = 3
    ) -> list[ExternalPackage]:
        """Recursively resolve and analyze transitive dependencies."""
        return await self.graph_builder.analyze_transitive_dependencies(packages, max_depth)

    def detect_circular_dependencies(
        self,
        packages: list[ExternalPackage],
        dependency_map: dict[str, list[str]] | None = None,
    ) -> list[list[str]]:
        """Detect circular dependencies in the package graph."""
        return self.circular_detector.detect_circular_dependencies(packages, dependency_map or {})

    def analyze_dependency_health(self, packages: list[ExternalPackage]) -> dict[str, Any]:
        """Analyze overall dependency health metrics."""
        return self.analyzer.analyze_dependency_health(packages)

    def get_ecosystem_breakdown(self, packages: list[ExternalPackage]) -> dict[str, int]:
        """Get breakdown of packages by ecosystem."""
        return self.analyzer.get_ecosystem_breakdown(packages)

    def identify_high_risk_packages(
        self, packages: list[ExternalPackage], vulnerabilities: list[Vulnerability]
    ) -> list[dict[str, Any]]:
        """Identify packages that pose the highest risk."""
        return self.analyzer.identify_high_risk_packages(packages, vulnerabilities)

    def clear_vulnerability_cache(self) -> None:
        """Clear the vulnerability cache."""
        self.vulnerability_scanner.clear_cache()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get vulnerability cache statistics."""
        return self.vulnerability_scanner.get_cache_stats()

    # Legacy method aliases for backward compatibility
    def _deduplicate_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Legacy method - use extractor.deduplicate_packages instead."""
        return self.extractor.deduplicate_packages(packages)

    def _calculate_risk_score(self, vulnerabilities: list[Vulnerability]) -> float:
        """Legacy method - use analyzer.calculate_risk_score instead."""
        return self.analyzer.calculate_risk_score(vulnerabilities)

    def _generate_summary(
        self, packages: list[ExternalPackage], vulnerabilities: list[Vulnerability]
    ) -> DependencyRiskSummary:
        """Legacy method - use analyzer.generate_summary instead."""
        return self.analyzer.generate_summary(packages, vulnerabilities)

    async def _query_osv_vulnerabilities(
        self, packages: list[ExternalPackage]
    ) -> list[Vulnerability]:
        """Legacy method - use vulnerability_scanner.scan_vulnerabilities instead."""
        return await self.vulnerability_scanner.scan_vulnerabilities(packages)
