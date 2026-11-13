"""Dependency Analysis and Metrics Module.

Handles risk scoring, summary generation, vulnerability categorization,
and overall dependency health metrics.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from models.architecture_models import (
    DependencyRiskReport,
    DependencyRiskSummary,
    Vulnerability,
)
from models.package_manager_models import ExternalPackage

logger = logging.getLogger(__name__)

# Single canonical severity vocabulary for the whole module. Scanners disagree
# on casing and synonyms ("MEDIUM" vs "MODERATE", lower/mixed case); normalize
# every incoming severity through here before scoring/counting so no real vuln
# silently falls through to a 0.0 weight or an uncounted bucket. Anything not
# recognized maps to "UNKNOWN" (deliberately unweighted).
_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MODERATE",
    "MEDIUM": "MODERATE",
    "LOW": "LOW",
}


def _normalize_severity(raw: str | None) -> str:
    """Canonicalize a raw severity string to CRITICAL/HIGH/MODERATE/LOW or UNKNOWN."""
    return _SEVERITY_ALIASES.get((raw or "").strip().upper(), "UNKNOWN")


class DependencyAnalyzer:
    """Analyzes dependencies and generates risk assessments and metrics."""

    def __init__(self) -> None:
        logger.info("DependencyAnalyzer initialized")

    def generate_risk_report(
        self,
        codebase_id: str,
        packages: list[ExternalPackage],
        vulnerabilities: list[Vulnerability],
    ) -> DependencyRiskReport:
        """Generate a comprehensive dependency risk report."""
        if not codebase_id.strip():
            raise ValueError("Codebase ID cannot be empty")

        risk_score = self.calculate_risk_score(vulnerabilities)
        summary = self.generate_summary(packages, vulnerabilities)

        report = DependencyRiskReport(
            codebase_id=codebase_id,
            generated_at=datetime.now(UTC).isoformat(),
            packages=packages,
            vulnerabilities=vulnerabilities,
            risk_score=risk_score,
            summary=summary,
        )

        logger.info(
            "Risk report generated: %d packages, %d vulnerabilities, risk score: %.1f",
            len(packages),
            len(vulnerabilities),
            risk_score,
        )
        return report

    def calculate_risk_score(self, vulnerabilities: list[Vulnerability]) -> float:
        """Calculate overall risk score from 0.0 to 10.0.

        Aggregates per-vuln severity via **noisy-OR** rather than an average, so
        a pile of LOW/UNKNOWN findings can never DILUTE a CRITICAL. Each severity
        contributes an independent "risk probability" ``p``; the combined score is
        ``10 * (1 - Π(1 - p))``. Properties this guarantees:
          - a single CRITICAL (``p=1.0``) saturates to exactly 10.0;
          - the worst severity present is a floor — extra vulns only raise;
          - LOW/UNKNOWN can never lower a score;
          - monotonic in the multiset of vulns and bounded to [0.0, 10.0].
        UNKNOWN maps to ``p=0.0`` (contributes nothing, preserving the floor).
        """
        if not vulnerabilities:
            return 0.0

        severity_probabilities = {
            "CRITICAL": 1.0,
            "HIGH": 0.7,
            "MODERATE": 0.4,
            "LOW": 0.2,
        }

        product = 1.0
        for vuln in vulnerabilities:
            p = severity_probabilities.get(_normalize_severity(vuln.severity), 0.0)
            product *= 1.0 - p
        return round(min(10.0, 10.0 * (1.0 - product)), 1)

    def generate_summary(
        self,
        packages: list[ExternalPackage],
        vulnerabilities: list[Vulnerability],
    ) -> DependencyRiskSummary:
        """Generate summary statistics."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = _normalize_severity(vuln.severity)
            if severity in severity_counts:
                severity_counts[severity] += 1

        vulnerable_package_count = self._get_vulnerable_packages_count(packages, vulnerabilities)

        return DependencyRiskSummary(
            total_packages=len(packages),
            vulnerable_packages=vulnerable_package_count,
            total_vulnerabilities=len(vulnerabilities),
            critical_vulnerabilities=severity_counts["CRITICAL"],
            high_vulnerabilities=severity_counts["HIGH"],
            moderate_vulnerabilities=severity_counts["MODERATE"],
            low_vulnerabilities=severity_counts["LOW"],
        )

    def _get_vulnerable_packages_count(
        self,
        packages: list[ExternalPackage],
        vulnerabilities: list[Vulnerability],
    ) -> int:
        # Correlate on the exact owning-package identity the scanner stamped on
        # each vuln (``package_name``), NOT a substring of free-text id/summary —
        # short real names (os, re, io, six) substring-match unrelated CVEs.
        vulnerable_packages = set()
        for vuln in vulnerabilities:
            if not vuln.package_name:
                continue
            for package in packages:
                if vuln.package_name.lower() == package.name.lower():
                    vulnerable_packages.add(package.name)
        return len(vulnerable_packages)

    def categorize_vulnerabilities_by_severity(
        self, vulnerabilities: list[Vulnerability]
    ) -> dict[str, int]:
        """Categorize vulnerabilities by severity level."""
        categories = {
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "moderate_vulnerabilities": 0,
            "low_vulnerabilities": 0,
        }
        for vuln in vulnerabilities:
            severity = _normalize_severity(vuln.severity)
            if severity == "CRITICAL":
                categories["critical_vulnerabilities"] += 1
            elif severity == "HIGH":
                categories["high_vulnerabilities"] += 1
            elif severity == "MODERATE":
                categories["moderate_vulnerabilities"] += 1
            elif severity == "LOW":
                categories["low_vulnerabilities"] += 1
        return categories

    def analyze_dependency_health(self, packages: list[ExternalPackage]) -> dict[str, Any]:
        """Analyze overall dependency health metrics."""
        total_packages = len(packages)
        if total_packages == 0:
            return {
                "total_packages": 0,
                "outdated_packages": 0,
                "packages_with_vulnerabilities": 0,
                "unlicensed_packages": 0,
                "health_score": 10.0,
            }

        outdated_count = sum(
            1
            for pkg in packages
            if pkg.latest_version and pkg.current_version != pkg.latest_version
        )
        vulnerable_count = sum(
            1
            for pkg in packages
            if _normalize_severity(pkg.severity) in ("CRITICAL", "HIGH", "MODERATE")
        )
        unlicensed_count = sum(
            1 for pkg in packages if not pkg.license or pkg.license.lower() in ["unknown", ""]
        )

        health_score = 10.0
        health_score -= (outdated_count / total_packages) * 3.0
        health_score -= (vulnerable_count / total_packages) * 5.0
        health_score -= (unlicensed_count / total_packages) * 2.0
        health_score = max(0.0, health_score)

        return {
            "total_packages": total_packages,
            "outdated_packages": outdated_count,
            "packages_with_vulnerabilities": vulnerable_count,
            "unlicensed_packages": unlicensed_count,
            "health_score": round(health_score, 1),
            "outdated_percentage": round((outdated_count / total_packages) * 100, 1),
            "vulnerable_percentage": round((vulnerable_count / total_packages) * 100, 1),
            "unlicensed_percentage": round((unlicensed_count / total_packages) * 100, 1),
        }

    def get_ecosystem_breakdown(self, packages: list[ExternalPackage]) -> dict[str, int]:
        """Get breakdown of packages by ecosystem."""
        ecosystem_counts: dict[str, int] = {}
        for package in packages:
            ecosystem = package.ecosystem or "unknown"
            ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
        return ecosystem_counts

    def identify_high_risk_packages(
        self, packages: list[ExternalPackage], vulnerabilities: list[Vulnerability]
    ) -> list[dict[str, Any]]:
        """Identify top 20 highest-risk packages."""
        high_risk_packages: list[dict[str, Any]] = []
        package_vulns: dict[str, list[Vulnerability]] = {}
        for vuln in vulnerabilities:
            if not vuln.package_name:
                continue
            for package in packages:
                if vuln.package_name.lower() == package.name.lower():
                    if package.name not in package_vulns:
                        package_vulns[package.name] = []
                    package_vulns[package.name].append(vuln)

        # All four severity buckets contribute to a package's risk (previously
        # only CRITICAL/HIGH scored, so a MODERATE/LOW-only package silently sat
        # at 0 even while its full vulnerability_count was reported).
        severity_bucket_weights = (
            ("CRITICAL", "critical", 3.0),
            ("HIGH", "high", 2.0),
            ("MODERATE", "moderate", 1.0),
            ("LOW", "low", 0.5),
        )

        for package in packages:
            risk_factors = []
            risk_score = 0.0
            severity_breakdown = {
                "critical": 0,
                "high": 0,
                "moderate": 0,
                "low": 0,
                "unknown": 0,
            }

            if package.name in package_vulns:
                for vuln in package_vulns[package.name]:
                    severity_breakdown[_normalize_severity(vuln.severity).lower()] += 1
                for label, key, weight in severity_bucket_weights:
                    count = severity_breakdown[key]
                    if count > 0:
                        risk_factors.append(f"{count} {label.lower()} vulnerabilities")
                        risk_score += count * weight

            if package.latest_version and package.current_version != package.latest_version:
                risk_factors.append("outdated version")
                risk_score += 1.0

            if not package.license or package.license.lower() in ["unknown", ""]:
                risk_factors.append("no license information")
                risk_score += 0.5

            if risk_score >= 2.0:
                high_risk_packages.append(
                    {
                        "name": package.name,
                        "version": package.version or package.current_version,
                        "ecosystem": package.ecosystem,
                        "risk_score": round(risk_score, 1),
                        "risk_factors": risk_factors,
                        "vulnerability_count": len(package_vulns.get(package.name, [])),
                        "severity_breakdown": severity_breakdown,
                    }
                )

        high_risk_packages.sort(key=lambda x: x["risk_score"], reverse=True)
        return high_risk_packages[:20]
