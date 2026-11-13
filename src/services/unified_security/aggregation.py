"""Aggregation helpers for unified security findings.

Free-function dedup, score, recommend, and per-axis counters that operate on
flat lists of SecurityFinding objects.
"""

from __future__ import annotations

import logging

from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
)

logger = logging.getLogger(__name__)


def deduplicate_findings(
    pattern_results: list[SecurityFinding],
    osv_results: list[SecurityFinding],
    safety_results: list[SecurityFinding],
    *additional_results: list[SecurityFinding],
) -> list[SecurityFinding]:
    """Merge findings from multiple sources and deduplicate.

    Deduplicates based on CVE ID, package name, or similar characteristics.
    Prioritizes findings by confidence and severity.

    Args:
        pattern_results: Findings from pattern detection
        osv_results: Findings from OSV scanning
        safety_results: Findings from Safety scanning
        *additional_results: Findings from additional scanners

    Returns:
        Deduplicated list of SecurityFinding objects
    """
    all_findings = pattern_results + osv_results + safety_results
    for extra in additional_results:
        all_findings.extend(extra)

    if not all_findings:
        return []

    # Group findings by CVE ID first
    by_cve: dict[str, list[SecurityFinding]] = {}
    by_package: dict[str, list[SecurityFinding]] = {}
    unmatched: list[SecurityFinding] = []

    for finding in all_findings:
        if finding.cve_id and finding.cve_id.startswith("CVE"):
            if finding.cve_id not in by_cve:
                by_cve[finding.cve_id] = []
            by_cve[finding.cve_id].append(finding)
        elif finding.package_name:
            key = f"{finding.package_name}:{finding.affected_version or 'unknown'}"
            if key not in by_package:
                by_package[key] = []
            by_package[key].append(finding)
        else:
            unmatched.append(finding)

    # Build deduplicated findings list
    deduplicated: list[SecurityFinding] = []
    seen_ids: set[str] = set()

    # Process CVE-based duplicates
    for cve_id, findings_group in by_cve.items():
        best_finding = max(findings_group, key=lambda f: f.confidence)
        finding_id = f"cve_{cve_id}_{best_finding.severity.value}"

        if finding_id not in seen_ids:
            deduplicated.append(best_finding)
            seen_ids.add(finding_id)

    # Process package-based duplicates
    for package_key, findings_group in by_package.items():
        best_finding = max(findings_group, key=lambda f: f.confidence)
        finding_id = f"pkg_{package_key}_{best_finding.severity.value}"

        if finding_id not in seen_ids:
            deduplicated.append(best_finding)
            seen_ids.add(finding_id)

    # Add unmatched findings
    for finding in unmatched:
        finding_id = f"{finding.source.value}_{finding.title}_{finding.severity.value}"
        if finding_id not in seen_ids:
            deduplicated.append(finding)
            seen_ids.add(finding_id)

    logger.debug(f"Deduplicated {len(all_findings)} findings to {len(deduplicated)} unique issues")

    return deduplicated


def calculate_security_score(findings: list[SecurityFinding]) -> float:
    """Calculate overall security score (0-100).

    Score is calculated based on:
    - Number of vulnerabilities
    - Severity distribution (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFO=0)
    - Confidence levels

    Args:
        findings: List of security findings

    Returns:
        Security score from 0 (best) to 100 (worst)
    """
    if not findings:
        return 100.0  # Perfect score with no findings

    severity_weights = {
        SecurityFindingSeverity.CRITICAL: 10.0,
        SecurityFindingSeverity.HIGH: 7.0,
        SecurityFindingSeverity.MEDIUM: 4.0,
        SecurityFindingSeverity.LOW: 1.0,
        SecurityFindingSeverity.INFO: 0.0,
    }

    total_score = 0.0
    for finding in findings:
        severity_weight = severity_weights.get(finding.severity, 0.0)
        confidence_weight = finding.confidence  # 0.0-1.0
        total_score += severity_weight * confidence_weight

    # Max possible score with 10 findings of CRITICAL with 100% confidence = 100
    normalized_score = min((total_score / 10.0) * 100.0, 100.0)

    return 100.0 - normalized_score  # Invert so lower is better


def generate_recommendations(findings: list[SecurityFinding], degraded: bool = False) -> list[str]:
    """Generate actionable remediation recommendations.

    Args:
        findings: List of security findings
        degraded: True when one or more scanners failed/were unavailable, so the
            scan was incomplete. When True we never claim the target is clean —
            a zero-finding result may just mean nothing was scanned.

    Returns:
        List of recommendation strings
    """
    recommendations: list[str] = []

    if degraded:
        recommendations.append(
            "⚠️ Security scan INCOMPLETE: one or more scanners failed or were "
            "unavailable. Results may understate risk — see the report's `errors`. "
            "Do not treat this scan as a clean bill of health; re-run once the "
            "scanners are available."
        )

    if not findings:
        if not degraded:
            recommendations.append(
                "Excellent! No security vulnerabilities detected. "
                "Continue following best practices."
            )
        return recommendations

    critical_count = len([f for f in findings if f.severity == SecurityFindingSeverity.CRITICAL])
    high_count = len([f for f in findings if f.severity == SecurityFindingSeverity.HIGH])
    medium_count = len([f for f in findings if f.severity == SecurityFindingSeverity.MEDIUM])

    if critical_count > 0:
        recommendations.append(
            f"URGENT: Address {critical_count} critical vulnerabilities immediately. "
            f"These pose severe security risks to the application."
        )

    if high_count > 0:
        recommendations.append(
            f"High Priority: Fix {high_count} high severity vulnerabilities as soon as possible. "
            f"Schedule remediation within current sprint."
        )

    if medium_count > 0:
        recommendations.append(
            f"Medium Priority: Address {medium_count} medium severity issues in upcoming releases. "
            f"Plan remediation timeline."
        )

    sources = set(f.source for f in findings)

    if SecurityFindingSource.PATTERN in sources:
        pattern_findings = [f for f in findings if f.source == SecurityFindingSource.PATTERN]
        recommendations.append(
            f"Code Quality: Review and fix {len(pattern_findings)} code pattern vulnerabilities. "
            f"Implement secure coding practices."
        )

    if SecurityFindingSource.OSV in sources:
        osv_findings = [f for f in findings if f.source == SecurityFindingSource.OSV]
        recommendations.append(
            f"Dependencies: Update {len(osv_findings)} packages with known vulnerabilities. "
            f"Use 'npm audit fix' or equivalent to resolve."
        )

    if SecurityFindingSource.SAFETY in sources:
        safety_findings = [f for f in findings if f.source == SecurityFindingSource.SAFETY]
        recommendations.append(
            f"Python Dependencies: Upgrade {len(safety_findings)} Python packages to patched versions. "
            f"Review 'pip install --upgrade' options."
        )

    if SecurityFindingSource.PIP_AUDIT in sources:
        pip_audit_findings = [f for f in findings if f.source == SecurityFindingSource.PIP_AUDIT]
        recommendations.append(
            f"pip-audit: Found {len(pip_audit_findings)} Python package vulnerabilities. "
            f"Run 'pip-audit --fix' to auto-remediate."
        )

    if SecurityFindingSource.TRIVY in sources or SecurityFindingSource.GRYPE in sources:
        image_findings = [
            f
            for f in findings
            if f.source in (SecurityFindingSource.TRIVY, SecurityFindingSource.GRYPE)
        ]
        recommendations.append(
            f"Container Image: Found {len(image_findings)} image vulnerabilities. "
            f"Rebuild with updated base image and packages."
        )

    recommendations.extend(
        [
            "Implement automated security scanning in CI/CD pipeline",
            "Conduct regular security code reviews",
            "Keep all dependencies up-to-date",
            "Enable dependency vulnerability notifications",
        ]
    )

    return recommendations


def count_by_source(findings: list[SecurityFinding]) -> dict[str, int]:
    """Count findings by source.

    Args:
        findings: List of security findings

    Returns:
        Dictionary with counts by source
    """
    counts: dict[str, int] = {
        "pattern": 0,
        "osv": 0,
        "safety": 0,
        "pip_audit": 0,
        "trivy": 0,
        "grype": 0,
    }

    for finding in findings:
        source_key = finding.source.value
        if source_key in counts:
            counts[source_key] += 1

    return counts


def count_by_severity(findings: list[SecurityFinding]) -> dict[str, int]:
    """Count findings by severity.

    Args:
        findings: List of security findings

    Returns:
        Dictionary with counts by severity
    """
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity_key = finding.severity.value
        if severity_key in counts:
            counts[severity_key] += 1

    return counts
