"""Pattern-based vulnerability detection source."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from services.security_detector import VulnerabilityMatch
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSource,
    map_confidence,
    map_severity,
)

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


def get_all_vulnerabilities(analysis_result) -> list[VulnerabilityMatch]:
    """Extract all vulnerability matches from analysis result."""
    all_vulns: list[VulnerabilityMatch] = []
    for matches in analysis_result.vulnerabilities_by_type.values():
        all_vulns.extend(matches)
    return all_vulns


async def run(
    scanner: UnifiedSecurityScanner, container_name: str, errors: list[str]
) -> list[SecurityFinding]:
    """Run pattern-based vulnerability detection.

    Args:
        scanner: UnifiedSecurityScanner instance (provides pattern_detector + helpers)
        container_name: Container to scan
        errors: List to append error messages

    Returns:
        List of SecurityFinding objects from pattern detection
    """
    findings: list[SecurityFinding] = []

    try:
        # Get file paths from container
        file_paths = await scanner._resolve_container_files(container_name)

        if not file_paths:
            logger.warning(f"No source files found in {container_name}")
            return findings

        logger.debug(f"Analyzing {len(file_paths)} files for security patterns")

        # Run pattern detection
        analysis_result = await scanner.pattern_detector.analyze_security_vulnerabilities(
            file_paths=file_paths, include_low_confidence=True
        )

        # Convert VulnerabilityMatch to SecurityFinding
        for vuln_match in get_all_vulnerabilities(analysis_result):
            finding = SecurityFinding(
                id=f"pattern_{vuln_match.id}",
                title=vuln_match.title,
                description=vuln_match.description,
                severity=map_severity(vuln_match.severity),
                confidence=map_confidence(vuln_match.confidence),
                source=SecurityFindingSource.PATTERN,
                cve_id=None,  # Patterns may have CVEs in references
                file_path=vuln_match.file_path,
                line_number=vuln_match.line_start,
                remediation_advice=vuln_match.remediation_advice,
                references=vuln_match.references,
                context_evidence=vuln_match.context_evidence,
            )
            # Add CVE from references if present
            if vuln_match.references:
                for ref in vuln_match.references:
                    if ref.startswith("CVE"):
                        finding.cve_id = ref
                        break
            findings.append(finding)

        logger.info(f"Pattern detection found {len(findings)} vulnerabilities")

    except Exception as e:
        error_msg = f"Pattern detection failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)

    return findings
