"""Safety CLI scanning source for Python dependencies."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from services.safety_scanner import SafetyVulnerability
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
)

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


def safety_vuln_to_finding(vuln: SafetyVulnerability) -> SecurityFinding:
    """Convert Safety vulnerability to unified finding."""
    severity_map = {
        "critical": SecurityFindingSeverity.CRITICAL,
        "high": SecurityFindingSeverity.HIGH,
        "medium": SecurityFindingSeverity.MEDIUM,
        "low": SecurityFindingSeverity.LOW,
    }
    severity = severity_map.get(vuln.severity, SecurityFindingSeverity.MEDIUM)

    return SecurityFinding(
        id=f"safety_{vuln.advisory_id or vuln.cve_id or 'unknown'}",
        title=f"{vuln.package_name}: {vuln.description[:100]}",
        description=vuln.description,
        severity=severity,
        confidence=0.85,  # Safety data is reliable
        source=SecurityFindingSource.SAFETY,
        cve_id=vuln.cve_id,
        package_name=vuln.package_name,
        affected_version=vuln.installed_version,
        fixed_version=vuln.safe_version,
        remediation_advice=vuln.remediation or f"Update {vuln.package_name} to a patched version",
    )


async def run(
    scanner: UnifiedSecurityScanner, container_name: str, errors: list[str]
) -> list[SecurityFinding]:
    """Run Safety CLI scanning for Python dependencies."""
    findings: list[SecurityFinding] = []

    if not scanner.safety_scanner.is_safety_available():
        logger.debug("Safety CLI not available, skipping Safety scan")
        return findings

    try:
        requirements_files = await scanner._find_requirements_files(container_name)

        if not requirements_files:
            logger.debug(f"No requirements files found in {container_name}")
            return findings

        logger.debug(f"Found {len(requirements_files)} requirements files")

        for req_file in requirements_files:
            try:
                logger.debug(f"Scanning requirements file: {req_file}")
                safety_vulns = await scanner.safety_scanner.scan_requirements(str(req_file))

                for vuln in safety_vulns:
                    finding = safety_vuln_to_finding(vuln)
                    findings.append(finding)

            except ValueError as e:
                logger.debug(f"Invalid requirements file: {req_file} - {e}")
            except Exception as e:
                error_msg = f"Safety scan failed for {req_file}: {str(e)}"
                logger.warning(error_msg)
                errors.append(error_msg)

        logger.info(f"Safety scanning found {len(findings)} vulnerabilities")

    except Exception as e:
        error_msg = f"Safety scanning failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)

    return findings
