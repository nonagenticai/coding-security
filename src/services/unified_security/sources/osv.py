"""OSV.dev dependency vulnerability scanning source."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from models.security_models import OSVVulnerability
from services.osv_scanner import OSVScanner
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
)

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


def osv_vuln_to_finding(vuln: OSVVulnerability) -> SecurityFinding:
    """Convert OSV vulnerability to unified finding."""
    cve_id = None
    if vuln.cve_ids:
        cve_id = vuln.cve_ids[0]

    severity_map = {
        "CRITICAL": SecurityFindingSeverity.CRITICAL,
        "HIGH": SecurityFindingSeverity.HIGH,
        "MEDIUM": SecurityFindingSeverity.MEDIUM,
        "LOW": SecurityFindingSeverity.LOW,
    }
    severity = severity_map.get(
        vuln.severity.upper() if vuln.severity else "",
        SecurityFindingSeverity.MEDIUM,
    )

    return SecurityFinding(
        id=f"osv_{vuln.id}",
        title=f"{vuln.package_name}: {vuln.summary[:100]}",
        description=vuln.details or vuln.summary,
        severity=severity,
        confidence=0.9,  # OSV data is highly reliable
        source=SecurityFindingSource.OSV,
        cve_id=cve_id,
        package_name=vuln.package_name,
        affected_version=(vuln.affected_versions[0] if vuln.affected_versions else None),
        fixed_version=vuln.fixed_versions[0] if vuln.fixed_versions else None,
        references=vuln.references,
        remediation_advice=(
            f"Update {vuln.package_name} to version {vuln.fixed_versions[0]} or later"
            if vuln.fixed_versions
            else f"Update {vuln.package_name} to a patched version"
        ),
    )


async def run(
    scanner: UnifiedSecurityScanner, container_name: str, errors: list[str]
) -> list[SecurityFinding]:
    """Run OSV.dev dependency vulnerability scanning."""
    findings: list[SecurityFinding] = []

    try:
        lockfile_paths = await scanner._find_lockfiles(container_name)

        if not lockfile_paths:
            logger.debug(f"No lockfiles found in {container_name}")
            return findings

        logger.debug(f"Found {len(lockfile_paths)} lockfiles to scan")

        if scanner.osv_scanner is None:
            scanner.osv_scanner = OSVScanner()

        for lockfile_path in lockfile_paths:
            try:
                logger.debug(f"Scanning lockfile: {lockfile_path}")
                osv_vulns = await scanner.osv_scanner.scan_lockfile(str(lockfile_path))

                for vuln in osv_vulns:
                    finding = osv_vuln_to_finding(vuln)
                    findings.append(finding)

            except FileNotFoundError:
                logger.debug(f"Lockfile not found: {lockfile_path}")
            except ValueError as e:
                logger.debug(f"Unsupported lockfile: {lockfile_path} - {e}")
            except Exception as e:
                error_msg = f"OSV scan failed for {lockfile_path}: {str(e)}"
                logger.warning(error_msg)
                errors.append(error_msg)

        logger.info(f"OSV scanning found {len(findings)} vulnerabilities")

    except Exception as e:
        error_msg = f"OSV scanning failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)

    finally:
        if scanner.osv_scanner:
            try:
                await scanner.osv_scanner.close()
            except Exception as e:
                logger.debug(f"Error closing OSV scanner: {e}")

    return findings
