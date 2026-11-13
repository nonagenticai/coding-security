"""pip-audit scanning source for Python dependencies."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from services.pip_audit_scanner import PipAuditVulnerability
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
)

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


def pip_audit_vuln_to_finding(vuln: PipAuditVulnerability) -> SecurityFinding:
    """Convert pip-audit vulnerability to unified finding."""
    cve_id = None
    if vuln.vulnerability_id.startswith("CVE"):
        cve_id = vuln.vulnerability_id
    else:
        for alias in vuln.aliases:
            if alias.startswith("CVE"):
                cve_id = alias
                break

    return SecurityFinding(
        id=f"pip_audit_{vuln.vulnerability_id}",
        title=f"{vuln.package_name}: {vuln.vulnerability_id}",
        description=vuln.description
        or f"Vulnerability {vuln.vulnerability_id} in {vuln.package_name}",
        severity=SecurityFindingSeverity.MEDIUM,  # pip-audit doesn't always provide severity
        confidence=0.9,
        source=SecurityFindingSource.PIP_AUDIT,
        cve_id=cve_id,
        package_name=vuln.package_name,
        affected_version=vuln.installed_version,
        fixed_version=vuln.fix_versions[0] if vuln.fix_versions else None,
        remediation_advice=(
            f"Update {vuln.package_name} to version {vuln.fix_versions[0]} or later"
            if vuln.fix_versions
            else f"Update {vuln.package_name} to a patched version"
        ),
    )


async def run(
    scanner: UnifiedSecurityScanner, container_name: str, errors: list[str]
) -> list[SecurityFinding]:
    """Run pip-audit scanning for Python dependencies."""
    findings: list[SecurityFinding] = []

    if not scanner.pip_audit_scanner.is_pip_audit_available():
        # pip-audit is a project dependency; if it is missing at runtime the
        # Python-dependency scan did NOT run. Record it so the report is marked
        # degraded rather than silently passing as "clean".
        msg = "pip-audit unavailable: Python dependency scan was skipped"
        logger.warning(msg)
        errors.append(msg)
        return findings

    try:
        requirements_files = await scanner._find_requirements_files(container_name)

        if not requirements_files:
            logger.debug(f"No requirements files found in {container_name}")
            return findings

        for req_file in requirements_files:
            try:
                vulns = await scanner.pip_audit_scanner.scan_requirements(str(req_file))
                for vuln in vulns:
                    finding = pip_audit_vuln_to_finding(vuln)
                    findings.append(finding)
            except ValueError as e:
                logger.debug(f"Invalid requirements file: {req_file} - {e}")
            except Exception as e:
                error_msg = f"pip-audit scan failed for {req_file}: {str(e)}"
                logger.warning(error_msg)
                errors.append(error_msg)

        logger.info(f"pip-audit scanning found {len(findings)} vulnerabilities")

    except Exception as e:
        error_msg = f"pip-audit scanning failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)

    return findings
