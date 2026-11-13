"""Container image scanning source (Trivy primary, Grype fallback)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from config.settings import get_settings
from models.image_scan_models import ImageVulnerability
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    SecurityFindingSource,
)

if TYPE_CHECKING:
    from services.unified_security.scanner import UnifiedSecurityScanner

logger = logging.getLogger(__name__)


def image_vuln_to_finding(vuln: ImageVulnerability, scanner_name: str) -> SecurityFinding:
    """Convert image vulnerability to unified finding."""
    severity_map = {
        "CRITICAL": SecurityFindingSeverity.CRITICAL,
        "HIGH": SecurityFindingSeverity.HIGH,
        "MEDIUM": SecurityFindingSeverity.MEDIUM,
        "LOW": SecurityFindingSeverity.LOW,
    }
    severity = severity_map.get(vuln.severity.upper(), SecurityFindingSeverity.MEDIUM)

    source = SecurityFindingSource.TRIVY if scanner_name == "trivy" else SecurityFindingSource.GRYPE

    return SecurityFinding(
        id=f"{scanner_name}_{vuln.vulnerability_id}",
        title=f"{vuln.package_name}: {vuln.title or vuln.vulnerability_id}",
        description=vuln.description or f"Image vulnerability {vuln.vulnerability_id}",
        severity=severity,
        confidence=0.95,
        source=source,
        cve_id=vuln.vulnerability_id if vuln.vulnerability_id.startswith("CVE") else None,
        package_name=vuln.package_name,
        affected_version=vuln.installed_version,
        fixed_version=vuln.fixed_version,
        remediation_advice=(
            f"Update {vuln.package_name} to version {vuln.fixed_version}"
            if vuln.fixed_version
            else f"Update {vuln.package_name} to a patched version"
        ),
    )


async def run(
    scanner: UnifiedSecurityScanner, container_name: str, errors: list[str]
) -> list[SecurityFinding]:
    """Run container image scanning using Trivy (primary) or Grype (fallback)."""
    findings: list[SecurityFinding] = []

    settings = get_settings()
    image_ref = f"{settings.docker_registry_url}/{container_name}:latest"

    try:
        image_vulns: list[ImageVulnerability] = []
        scanner_name = ""

        if scanner.trivy_scanner.is_trivy_available():
            scanner_name = "trivy"
            image_vulns = await scanner.trivy_scanner.scan_image(
                image_ref, timeout=settings.trivy_scan_timeout
            )
        elif scanner.grype_scanner.is_grype_available():
            scanner_name = "grype"
            image_vulns = await scanner.grype_scanner.scan_image(
                image_ref, timeout=settings.grype_scan_timeout
            )
        else:
            # trivy/grype are load-bearing CLIs baked into the image; if neither
            # is present the image-CVE scan did NOT run. Record it so the report
            # is flagged degraded instead of passing as "clean".
            msg = "No image scanner (trivy/grype) available: image CVE scan was skipped"
            logger.warning(msg)
            errors.append(msg)
            return findings

        for vuln in image_vulns:
            finding = image_vuln_to_finding(vuln, scanner_name)
            findings.append(finding)

        logger.info(f"Image scanning ({scanner_name}) found {len(findings)} vulnerabilities")

    except Exception as e:
        error_msg = f"Image scanning failed for {container_name}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)

    return findings
