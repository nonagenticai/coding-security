"""UnifiedSecurityScanner orchestrator.

Thin orchestrator that wires the per-source scanners, aggregation helpers,
and NVD enrichment together behind the public ``UnifiedSecurityScanner``
interface used by callers and tests.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from models.image_scan_models import ImageVulnerability
from models.security_models import OSVVulnerability
from services.grype_scanner import GrypeScanner
from services.nvd_client import NVDClient
from services.osv_scanner import OSVScanner
from services.pip_audit_scanner import PipAuditScanner, PipAuditVulnerability
from services.safety_scanner import SafetyScanner, SafetyVulnerability
from services.security_detector import (
    VulnerabilityMatch,
    VulnerabilitySeverity,
    get_security_detector,
)
from services.trivy_scanner import TrivyScanner
from services.unified_security import aggregation, container_files
from services.unified_security.base import (
    SecurityFinding,
    SecurityFindingSeverity,
    UnifiedSecurityReport,
    map_confidence,
    map_severity,
)
from services.unified_security.sources import image, nvd, osv, pattern, pip_audit, safety

logger = logging.getLogger(__name__)


class UnifiedSecurityScanner:
    """Unified security scanner orchestrating multiple vulnerability detection methods.

    Coordinates pattern-based detection, OSV.dev scanning, Safety/pip-audit
    Python dependency scanning, and Trivy/Grype container image scanning.
    Findings are deduplicated, scored, recommended on, and optionally
    enriched with NVD CVSS data.
    """

    def __init__(self):
        """Initialize the unified security scanner."""
        self.pattern_detector = get_security_detector()
        self.osv_scanner: OSVScanner | None = None
        self.safety_scanner = SafetyScanner()
        self.pip_audit_scanner = PipAuditScanner()
        self.trivy_scanner = TrivyScanner()
        self.grype_scanner = GrypeScanner()
        self.nvd_client: NVDClient | None = None
        logger.info("UnifiedSecurityScanner initialized")

    async def comprehensive_scan(self, container_name: str) -> UnifiedSecurityReport:
        """Perform comprehensive security scan on a container.

        Runs all available scanners (pattern, OSV, Safety, pip-audit, image),
        merges + deduplicates results, enriches with NVD CVSS data, and
        returns a UnifiedSecurityReport. Partial results are returned on
        per-scanner failure; no exception is raised.
        """
        start_time = datetime.now(UTC)
        logger.info(f"Starting comprehensive security scan for: {container_name}")

        report = UnifiedSecurityReport(container_name=container_name)
        errors: list[str] = []

        logger.debug("Running pattern-based detection...")
        pattern_results = await self._run_pattern_detection(container_name, errors)

        logger.debug("Running OSV.dev dependency scanning...")
        osv_results = await self._run_osv_scan(container_name, errors)

        logger.debug("Running Safety scanning...")
        safety_results = await self._run_safety_scan(container_name, errors)

        logger.debug("Running pip-audit scanning...")
        pip_audit_results = await self._run_pip_audit_scan(container_name, errors)

        logger.debug("Running container image scanning...")
        image_results = await self._run_image_scan(container_name, errors)

        logger.debug("Merging and deduplicating findings...")
        findings = self._deduplicate_findings(
            pattern_results,
            osv_results,
            safety_results,
            pip_audit_results,
            image_results,
        )

        await self._enrich_findings_with_nvd(findings, errors)

        # A scanner that failed or was unavailable recorded a message in `errors`.
        # When that happens the scan is incomplete, so a clean (100, zero-finding)
        # result is not trustworthy — flag it so consumers can fail closed.
        scan_degraded = bool(errors)

        security_score = self._calculate_security_score(findings)
        recommendations = self._generate_recommendations(findings, degraded=scan_degraded)

        report.findings = findings
        report.total_vulnerabilities = len(findings)
        report.security_score = security_score
        report.recommendations = recommendations
        report.errors = errors
        report.scan_degraded = scan_degraded

        report.by_source = self._count_by_source(findings)
        report.by_severity = self._count_by_severity(findings)
        report.cve_count = len(
            set(f.cve_id for f in findings if f.cve_id and f.cve_id.startswith("CVE"))
        )

        scan_duration = (datetime.now(UTC) - start_time).total_seconds()
        report.scan_duration_seconds = scan_duration

        logger.info(
            f"Comprehensive scan completed for {container_name}: "
            f"{report.total_vulnerabilities} vulnerabilities found, "
            f"security score: {security_score:.1f}, duration: {scan_duration:.2f}s"
        )

        return report

    # --- source delegations ------------------------------------------------

    async def _run_pattern_detection(
        self, container_name: str, errors: list[str]
    ) -> list[SecurityFinding]:
        return await pattern.run(self, container_name, errors)

    async def _run_osv_scan(self, container_name: str, errors: list[str]) -> list[SecurityFinding]:
        return await osv.run(self, container_name, errors)

    async def _run_safety_scan(
        self, container_name: str, errors: list[str]
    ) -> list[SecurityFinding]:
        return await safety.run(self, container_name, errors)

    async def _run_pip_audit_scan(
        self, container_name: str, errors: list[str]
    ) -> list[SecurityFinding]:
        return await pip_audit.run(self, container_name, errors)

    async def _run_image_scan(
        self, container_name: str, errors: list[str]
    ) -> list[SecurityFinding]:
        return await image.run(self, container_name, errors)

    async def _enrich_findings_with_nvd(
        self, findings: list[SecurityFinding], errors: list[str]
    ) -> None:
        await nvd.enrich(self, findings, errors)

    # --- per-vuln conversion delegations ----------------------------------

    def _pip_audit_vuln_to_finding(self, vuln: PipAuditVulnerability) -> SecurityFinding:
        return pip_audit.pip_audit_vuln_to_finding(vuln)

    def _image_vuln_to_finding(
        self, vuln: ImageVulnerability, scanner_name: str
    ) -> SecurityFinding:
        return image.image_vuln_to_finding(vuln, scanner_name)

    def _osv_vuln_to_finding(self, vuln: OSVVulnerability) -> SecurityFinding:
        return osv.osv_vuln_to_finding(vuln)

    def _safety_vuln_to_finding(self, vuln: SafetyVulnerability) -> SecurityFinding:
        return safety.safety_vuln_to_finding(vuln)

    def _map_severity(self, vuln_severity: VulnerabilitySeverity) -> SecurityFindingSeverity:
        return map_severity(vuln_severity)

    def _map_confidence(self, confidence_str: str) -> float:
        return map_confidence(confidence_str)

    def _get_all_vulnerabilities(self, analysis_result) -> list[VulnerabilityMatch]:
        return pattern.get_all_vulnerabilities(analysis_result)

    # --- aggregation delegations ------------------------------------------

    def _deduplicate_findings(
        self,
        pattern_results: list[SecurityFinding],
        osv_results: list[SecurityFinding],
        safety_results: list[SecurityFinding],
        *additional_results: list[SecurityFinding],
    ) -> list[SecurityFinding]:
        return aggregation.deduplicate_findings(
            pattern_results, osv_results, safety_results, *additional_results
        )

    def _calculate_security_score(self, findings: list[SecurityFinding]) -> float:
        return aggregation.calculate_security_score(findings)

    def _generate_recommendations(
        self, findings: list[SecurityFinding], degraded: bool = False
    ) -> list[str]:
        return aggregation.generate_recommendations(findings, degraded=degraded)

    def _count_by_source(self, findings: list[SecurityFinding]) -> dict[str, int]:
        return aggregation.count_by_source(findings)

    def _count_by_severity(self, findings: list[SecurityFinding]) -> dict[str, int]:
        return aggregation.count_by_severity(findings)

    # --- container-file resolution delegations ----------------------------

    async def _resolve_container_files(self, container_name: str) -> list[str]:
        return await container_files.resolve_container_files(container_name)

    async def _find_lockfiles(self, container_name: str) -> list[str]:
        return await container_files.find_lockfiles(container_name)

    async def _find_requirements_files(self, container_name: str) -> list[str]:
        return await container_files.find_requirements_files(container_name)


# Singleton instance
_unified_scanner: UnifiedSecurityScanner | None = None


def get_unified_security_scanner() -> UnifiedSecurityScanner:
    """Get or create global unified security scanner instance."""
    global _unified_scanner
    if _unified_scanner is None:
        _unified_scanner = UnifiedSecurityScanner()
        logger.info("Initialized global unified security scanner")
    return _unified_scanner
