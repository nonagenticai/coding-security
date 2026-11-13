"""
Security Scan Service for Container-Scoped Security Analysis

This service provides comprehensive security scanning capabilities at the container level,
including vulnerability detection, risk assessment, and security reporting.
"""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from models.container_models import ContainerInfo
from models.security_api_models import (
    BaseImageCoverage,
    ContainerSecurityReport,
    ContainerSecurityScanRequest,
    CVEReference,
    EngineStatus,
    FileSecurityResult,
    ScanFindingViolation,
    SecurityHotspot,
    SecurityScanResult,
    SeverityDistribution,
    SeverityLevel,
    VulnerabilityTypeCount,
)
from models.security_models import SecurityLevel
from services.iac_scanner import is_iac_scan_candidate
from services.security_detector import (
    PartialAnalysisState,
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    all_engines_failed,
    get_security_detector,
)

logger = logging.getLogger(__name__)

#: Directories the whole-codebase walk never descends into. Kept as a denylist
#: for non-hidden caches/vendored trees; hidden directories are pruned by the
#: allowlist below so build artifacts (``.next``, ``.cache``, ``.yarn``,
#: ``.gradle``, ``.idea``, ``.hg`` ...) cannot flood the walk and push real
#: source out of ``max_files``.
_WALK_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        "venv",
        "__pycache__",
        "build",
        "dist",
        "target",
    }
)

#: Hidden directories that ARE walked: CI definitions (workflows, composite
#: actions, pipeline config) are a prime place for hardcoded secrets, and the
#: previous blanket dot-prune made them invisible to every engine. Every other
#: dot-directory (``.git``, ``.venv``, ``.repos``, ``.next``, ``.cache`` ...)
#: stays out.
_WALK_ALLOWED_HIDDEN_DIRS: frozenset[str] = frozenset({".github", ".circleci", ".gitlab"})

#: Files never admitted even when their suffix matches: detect-secrets' baseline
#: holds HASHES of known secrets, not the secrets themselves, so re-scanning it
#: only reports its own hashes.
_WALK_EXCLUDED_FILES: frozenset[str] = frozenset({".secrets.baseline"})

#: Engines whose findings make up the "code" area — everything the source and
#: config scanners produce. trivy-image is deliberately absent: OS-package CVEs
#: in the base image are reported separately as ``base_image_grade`` so a
#: CVE-heavy Dockerfile cannot hide (or be hidden by) the source findings.
_CODE_AREA_ENGINES: tuple[str, ...] = (
    ScanEngine.PATTERN,
    ScanEngine.BANDIT,
    ScanEngine.SEMGREP,
    ScanEngine.DETECT_SECRETS,
    ScanEngine.TRIVY_IAC,
)
_BASE_IMAGE_AREA_ENGINES: tuple[str, ...] = (ScanEngine.TRIVY_IMAGE,)

#: Weights from the detector's whole-scan risk formula
#: (``security_detector._analyze_security_results``). Duplicated deliberately:
#: a per-area risk score must be on the same scale as the overall score it
#: decomposes, and the detector's weights are not exported. Keep the two in step.
_SEVERITY_RISK_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.1,
}
_CONFIDENCE_RISK_WEIGHTS: dict[str, float] = {
    "very_high": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "very_low": 0.2,
}

#: A CVE identifier trivy reports for an OS package. Trivy also emits vendor
#: advisories (``ALAS-…``, ``DSA-…``, ``GHSA-…``); those stay on the finding but
#: are not CVE ids, so they never enter the CVE summary fields.
_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

#: Severity for the CVE summary. ``SeverityLevel`` has no INFO bucket, so an
#: unknown/INFO CVE maps to the lowest representable level (LOW).
_CVE_SEVERITY: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.LOW,
}


class SecurityScanService:
    """Service for performing container-scoped security scans and generating reports."""

    def __init__(self):
        """Initialize the SecurityScanService."""
        self.detector = get_security_detector()
        logger.info("SecurityScanService initialized")

    async def scan_container(
        self,
        container_info: ContainerInfo,
        scan_request: ContainerSecurityScanRequest,
        *,
        partial: PartialAnalysisState | None = None,
        deadline: float | None = None,
        force_degraded: bool = False,
    ) -> SecurityScanResult:
        """Perform a comprehensive security scan on a container.

        Args:
            container_info: Information about the container to scan
            scan_request: Security scan request parameters
            partial: Optional caller-held accumulator. When provided, the
                detector fills it incrementally so that if this coroutine is
                cancelled by an overall-deadline ``asyncio.wait_for`` the caller
                can rebuild a degraded result from the partial findings (see
                ``build_partial_result``) instead of discarding them.
            deadline: Absolute ``loop.time()`` value of the caller's wall-clock
                budget. The base-image engine budgets itself against what is
                left so it can never consume the whole scan.
            force_degraded: True when the caller knows the file set this scan
                examines is incomplete (a dropped chunk in the remote fetch).
                The flag MUST reach ``_assemble_scan_result`` so the coverage
                gate sees it: patching ``scan_degraded`` on the finished result
                leaves the grades computed as if coverage were complete, and a
                partial fetch then reads as ``D``/``A`` instead of ``F``.

        Returns:
            SecurityScanResult with comprehensive vulnerability information
        """
        start_time = datetime.now(UTC)
        logger.info(f"Starting security scan for container: {container_info.container_name}")

        # Resolve file paths to scan
        file_paths = await self._resolve_container_file_paths(
            container_info,
            scan_request.file_paths,
            scan_request.max_files,
        )

        logger.info(f"Scanning {len(file_paths)} files in container")

        # No files discovered → the scan saw nothing. Report the worst, honest
        # result (grade F, degraded) instead of letting a downstream empty
        # analysis grade "A" by scanning zero files. This is the fake-green the
        # oracle gate must never accept.
        if not file_paths:
            logger.error(
                "No scannable files discovered for container %s (codebase_path=%s); "
                "returning grade F (scan saw nothing)",
                container_info.container_name,
                container_info.codebase_path,
            )
            return SecurityScanResult(
                container_name=container_info.container_name,
                scan_timestamp=datetime.now(UTC),
                scan_duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                total_files_scanned=0,
                total_vulnerabilities=0,
                overall_risk_score=100.0,
                security_grade="F",
                finding_grade="F",
                code_grade="F",
                base_image_grade="F",
                scan_degraded=True,
                degraded_reasons=["no scannable files discovered"],
                engine_status={
                    k: EngineStatus.model_validate(v)
                    for k, v in all_engines_failed("no scannable files discovered").items()
                },
            )

        # Perform vulnerability detection
        analysis_result = await self.detector.analyze_security_vulnerabilities(
            file_paths=file_paths,
            include_low_confidence=scan_request.include_low_confidence,
            max_files=scan_request.max_files,
            partial=partial,
            deadline=deadline,
        )

        # Filter by severity if requested
        if scan_request.severity_filter:
            analysis_result = self._filter_by_severity(
                analysis_result,
                scan_request.severity_filter,
            )

        return await self._assemble_scan_result(
            analysis_result,
            container_info,
            start_time,
            force_degraded=force_degraded,
        )

    async def _assemble_scan_result(
        self,
        analysis_result: Any,
        container_info: ContainerInfo,
        start_time: datetime,
        *,
        force_degraded: bool = False,
    ) -> SecurityScanResult:
        """Build a SecurityScanResult from a (possibly partial) analysis result.

        Shared by the normal completion path and the timeout path so a degraded
        partial result is structurally identical to a full one — only the
        coverage/degraded flag and the finding counts differ. ``force_degraded``
        is set on the timeout path: a scan cut short by the deadline examined an
        unknown-incomplete slice, so it grades degraded regardless of what the
        analysis result itself recorded, but the findings it *did* surface are
        real and are carried through (never discarded to a fake zero).
        """
        # Build file-level results
        file_results = await self._build_file_results(
            analysis_result,
            container_info.codebase_path,
        )

        # Calculate severity counts
        severity_counts = self._calculate_severity_counts(analysis_result)

        # Calculate grades. risk_score stays informational: it is a per-file
        # average, so on a large repository it dilutes — the severity floor and
        # the per-area decomposition carry the signal. security_grade alone
        # keeps the coverage gate (fail closed).
        overall_risk_score = analysis_result.overall_risk_score
        total_files = analysis_result.total_files_analyzed
        degraded = analysis_result.scan_degraded or force_degraded
        all_matches = self._get_all_vulnerabilities(analysis_result)
        code_matches = [m for m in all_matches if m.engine != ScanEngine.TRIVY_IMAGE]
        base_image_matches = [m for m in all_matches if m.engine == ScanEngine.TRIVY_IMAGE]
        finding_grade = self._calculate_finding_grade(severity_counts, overall_risk_score)
        security_grade = self._calculate_security_grade(
            overall_risk_score,
            total_files,
            degraded,
            severity_counts,
        )
        code_grade = self._calculate_area_grade(
            code_matches,
            total_files,
            analysis_result.engine_status,
            _CODE_AREA_ENGINES,
            coverage_incomplete=force_degraded,
        )
        base_image_grade = self._calculate_area_grade(
            base_image_matches,
            total_files,
            analysis_result.engine_status,
            _BASE_IMAGE_AREA_ENGINES,
            coverage_incomplete=force_degraded,
        )
        cve_count, cve_references = self._build_cve_summary(base_image_matches)
        base_images = self._build_base_image_coverage(analysis_result, container_info.codebase_path)
        degraded_reasons = list(analysis_result.degraded_reasons)
        # Fail closed on the machine-readable signal too: a row that says an
        # image was not scanned must make the scan degraded even if the engine
        # status somehow did not.
        if any(image.status == "unresolved" for image in base_images) and not degraded:
            degraded = True
            degraded_reasons.append("base image coverage incomplete")

        # Build vulnerability summary
        vulnerability_summary = self._build_vulnerability_summary(analysis_result)

        # Get affected files list
        affected_files = list(
            set(v.file_path for v in self._get_all_vulnerabilities(analysis_result))
        )
        affected_files = [os.path.relpath(f, container_info.codebase_path) for f in affected_files]

        scan_duration = (datetime.now(UTC) - start_time).total_seconds()

        result = SecurityScanResult(
            container_name=container_info.container_name,
            scan_timestamp=datetime.now(UTC),
            scan_duration_seconds=scan_duration,
            total_files_scanned=analysis_result.total_files_analyzed,
            total_vulnerabilities=analysis_result.total_vulnerabilities_found,
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            overall_risk_score=overall_risk_score,
            security_grade=security_grade,
            finding_grade=finding_grade,
            code_grade=code_grade,
            base_image_grade=base_image_grade,
            base_images=base_images,
            cve_count=cve_count,
            cve_references=cve_references,
            scan_degraded=degraded,
            engine_status={
                k: EngineStatus.model_validate(v) for k, v in analysis_result.engine_status.items()
            },
            degraded_reasons=degraded_reasons,
            suppressed_findings=dict(getattr(analysis_result, "suppressed_findings", {}) or {}),
            file_results=file_results,
            vulnerability_summary=vulnerability_summary,
            affected_files=affected_files,
        )

        logger.info(
            f"Security scan assembled for {container_info.container_name}: "
            f"{result.total_vulnerabilities} vulnerabilities found, "
            f"risk score: {overall_risk_score:.2f}, grade: {security_grade}, "
            f"degraded: {degraded}"
        )

        return result

    async def build_partial_result(
        self,
        container_info: ContainerInfo,
        partial: PartialAnalysisState,
        elapsed_seconds: float,
    ) -> SecurityScanResult:
        """Assemble a degraded result from findings gathered before a scan timeout.

        Called by the router's bounded-scan handler when the overall deadline
        fires. Instead of discarding the vulnerabilities the completed engines
        already found (and returning a fake "F, 0 files"), surface them flagged
        ``scan_degraded``. If nothing was gathered yet (timeout before any file
        or engine completed) this yields the same honest zero-coverage grade-F
        result as before — never a fake pass.
        """
        start_time = datetime.now(UTC)
        analysis_result = await self.detector.result_from_partial(partial)
        result = await self._assemble_scan_result(
            analysis_result, container_info, start_time, force_degraded=True
        )
        result.scan_duration_seconds = elapsed_seconds
        return result

    async def generate_security_report(
        self,
        container_info: ContainerInfo,
        scan_result: SecurityScanResult,
    ) -> ContainerSecurityReport:
        """Generate a comprehensive security report for a container.

        Args:
            container_info: Information about the container
            scan_result: Security scan result to generate report from

        Returns:
            ContainerSecurityReport with detailed security analysis
        """
        logger.info(f"Generating security report for container: {container_info.container_name}")

        # Build severity distribution
        severity_distribution = SeverityDistribution(
            critical=scan_result.critical_count,
            high=scan_result.high_count,
            medium=scan_result.medium_count,
            low=scan_result.low_count,
            info=scan_result.info_count,
        )

        # Build vulnerability type breakdown
        vulnerability_types = self._build_vulnerability_type_breakdown(scan_result)

        # Identify security hotspots
        security_hotspots = self._identify_security_hotspots(scan_result)

        # Extract top priorities (critical and high severity violations)
        top_priorities = self._extract_top_priorities(scan_result)

        # Generate recommendations
        recommendations = self._generate_recommendations(scan_result)

        # Build language breakdown
        language_breakdown = self._build_language_breakdown(scan_result)

        # Calculate file counts
        affected_files_count = len(scan_result.affected_files)
        clean_files_count = scan_result.total_files_scanned - affected_files_count

        report = ContainerSecurityReport(
            container_name=container_info.container_name,
            report_generated_at=datetime.now(UTC),
            scan_summary=scan_result,
            severity_distribution=severity_distribution,
            vulnerability_types=vulnerability_types,
            security_hotspots=security_hotspots,
            top_priorities=top_priorities,
            security_score=scan_result.overall_risk_score,
            security_grade=scan_result.security_grade,
            scan_degraded=scan_result.scan_degraded,
            recommendations=recommendations,
            affected_files_count=affected_files_count,
            clean_files_count=clean_files_count,
            language_breakdown=language_breakdown,
        )

        logger.info(
            f"Security report generated for {container_info.container_name}: "
            f"{affected_files_count} affected files, {clean_files_count} clean files"
        )

        return report

    async def _resolve_container_file_paths(
        self,
        container_info: ContainerInfo,
        file_paths: list[str] | None,
        max_files: int | None,
    ) -> list[str]:
        """Resolve file paths within container for scanning.

        Args:
            container_info: Container information
            file_paths: Optional specific file paths to scan
            max_files: Maximum number of files to scan

        Returns:
            List of absolute file paths to scan
        """
        codebase_path = container_info.codebase_path

        if file_paths:
            # Resolve specific file paths relative to container
            resolved_paths = []
            for file_path in file_paths:
                abs_path = os.path.join(codebase_path, file_path)
                if os.path.exists(abs_path):
                    resolved_paths.append(abs_path)
                else:
                    logger.warning(f"File not found in container: {file_path}")
            return resolved_paths

        # Scan all supported files in the container
        valid_files = []
        supported_extensions = [
            ".py",
            ".java",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".vue",
            ".svelte",
            ".go",
            ".rs",
            ".cs",
            ".cpp",
            ".c",
            ".h",
            ".hpp",
            ".php",
            ".rb",
        ]

        for root, dirs, files in os.walk(codebase_path):
            # Only the CI-definition dot-directories are walked; everything
            # else hidden (VCS, caches, build artifacts) is pruned.
            dirs[:] = [
                d
                for d in dirs
                if (not d.startswith(".") or d in _WALK_ALLOWED_HIDDEN_DIRS)
                and d not in _WALK_EXCLUDED_DIRS
            ]

            for file in files:
                abs_path = os.path.join(root, file)
                # Environment files have no suffix, so they need a name-based
                # admission. ``.env`` and ``.env.*`` (``.env.local``,
                # ``.env.production``, ...) hold exactly the secrets
                # detect-secrets exists to find.
                is_env_file = file == ".env" or file.startswith(".env.")
                if file in _WALK_EXCLUDED_FILES:
                    continue
                # Source-code SAST (bandit/semgrep/detect-secrets/regex) keys off
                # these extensions. ALSO collect IaC manifests
                # (Dockerfile/Terraform/YAML/CloudFormation-json) so the
                # trivy-config iac_scanner producer actually receives them — the
                # whole-codebase walk previously dropped every IaC file, leaving
                # the IaC engine inert in this primary scan path.
                if (
                    any(file.endswith(ext) for ext in supported_extensions)
                    or is_iac_scan_candidate(abs_path)
                    or is_env_file
                ):
                    valid_files.append(abs_path)

        # Apply max_files limit if specified
        if max_files and len(valid_files) > max_files:
            logger.warning(f"Found {len(valid_files)} files, limiting to {max_files}")
            valid_files = valid_files[:max_files]

        return valid_files

    def _filter_by_severity(self, analysis_result, severity_filter: list[str]):
        """Filter analysis results by severity levels."""
        filtered_severities = {VulnerabilitySeverity(s) for s in severity_filter}

        # Filter vulnerabilities by type
        for vuln_type, matches in analysis_result.vulnerabilities_by_type.items():
            analysis_result.vulnerabilities_by_type[vuln_type] = [
                m for m in matches if m.severity in filtered_severities
            ]

        # Filter vulnerabilities by severity
        analysis_result.vulnerabilities_by_severity = {
            severity: matches
            for severity, matches in analysis_result.vulnerabilities_by_severity.items()
            if severity in filtered_severities
        }

        # Update counts
        total_filtered = sum(
            len(matches) for matches in analysis_result.vulnerabilities_by_type.values()
        )
        analysis_result.total_vulnerabilities_found = total_filtered

        return analysis_result

    async def _build_file_results(
        self,
        analysis_result,
        codebase_path: str,
    ) -> list[FileSecurityResult]:
        """Build file-level security results from analysis."""
        file_results_dict: dict[str, dict[str, Any]] = {}

        all_vulnerabilities = self._get_all_vulnerabilities(analysis_result)

        for vuln in all_vulnerabilities:
            file_path = vuln.file_path
            relative_path = os.path.relpath(file_path, codebase_path)

            if relative_path not in file_results_dict:
                file_results_dict[relative_path] = {
                    "language": vuln.language,
                    "violations": [],
                    "severities": [],
                    "cve_ids": [],
                }

            # Convert VulnerabilityMatch to SecurityViolation
            # model_validate (not kwargs): ``engine`` is checked against the
            # contract's Literal at runtime, so a producer that emits an
            # unknown or empty engine fails loudly here instead of shipping.
            violation = ScanFindingViolation.model_validate(
                {
                    "engine": vuln.engine,
                    "type": vuln.vulnerability_type.value,
                    "severity": SecurityLevel(vuln.severity.value),
                    "line_number": vuln.line_start,
                    "pattern_matched": vuln.pattern_id,
                    "description": vuln.description,
                    "suggested_fix": vuln.remediation_advice,
                    # Structured base-image context; None for every other engine.
                    "package_name": vuln.package_name or None,
                    "installed_version": vuln.installed_version or None,
                    "fixed_version": vuln.fixed_version or None,
                    "fix_available": (
                        vuln.fix_available if vuln.engine == ScanEngine.TRIVY_IMAGE else None
                    ),
                    "image_ref": vuln.image_ref or None,
                }
            )

            file_results_dict[relative_path]["violations"].append(violation)
            file_results_dict[relative_path]["severities"].append(vuln.severity.value)
            if vuln.engine == ScanEngine.TRIVY_IMAGE and _CVE_ID_PATTERN.fullmatch(vuln.pattern_id):
                file_results_dict[relative_path]["cve_ids"].append(vuln.pattern_id)

        # Build FileSecurityResult objects
        file_results = []
        for file_path, data in file_results_dict.items():
            violations = data["violations"]
            severities = data["severities"]

            # Calculate highest severity
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            highest_severity = min(severities, key=lambda s: severity_order.get(s, 999))

            # Calculate file risk score
            risk_score = self._calculate_file_risk_score(violations)

            file_result = FileSecurityResult(
                file_path=file_path,
                language=data["language"],
                vulnerabilities_found=len(violations),
                highest_severity=highest_severity,
                violations=violations,
                risk_score=risk_score,
                cve_ids=sorted(set(data["cve_ids"])),
            )
            file_results.append(file_result)

        return file_results

    def _get_all_vulnerabilities(self, analysis_result) -> list[VulnerabilityMatch]:
        """Extract all vulnerability matches from analysis result."""
        all_vulnerabilities = []
        for matches in analysis_result.vulnerabilities_by_type.values():
            all_vulnerabilities.extend(matches)
        return all_vulnerabilities

    def _calculate_severity_counts(self, analysis_result) -> dict[str, int]:
        """Calculate counts for each severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for severity, matches in analysis_result.vulnerabilities_by_severity.items():
            counts[severity.value] = len(matches)

        return counts

    def _risk_grade(self, risk_score: float) -> str:
        """Map a risk score to the A-F ladder.

        The score is a whole-scan average, so on a large repository it is
        diluted: five critical findings among 994 files can read as ~1/100.
        The ladder therefore never decides a grade on its own —
        ``_severity_floor_grade`` applies the finding floor on top of it.
        """
        if risk_score <= 10:
            return "A"
        elif risk_score <= 25:
            return "B"
        elif risk_score <= 50:
            return "C"
        elif risk_score <= 75:
            return "D"
        else:
            return "F"

    def _severity_floor_grade(self, severity_counts: dict[str, int], risk_grade: str) -> str:
        """Apply the finding-severity floor to a risk-ladder grade.

        Any critical finding is an F. Any high finding caps the grade at D.
        Without this floor the risk score's per-file average buries real
        high-severity findings: 5 criticals in 994 files averaged 0.98/100 and
        would have graded A. The floor only ever worsens a grade, never
        improves one.
        """
        if severity_counts.get("critical", 0) > 0:
            return "F"
        if severity_counts.get("high", 0) > 0 and risk_grade in ("A", "B", "C"):
            return "D"
        return risk_grade

    def _calculate_finding_grade(self, severity_counts: dict[str, int], risk_score: float) -> str:
        """Grade from findings alone: the severity floor on the risk ladder.

        Coverage is deliberately not part of this grade — it answers "how bad
        are the findings that were seen", while ``security_grade`` answers
        "can this scan be trusted". The latter still fails closed on coverage.
        """
        return self._severity_floor_grade(severity_counts, self._risk_grade(risk_score))

    def _calculate_security_grade(
        self,
        risk_score: float,
        files_scanned: int,
        degraded: bool,
        severity_counts: dict[str, int],
    ) -> str:
        """Calculate security grade from findings, risk score and scan coverage.

        Coverage gates the grade BEFORE any severity or risk threshold: a scan
        that examined nothing (``files_scanned == 0``) or could not examine
        everything it was asked to (``degraded``) grades ``F``. Grading a
        zero-coverage or degraded scan on findings alone yields a fake "A"
        (clean because nothing was looked at), which the oracle gate would
        read as a genuine pass.

        With coverage complete the grade is the finding grade: the severity
        floor (critical → F, high → at most D) applied to the risk ladder.
        ``risk_score`` is informational — a per-file average must never be the
        only input to a grade.

        Args:
            risk_score: Risk score from 0-100 (whole-scan average)
            files_scanned: Number of files actually examined
            degraded: True when the scan could not examine everything requested
            severity_counts: Findings counted by severity

        Returns:
            Security grade: A, B, C, D, or F
        """
        if files_scanned == 0 or degraded:
            return "F"
        return self._calculate_finding_grade(severity_counts, risk_score)

    @staticmethod
    def _engine_status_value(status: Any) -> str | None:
        """Read an engine's status whether it is a dict or an EngineStatus."""
        if isinstance(status, dict):
            return status.get("status")
        return getattr(status, "status", None)

    def _calculate_area_risk_score(
        self, matches: list[VulnerabilityMatch], total_files: int
    ) -> float:
        """Risk contribution of one finding area, on the whole-scan scale.

        Same formula and denominator as the detector's overall score
        (``Σ severity_weight × confidence_weight / files analyzed``), so this is
        the part of ``overall_risk_score`` attributable to the area.
        """
        total = 0.0
        for match in matches:
            severity = (
                match.severity.value
                if isinstance(match.severity, VulnerabilitySeverity)
                else str(match.severity)
            )
            confidence = (
                match.confidence.value
                if isinstance(match.confidence, VulnerabilityConfidence)
                else str(match.confidence)
            )
            total += _SEVERITY_RISK_WEIGHTS.get(severity, 0.0) * _CONFIDENCE_RISK_WEIGHTS.get(
                confidence, 0.0
            )
        return min(total / max(total_files, 1), 100.0)

    def _calculate_area_grade(
        self,
        matches: list[VulnerabilityMatch],
        total_files: int,
        engine_status: dict[str, Any],
        engines: tuple[str, ...],
        *,
        coverage_incomplete: bool = False,
    ) -> str:
        """Grade one finding area from its findings and its engines' coverage.

        Fail closed: when any engine responsible for the area did not run to
        completion, the area is unmeasured and grades F even if the findings
        that were seen look clean. An unchecked area must never read as clean.

        ``coverage_incomplete`` covers the case the engine status cannot see:
        the caller knows the file set is incomplete (a dropped chunk in the
        remote fetch). Every engine can then report ``ok`` over a slice of the
        repository, and grading the areas on that slice reads "A" for an area
        whose files were simply never fetched. F is the only honest answer.
        """
        if coverage_incomplete:
            return "F"
        for name in engines:
            if self._engine_status_value(engine_status.get(name)) != "ok":
                return "F"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for match in matches:
            severity = (
                match.severity.value
                if isinstance(match.severity, VulnerabilitySeverity)
                else str(match.severity)
            )
            if severity in counts:
                counts[severity] += 1
        risk_score = self._calculate_area_risk_score(matches, total_files)
        return self._calculate_finding_grade(counts, risk_score)

    def _build_cve_summary(
        self, matches: list[VulnerabilityMatch]
    ) -> tuple[int, list[CVEReference]]:
        """Distinct CVE ids and reference rows from the base-image findings.

        Only trivy-image findings carry package CVEs, and only CVE-shaped ids
        are summarised — trivy also emits vendor advisories (``ALAS-…``,
        ``DSA-…``, ``GHSA-…``) which stay on the finding itself. One
        ``CVEReference`` per distinct id; references from repeated occurrences
        (the same CVE in several packages or Dockerfiles) are unioned in
        first-seen order.
        """
        first: dict[str, VulnerabilityMatch] = {}
        references: dict[str, list[str]] = {}
        for match in matches:
            if match.engine != ScanEngine.TRIVY_IMAGE:
                continue
            cve_id = match.pattern_id
            if not _CVE_ID_PATTERN.fullmatch(cve_id):
                continue
            first.setdefault(cve_id, match)
            references[cve_id] = list(
                dict.fromkeys([*references.get(cve_id, []), *match.references])
            )

        summary: list[CVEReference] = []
        for cve_id in sorted(first):
            match = first[cve_id]
            description = (
                match.title
                or match.description
                or (f"{cve_id} reported by trivy-image in a base image")
            )
            description = description[:5000]
            if len(description) < 10:
                description = f"{cve_id} reported by trivy-image in a base image"
            summary.append(
                CVEReference(
                    cve_id=cve_id,
                    description=description,
                    severity=_CVE_SEVERITY.get(match.severity.value, SeverityLevel.LOW),
                    cvss_score=match.cvss_score,
                    references=references[cve_id],
                )
            )
        return len(first), summary

    def _build_base_image_coverage(
        self, analysis_result, codebase_path: str
    ) -> list[BaseImageCoverage]:
        """Validate the engine's coverage rows and relativise their paths.

        The engine reports absolute Dockerfile paths; the API reports paths
        relative to the workspace, like ``file_results`` does.
        """
        coverage: list[BaseImageCoverage] = []
        for row in getattr(analysis_result, "base_images", None) or []:
            row = dict(row)
            dockerfile = row.get("dockerfile")
            if isinstance(dockerfile, str):
                row["dockerfile"] = os.path.relpath(dockerfile, codebase_path)
            coverage.append(BaseImageCoverage.model_validate(row))
        return coverage

    def _calculate_file_risk_score(self, violations: list[ScanFindingViolation]) -> float:
        """Calculate risk score for a single file."""
        severity_weights = {
            SecurityLevel.CRITICAL: 10.0,
            SecurityLevel.HIGH: 7.0,
            SecurityLevel.MEDIUM: 4.0,
            SecurityLevel.LOW: 1.0,
        }

        total_score = sum(severity_weights.get(v.severity, 0) for v in violations)
        return min(total_score, 100.0)

    def _build_vulnerability_summary(self, analysis_result) -> dict[str, int]:
        """Build summary of vulnerabilities by type."""
        summary = {}
        for vuln_type, matches in analysis_result.vulnerabilities_by_type.items():
            if matches:
                summary[vuln_type.value] = len(matches)
        return summary

    def _build_vulnerability_type_breakdown(
        self,
        scan_result: SecurityScanResult,
    ) -> list[VulnerabilityTypeCount]:
        """Build breakdown of vulnerabilities by type."""
        type_breakdown = []

        # Count vulnerabilities by type
        type_counts = Counter()
        type_severities = {}

        for file_result in scan_result.file_results:
            for violation in file_result.violations:
                vuln_type = violation.type
                type_counts[vuln_type] += 1

                # Track most severe level for this type
                if vuln_type not in type_severities:
                    type_severities[vuln_type] = violation.severity.value
                else:
                    current_severity = type_severities[vuln_type]
                    severity_order = {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                        "low": 3,
                        "info": 4,
                    }
                    if severity_order.get(violation.severity.value, 999) < severity_order.get(
                        current_severity, 999
                    ):
                        type_severities[vuln_type] = violation.severity.value

        for vuln_type, count in type_counts.most_common():
            type_breakdown.append(
                VulnerabilityTypeCount(
                    type=vuln_type,
                    count=count,
                    severity=type_severities[vuln_type],
                )
            )

        return type_breakdown

    def _identify_security_hotspots(
        self,
        scan_result: SecurityScanResult,
    ) -> list[SecurityHotspot]:
        """Identify files with multiple vulnerabilities (security hotspots)."""
        hotspots = []

        for file_result in scan_result.file_results:
            # Consider files with 3+ vulnerabilities as hotspots
            if file_result.vulnerabilities_found >= 3:
                hotspot = SecurityHotspot(
                    file_path=file_result.file_path,
                    vulnerability_count=file_result.vulnerabilities_found,
                    highest_severity=file_result.highest_severity,
                    risk_score=file_result.risk_score,
                )
                hotspots.append(hotspot)

        # Sort by vulnerability count (descending)
        hotspots.sort(key=lambda h: h.vulnerability_count, reverse=True)

        return hotspots[:10]  # Return top 10 hotspots

    def _extract_top_priorities(
        self,
        scan_result: SecurityScanResult,
    ) -> list[ScanFindingViolation]:
        """Extract top priority vulnerabilities (critical and high severity)."""
        priorities = []

        for file_result in scan_result.file_results:
            for violation in file_result.violations:
                if violation.severity in [SecurityLevel.CRITICAL, SecurityLevel.HIGH]:
                    priorities.append(violation)

        # Sort by severity (critical first) and then by line number
        severity_order = {SecurityLevel.CRITICAL: 0, SecurityLevel.HIGH: 1}
        priorities.sort(
            key=lambda v: (
                severity_order.get(v.severity, 999),
                v.line_number or 0,
            )
        )

        return priorities[:20]  # Return top 20 priorities

    def _generate_recommendations(
        self,
        scan_result: SecurityScanResult,
    ) -> list[str]:
        """Generate security improvement recommendations."""
        recommendations = []

        # Check critical vulnerabilities
        if scan_result.critical_count > 0:
            recommendations.append(
                f"URGENT: Address {scan_result.critical_count} critical security "
                f"vulnerabilities immediately. These pose severe security risks."
            )

        # Check high severity vulnerabilities
        if scan_result.high_count > 0:
            recommendations.append(
                f"High Priority: Fix {scan_result.high_count} high severity vulnerabilities as soon as possible."
            )

        # Check security hotspots
        if scan_result.file_results:
            hotspot_files = [f for f in scan_result.file_results if f.vulnerabilities_found >= 3]
            if hotspot_files:
                recommendations.append(
                    f"Security Hotspots: {len(hotspot_files)} files contain multiple "
                    f"vulnerabilities. Consider refactoring these files."
                )

        # Check overall security grade
        if scan_result.security_grade in ["D", "F"]:
            recommendations.append(
                f"Security Grade {scan_result.security_grade}: Implement comprehensive "
                f"security review and testing practices."
            )

        # General recommendations
        if scan_result.total_vulnerabilities > 0:
            recommendations.extend(
                [
                    "Implement automated security scanning in CI/CD pipeline",
                    "Conduct regular security code reviews",
                    "Keep dependencies up-to-date to patch known vulnerabilities",
                    "Follow secure coding best practices for all languages used",
                ]
            )

        # If no vulnerabilities found
        if scan_result.total_vulnerabilities == 0:
            recommendations.append(
                "Excellent! No vulnerabilities detected. Continue following security best practices."
            )

        return recommendations

    def _build_language_breakdown(
        self,
        scan_result: SecurityScanResult,
    ) -> dict[str, int]:
        """Build breakdown of vulnerabilities by programming language."""
        language_breakdown = Counter()

        for file_result in scan_result.file_results:
            if file_result.vulnerabilities_found > 0:
                language_breakdown[file_result.language] += file_result.vulnerabilities_found

        return dict(language_breakdown)


# Singleton instance
_security_scan_service: SecurityScanService | None = None


def get_security_scan_service() -> SecurityScanService:
    """Get or create the global security scan service instance."""
    global _security_scan_service
    if _security_scan_service is None:
        _security_scan_service = SecurityScanService()
        logger.info("Initialized global security scan service")
    return _security_scan_service
