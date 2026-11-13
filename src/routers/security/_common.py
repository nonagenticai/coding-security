"""Shared helpers and shared response models for the security router package.

Co-located here so each per-resource submodule stays under 300 lines and so
that the package ``__init__`` can re-export the names tests patch as
``routers.security.X``.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from models.common import BaseResponse, ResponseStatus
from models.responses import bad_request
from services.security_detector import (
    SecurityAnalysisResult,
    VulnerabilityMatch,
    VulnerabilitySeverity,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Request / response models shared across endpoints
# ----------------------------------------------------------------------------


class SecurityAnalysisRequest(BaseModel):
    """Request for security vulnerability analysis."""

    container_name: str | None = Field(
        None, description="Container name to analyze for vulnerabilities"
    )
    file_paths: list[str] | None = Field(
        None, description="Specific file paths within container to analyze"
    )
    include_low_confidence: bool = Field(
        True,
        description="Whether to include low confidence vulnerability findings",
    )
    max_files: int | None = Field(
        None,
        ge=1,
        le=1000,
        description="Maximum number of files to analyze (performance limit)",
    )
    severity_filter: list[str] | None = Field(
        None,
        description="Filter results by severity levels: critical, high, medium, low, info",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "container_name": "api-service",
                "file_paths": [
                    "src/auth.py",
                    "lib/database.java",
                    "api/handlers.go",
                ],
                "include_low_confidence": True,
                "max_files": 100,
                "severity_filter": ["critical", "high"],
            },
        }
    )


class VulnerabilityMatchModel(BaseModel):
    """
    Vulnerability match response model.

    Represents a single security vulnerability found during code analysis,
    containing details about the vulnerability, its location, severity,
    and remediation suggestions.
    """

    id: str
    vulnerability_type: str
    severity: str
    confidence: str

    file_path: str
    language: str
    line_start: int
    line_end: int
    function_name: str | None = None
    class_name: str | None = None

    pattern_id: str
    title: str
    description: str
    code_snippet: str

    cwe_ids: list[str]
    owasp_categories: list[str]
    cvss_score: float | None = None

    remediation_advice: str
    resolve_suggestions: list[str]
    references: list[str]

    matched_patterns: list[str]
    context_evidence: dict[str, Any]
    false_positive_likelihood: float


class SecurityAnalysisResponseModel(BaseModel):
    """
    Security analysis result response model.

    Contains comprehensive results from a security vulnerability analysis,
    including vulnerability counts, categorizations, risk metrics, and
    remediation recommendations.
    """

    total_files_analyzed: int
    total_vulnerabilities_found: int
    analysis_time_seconds: float

    vulnerabilities_by_type: dict[str, list[VulnerabilityMatchModel]]
    vulnerabilities_by_severity: dict[str, list[VulnerabilityMatchModel]]
    vulnerabilities_by_confidence: dict[str, list[VulnerabilityMatchModel]]

    language_distribution: dict[str, int]
    vulnerabilities_by_language: dict[str, list[VulnerabilityMatchModel]]

    overall_risk_score: float
    critical_issues_count: int
    high_severity_count: int

    most_common_vulnerability: str | None = None
    security_hotspots: list[str]

    priority_fixes: list[VulnerabilityMatchModel]
    security_improvements: list[str]

    # Coverage. A result that examined fewer files than requested (or none)
    # is degraded: zero findings over zero files is "not computed", not clean.
    scan_degraded: bool = False
    files_failed_to_parse: int = 0
    degraded_reasons: list[str] = Field(default_factory=list)
    # False-positive filter actions by reason (see services.finding_filters).
    suppressed_findings: dict[str, int] = Field(default_factory=dict)


class SecurityAnalysisResponse(BaseResponse):
    """
    Response from security vulnerability analysis operation.

    Wraps the security analysis results in a standardized response format
    with status and metadata information.
    """

    status: ResponseStatus = ResponseStatus.SUCCESS
    result: SecurityAnalysisResponseModel = Field(..., description="Security analysis result")


# ----------------------------------------------------------------------------
# Conversion + validation helpers
# ----------------------------------------------------------------------------


def _convert_match_to_model(
    match: VulnerabilityMatch,
) -> VulnerabilityMatchModel:
    """Convert VulnerabilityMatch to response model."""
    return VulnerabilityMatchModel(
        id=match.id,
        vulnerability_type=match.vulnerability_type.value,
        severity=match.severity.value,
        confidence=match.confidence.value,
        file_path=match.file_path,
        language=match.language,
        line_start=match.line_start,
        line_end=match.line_end,
        function_name=match.function_name,
        class_name=match.class_name,
        pattern_id=match.pattern_id,
        title=match.title,
        description=match.description,
        code_snippet=match.code_snippet,
        cwe_ids=match.cwe_ids,
        owasp_categories=match.owasp_categories,
        cvss_score=match.cvss_score,
        remediation_advice=match.remediation_advice,
        resolve_suggestions=match.resolve_suggestions,
        references=match.references,
        matched_patterns=match.matched_patterns,
        context_evidence=match.context_evidence,
        false_positive_likelihood=match.false_positive_likelihood,
    )


def _validate_severity_filter(severity_filter: list[str] | None) -> None:
    """Validate severity filter values."""
    if not severity_filter:
        return

    valid_severities = [s.value for s in VulnerabilitySeverity]
    invalid_severities = [s for s in severity_filter if s not in valid_severities]
    if invalid_severities:
        raise bad_request(
            f"Invalid severity levels: {', '.join(invalid_severities)}. "
            f"Valid levels: {', '.join(valid_severities)}"
        )


def _filter_results_by_severity(result: SecurityAnalysisResult, severity_filter: list[str]) -> None:
    """Filter security analysis results to the requested severity levels.

    The response surfaces vulnerabilities grouped by type, severity, confidence
    and language, plus derived counts (critical/high), priority fixes, security
    hotspots and the most-common type. The previous implementation only pruned
    ``vulnerabilities_by_type`` and ``vulnerabilities_by_severity`` — it left the
    confidence/language views, ``priority_fixes``, the critical/high counts, the
    hotspots and ``most_common_vulnerability`` reflecting the UNFILTERED scan. A
    caller asking for ``["critical"]`` therefore still saw lower-severity vulns
    in ``vulnerabilities_by_confidence`` / ``vulnerabilities_by_language`` /
    ``priority_fixes`` and a ``critical_issues_count`` that could contradict
    ``total_vulnerabilities_found``. Re-derive every per-match view and count from
    the surviving matches so the filtered result is internally consistent.

    ``overall_risk_score`` (whole-codebase posture) and ``language_distribution``
    (files analyzed per language, not a per-vuln view) intentionally describe the
    whole scan and are left unchanged.
    """
    filtered_severities = {VulnerabilitySeverity(s) for s in severity_filter}

    # ``vulnerabilities_by_type`` holds every vulnerability exactly once, so it is
    # the authoritative source for the surviving set.
    surviving = [
        m
        for matches in result.vulnerabilities_by_type.values()
        for m in matches
        if m.severity in filtered_severities
    ]

    def _group_by(key: Any) -> dict:
        grouped: dict = {}
        for m in surviving:
            grouped.setdefault(key(m), []).append(m)
        return grouped

    result.vulnerabilities_by_type = _group_by(lambda m: m.vulnerability_type)
    result.vulnerabilities_by_severity = _group_by(lambda m: m.severity)
    result.vulnerabilities_by_confidence = _group_by(lambda m: m.confidence)
    result.vulnerabilities_by_language = _group_by(lambda m: m.language)

    result.total_vulnerabilities_found = len(surviving)
    result.critical_issues_count = sum(
        1 for m in surviving if m.severity == VulnerabilitySeverity.CRITICAL
    )
    result.high_severity_count = sum(
        1 for m in surviving if m.severity == VulnerabilitySeverity.HIGH
    )
    result.priority_fixes = [m for m in result.priority_fixes if m.severity in filtered_severities]

    file_vuln_counts = Counter(m.file_path for m in surviving)
    result.security_hotspots = [fp for fp, count in file_vuln_counts.items() if count >= 3]
    result.most_common_vulnerability = (
        Counter(m.vulnerability_type for m in surviving).most_common(1)[0][0] if surviving else None
    )


def _convert_result_to_model(
    result: SecurityAnalysisResult,
) -> SecurityAnalysisResponseModel:
    """Convert SecurityAnalysisResult to response model."""

    # Convert vulnerabilities by type
    vulns_by_type = {}
    for vuln_type, matches in result.vulnerabilities_by_type.items():
        vulns_by_type[vuln_type.value] = [_convert_match_to_model(m) for m in matches]

    # Convert vulnerabilities by severity
    vulns_by_severity = {}
    for severity, matches in result.vulnerabilities_by_severity.items():
        vulns_by_severity[severity.value] = [_convert_match_to_model(m) for m in matches]

    # Convert vulnerabilities by confidence
    vulns_by_confidence = {}
    for confidence, matches in result.vulnerabilities_by_confidence.items():
        vulns_by_confidence[confidence.value] = [_convert_match_to_model(m) for m in matches]

    # Convert vulnerabilities by language
    vulns_by_language = {}
    for language, matches in result.vulnerabilities_by_language.items():
        vulns_by_language[language] = [_convert_match_to_model(m) for m in matches]

    # Convert priority fixes
    priority_fixes = [_convert_match_to_model(m) for m in result.priority_fixes]

    return SecurityAnalysisResponseModel(
        total_files_analyzed=result.total_files_analyzed,
        total_vulnerabilities_found=result.total_vulnerabilities_found,
        analysis_time_seconds=result.analysis_time_seconds,
        vulnerabilities_by_type=vulns_by_type,
        vulnerabilities_by_severity=vulns_by_severity,
        vulnerabilities_by_confidence=vulns_by_confidence,
        language_distribution=result.language_distribution,
        vulnerabilities_by_language=vulns_by_language,
        overall_risk_score=result.overall_risk_score,
        critical_issues_count=result.critical_issues_count,
        high_severity_count=result.high_severity_count,
        most_common_vulnerability=(
            result.most_common_vulnerability.value if result.most_common_vulnerability else None
        ),
        security_hotspots=result.security_hotspots,
        priority_fixes=priority_fixes,
        security_improvements=result.security_improvements,
        scan_degraded=result.scan_degraded,
        files_failed_to_parse=result.files_failed_to_parse,
        suppressed_findings=dict(result.suppressed_findings),
    )
