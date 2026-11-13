"""Security API Models for Container-Scoped Security Analysis.

This module provides comprehensive API models for security scanning, vulnerability detection,
and security reporting at the container level.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from models.common import SAFE_STRING_PATTERN, BaseResponse
from models.image_scan_models import ImageScanResult, SBOMResult
from models.security_models import SecurityViolation
from models.workspace_repos import REPO_FIELD_DESCRIPTION, normalize_repo

#: Canonical dependency ecosystem keys: what the ``ecosystem`` selectors accept
#: and what ``GET /api/security/patterns`` advertises in ``dependency_ecosystems``.
DEPENDENCY_ECOSYSTEMS: tuple[str, ...] = ("pypi", "crates.io")


def canonical_ecosystem(value: Any) -> Any:
    """Case-insensitive ecosystem key -> its canonical form (``PyPI`` -> ``pypi``).

    OSV names ecosystems ``PyPI`` / ``crates.io``; callers that copy an
    OSV or advertised name must not get a 422 for its case.
    """
    return value.strip().lower() if isinstance(value, str) else value


#: Dependency ecosystem selector of the dependency list route.
Ecosystem = Annotated[Literal["auto", "pypi", "crates.io"], BeforeValidator(canonical_ecosystem)]


class SeverityLevel(StrEnum):
    """Enumeration of vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilitySource(StrEnum):
    """Enumeration of vulnerability sources."""

    CVE = "cve"
    OSV = "osv"
    SAFETY = "safety"
    PATTERN = "pattern"
    PIP_AUDIT = "pip_audit"
    TRIVY = "trivy"
    GRYPE = "grype"


# CVE and OSV Vulnerability Models


class CVEReference(BaseModel):
    """Model for Common Vulnerabilities and Exposures (CVE) information."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2021-44228",
                "description": "Apache Log4j2 allows JNDI features used in configuration do not protect against attacker controlled LDAP.",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "published_date": "2021-12-10T00:00:00",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                ],
            }
        },
    )

    cve_id: str = Field(
        ...,
        description="CVE identifier (e.g., CVE-2021-44228)",
        pattern=r"^CVE-\d{4}-\d{4,}$",
    )
    description: str = Field(
        ...,
        description="Detailed vulnerability description",
        min_length=10,
        max_length=5000,
        pattern=SAFE_STRING_PATTERN,
    )
    severity: SeverityLevel = Field(
        ...,
        description="Vulnerability severity level",
    )
    cvss_score: float | None = Field(
        None,
        description="CVSS v3.1 severity score (0.0-10.0)",
        ge=0.0,
        le=10.0,
    )
    published_date: datetime | None = Field(
        None,
        description="Date when CVE was published",
    )
    references: list[str] = Field(
        default_factory=list,
        description="URLs with additional CVE information",
    )

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        """Validate CVE ID format."""
        if not v or not v.startswith("CVE-"):
            raise ValueError("CVE ID must start with 'CVE-'")
        return v.upper()


class OSVVulnerability(BaseModel):
    """Model for Open Source Vulnerability (OSV) database entries."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "id": "GHSA-7rjr-3q54-20gg",
                "package_name": "log4j-core",
                "package_version": "2.14.1",
                "ecosystem": "Maven",
                "summary": "Remote Code Execution in Apache Log4j2",
                "details": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "fixed_versions": ["2.17.0", "2.16.1"],
                "references": [
                    "https://github.com/advisories/GHSA-7rjr-3q54-20gg",
                ],
            }
        },
    )

    id: str = Field(
        ...,
        description="OSV ID or CVE ID",
        min_length=3,
        max_length=50,
        pattern=SAFE_STRING_PATTERN,
    )
    package_name: str = Field(
        ...,
        description="Name of the affected package",
        min_length=1,
        max_length=256,
        pattern=SAFE_STRING_PATTERN,
    )
    package_version: str = Field(
        ...,
        description="Version of the affected package",
        min_length=1,
        max_length=50,
        pattern=SAFE_STRING_PATTERN,
    )
    ecosystem: str = Field(
        ...,
        description="Package ecosystem (npm, PyPI, crates.io, Maven, NuGet, Go, Rust, etc.)",
        min_length=1,
        max_length=50,
        pattern=SAFE_STRING_PATTERN,
    )
    summary: str = Field(
        ...,
        description="Brief summary of the vulnerability",
        min_length=10,
        max_length=500,
        pattern=SAFE_STRING_PATTERN,
    )
    details: str = Field(
        ...,
        description="Detailed vulnerability description",
        min_length=10,
        max_length=10000,
        pattern=SAFE_STRING_PATTERN,
    )
    severity: SeverityLevel | None = Field(
        None,
        description="Severity level of the vulnerability",
    )
    cvss_score: float | None = Field(
        None,
        description="CVSS v3.1 severity score (0.0-10.0)",
        ge=0.0,
        le=10.0,
    )
    fixed_versions: list[str] = Field(
        default_factory=list,
        description="Versions that fix the vulnerability",
    )
    references: list[str] = Field(
        default_factory=list,
        description="URLs with additional vulnerability information",
    )

    @field_validator("ecosystem")
    @classmethod
    def validate_ecosystem(cls, v: str) -> str:
        """Validate and normalize ecosystem name."""
        if not v or not v.strip():
            raise ValueError("Ecosystem must not be empty")
        return v.strip()


class SafetyVulnerability(BaseModel):
    """Model for vulnerabilities detected by Python Safety scanner."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "package": "django",
                "version": "2.2.10",
                "cve_id": "CVE-2020-9402",
                "advisory": "Django 2.2 before 2.2.11 allows SQL injection via tolerance parameter in GIS functions.",
                "severity": "HIGH",
                "vulnerable_versions": "<2.2.11",
                "safe_versions": ">=2.2.11",
            }
        },
    )

    package: str = Field(
        ...,
        description="Name of the vulnerable package",
        min_length=1,
        max_length=256,
        pattern=SAFE_STRING_PATTERN,
    )
    version: str = Field(
        ...,
        description="Current version of the package",
        min_length=1,
        max_length=50,
        pattern=SAFE_STRING_PATTERN,
    )
    cve_id: str | None = Field(
        None,
        description="CVE identifier if available",
        pattern=r"^CVE-\d{4}-\d{4,}$|^$",
    )
    advisory: str = Field(
        ...,
        description="Description of the security advisory",
        min_length=10,
        max_length=5000,
        pattern=SAFE_STRING_PATTERN,
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity level of the vulnerability",
    )
    vulnerable_versions: str = Field(
        ...,
        description="String specifying vulnerable version range (e.g., '<2.2.11')",
        min_length=1,
        max_length=200,
        pattern=SAFE_STRING_PATTERN,
    )
    safe_versions: str = Field(
        ...,
        description="String specifying safe versions or upgrade recommendations (e.g., '>=2.2.11')",
        min_length=1,
        max_length=200,
        pattern=SAFE_STRING_PATTERN,
    )


class SecurityFinding(BaseModel):
    """Model for a security finding from any source (pattern, OSV, Safety, etc.)."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "source": "pattern",
                "vulnerability_type": "sql_injection",
                "severity": "HIGH",
                "confidence": "high",
                "file_path": "app/database.py",
                "line_number": 42,
                "cve_ids": ["CVE-2020-9402"],
                "description": "Unvalidated user input passed directly to SQL query without parameterization.",
                "remediation": "Use parameterized queries or ORM methods instead of string concatenation.",
            }
        },
    )

    source: VulnerabilitySource = Field(
        ...,
        description="Source of the security finding",
    )
    vulnerability_type: str = Field(
        ...,
        description="Type of vulnerability (e.g., sql_injection, crypto, auth, xss)",
        min_length=1,
        max_length=100,
        pattern=SAFE_STRING_PATTERN,
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity level of the finding",
    )
    confidence: str = Field(
        ...,
        description="Confidence level (high, medium, low)",
        pattern=SAFE_STRING_PATTERN,
    )
    file_path: str | None = Field(
        None,
        description="Path to file containing the vulnerability",
        pattern=SAFE_STRING_PATTERN,
    )
    line_number: int | None = Field(
        None,
        description="Line number where vulnerability occurs",
        ge=1,
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Associated CVE identifiers",
    )
    description: str = Field(
        ...,
        description="Detailed description of the security issue",
        min_length=10,
        max_length=5000,
        pattern=SAFE_STRING_PATTERN,
    )
    remediation: str | None = Field(
        None,
        description="Remediation or fix guidance",
        max_length=2000,
        pattern=SAFE_STRING_PATTERN,
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        """Validate confidence level."""
        valid_levels = {"high", "medium", "low"}
        if v.lower() not in valid_levels:
            raise ValueError(f"Confidence must be one of {valid_levels}, got '{v}'")
        return v.lower()


class UnifiedSecurityReport(BaseModel):
    """Unified security report aggregating findings from all sources."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "total_vulnerabilities": 5,
                "by_source": {"pattern": 2, "safety": 2, "osv": 1},
                "by_severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2},
                "cve_count": 3,
                "security_score": 65,
                "findings": [],
                "recommendations": [
                    "Update log4j-core to 2.17.0 or later (CRITICAL)",
                ],
            }
        },
    )

    total_vulnerabilities: int = Field(
        ...,
        description="Total number of vulnerabilities found",
        ge=0,
    )
    by_source: dict[str, int] = Field(
        default_factory=dict,
        description="Vulnerability count by source (pattern, osv, safety)",
    )
    by_severity: dict[str, int] = Field(
        default_factory=dict,
        description="Vulnerability count by severity level",
    )
    cve_count: int = Field(
        0,
        description="Number of unique CVE identifiers found",
        ge=0,
    )
    security_score: float = Field(
        ...,
        description="Overall security score (0-100, where 100 is most secure)",
        ge=0.0,
        le=100.0,
    )
    findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="Complete list of security findings",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Prioritized list of remediation recommendations",
    )

    @field_validator("security_score")
    @classmethod
    def validate_security_score(cls, v: float) -> float:
        """Validate and round security score."""
        return round(v, 2)


# Container-Scoped Security Scan Request Models


class ContainerSecurityScanRequest(BaseModel):
    """Request model for container-wide security scanning."""

    container_name: str | None = Field(
        None,
        description="Name of the container to scan (optional, uses path param)",
        pattern=SAFE_STRING_PATTERN,
    )
    scan_type: str | None = Field(
        "full",
        description="Type of security scan: full, quick, or targeted",
        pattern=SAFE_STRING_PATTERN,
    )
    include_dependencies: bool = Field(
        True,
        description="Whether to include dependency scanning",
    )
    severity_filter: list[str] | None = Field(
        None,
        description="Filter by severity: critical, high, medium, low, info",
    )
    include_low_confidence: bool = Field(
        True,
        description="Whether to include low confidence findings",
    )
    max_files: int | None = Field(
        None,
        ge=1,
        le=10000,
        description="Maximum number of files to scan",
    )
    file_paths: list[str] | None = Field(
        None,
        description="Specific file paths within container to scan",
    )
    repo: str | None = Field(
        None,
        description=REPO_FIELD_DESCRIPTION,
        validate_default=True,
    )

    @field_validator("repo")
    @classmethod
    def _canonical_repo(cls, value: str | None) -> str:
        return normalize_repo(value)


class SecurityReportRequest(BaseModel):
    """Request model for generating security reports."""

    container_name: str = Field(
        ...,
        description="Name of the container for security report",
        pattern=SAFE_STRING_PATTERN,
    )
    format: str = Field(
        "json",
        description="Output format: json, html, pdf, markdown",
        pattern=SAFE_STRING_PATTERN,
    )
    include_remediation: bool = Field(
        True,
        description="Whether to include remediation suggestions",
    )
    include_code_snippets: bool = Field(
        False,
        description="Whether to include code snippets in report",
    )


# Security Scan Result Models


class ScanFindingViolation(SecurityViolation):
    """A container-scan finding: a ``SecurityViolation`` that names its engine.

    R216: consumers read ``engine`` instead of inferring the producer from the
    rule-id shape (``pattern_matched`` = an AVD id does not by itself mean IaC).
    """

    engine: Literal[
        "pattern", "bandit", "semgrep", "detect-secrets", "trivy-iac", "trivy-image"
    ] = Field(
        ...,
        description=(
            "Engine that produced this finding: pattern (in-process rule set), "
            "bandit, semgrep, detect-secrets, trivy-iac (IaC misconfiguration), "
            "or trivy-image (OS-package CVEs in the Dockerfile base image)."
        ),
    )
    #: Structured base-image CVE context. Only trivy-image findings carry
    #: these; every other engine leaves them null. They exist so a consumer
    #: does not have to parse the free-text ``description`` to learn which
    #: package, version and fix a CVE applies to.
    package_name: str | None = Field(
        None,
        description="Affected OS package (trivy-image findings only)",
        pattern=SAFE_STRING_PATTERN,
    )
    installed_version: str | None = Field(
        None,
        description="Installed version of the affected package (trivy-image findings only)",
        pattern=SAFE_STRING_PATTERN,
    )
    fixed_version: str | None = Field(
        None,
        description=(
            "First version that fixes the CVE (trivy-image findings only); null "
            "or empty when no fix is published"
        ),
        pattern=SAFE_STRING_PATTERN,
    )
    fix_available: bool | None = Field(
        None,
        description=(
            "True when trivy reports a fixed version for this CVE; null for "
            "findings from engines that do not track package fixes"
        ),
    )
    image_ref: str | None = Field(
        None,
        description=(
            "Base image reference from the Dockerfile FROM line that pulled in "
            "the vulnerable package (trivy-image findings only)"
        ),
        pattern=SAFE_STRING_PATTERN,
    )


class EngineStatus(BaseModel):
    """Outcome of one scan engine for this scan (R215/R216)."""

    status: Literal["ok", "degraded", "failed"] = Field(
        ...,
        description=(
            "ok = ran to completion over the files it was given; degraded = ran "
            "but its results are partial (some targets failed, or checks ran out "
            "of budget); failed = produced no usable result (not installed, "
            "crashed, timed out, did not complete before the scan deadline, or "
            "the scan examined no files)."
        ),
    )
    reason: str | None = Field(None, description="Why the engine is not ok; null when ok.")


class FileSecurityResult(BaseModel):
    """Security scan result for a single file."""

    file_path: str = Field(..., description="Path to the scanned file", pattern=SAFE_STRING_PATTERN)
    language: str = Field(..., description="Programming language", pattern=SAFE_STRING_PATTERN)
    vulnerabilities_found: int = Field(
        ...,
        description="Number of vulnerabilities found",
    )
    highest_severity: str = Field(
        ..., description="Highest severity level found", pattern=SAFE_STRING_PATTERN
    )
    violations: list[ScanFindingViolation] = Field(
        default_factory=list,
        description="List of security violations, each naming its engine",
    )
    risk_score: float = Field(
        ...,
        ge=0,
        le=100,
        description="Risk score for this file",
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="List of CVE identifiers found in this file",
    )


class BaseImageCoverage(BaseModel):
    """Coverage outcome for one Dockerfile ``FROM`` reference.

    ``unresolved`` means trivy produced no report for that image (not in the
    mirror registry, the scan errored or timed out, the deadline was reached,
    or the per-scan image cap dropped it). It is a coverage gap, never clean.
    """

    # No SAFE_STRING_PATTERN here: a repository path is data the scanner
    # reports verbatim, and a control character in a path must not turn a scan
    # into a 500. The row is coverage metadata, not executable content.
    ref: str = Field(
        ...,
        description="Base image reference as written on the Dockerfile FROM line",
    )
    dockerfile: str = Field(
        ...,
        description="Dockerfile that references the image (relative to the workspace)",
    )
    line: int = Field(..., ge=0, description="Line number of the FROM reference")
    status: Literal["scanned", "unresolved"] = Field(
        ..., description="scanned = trivy reported on this image; unresolved = it did not"
    )
    error: str | None = Field(
        None,
        description="Why the image is unresolved; null when scanned",
    )


class SecurityScanResult(BaseModel):
    """Comprehensive security scan result for a container."""

    container_name: str = Field(
        ..., description="Name of the scanned container", pattern=SAFE_STRING_PATTERN
    )
    scan_timestamp: datetime = Field(
        ...,
        description="Timestamp when scan completed",
    )
    scan_duration_seconds: float = Field(
        ...,
        description="Duration of the scan in seconds",
    )
    total_files_scanned: int = Field(
        ...,
        description="Total number of files scanned",
    )
    total_vulnerabilities: int = Field(
        ...,
        description="Total vulnerabilities found",
    )
    critical_count: int = Field(
        0,
        description="Number of critical vulnerabilities",
    )
    high_count: int = Field(0, description="Number of high vulnerabilities")
    medium_count: int = Field(0, description="Number of medium vulnerabilities")
    low_count: int = Field(0, description="Number of low vulnerabilities")
    info_count: int = Field(0, description="Number of info vulnerabilities")
    overall_risk_score: float = Field(
        ...,
        ge=0,
        le=100,
        description="Overall risk score",
    )
    security_grade: str = Field(
        ..., description="Security grade: A, B, C, D, F", pattern=SAFE_STRING_PATTERN
    )
    finding_grade: str = Field(
        "F",
        description=(
            "Grade from the findings' severities alone, independent of coverage: "
            "any critical → F; any high caps the risk-based grade at D. "
            "security_grade equals this only when the scan covered everything it "
            "was asked to. Defaults to F (fail closed) for payloads that predate "
            "this field."
        ),
        pattern=SAFE_STRING_PATTERN,
    )
    code_grade: str = Field(
        "F",
        description=(
            "Grade for source/config findings (every engine except trivy-image), "
            "derived from those findings and their engines' coverage. F when any "
            "of those engines did not run to completion — a partial code scan is "
            "never presented as clean."
        ),
        pattern=SAFE_STRING_PATTERN,
    )
    base_image_grade: str = Field(
        "F",
        description=(
            "Grade for base-image OS-package CVEs (trivy-image findings), derived "
            "from those findings and that engine's coverage. F when trivy-image "
            "did not run to completion or a requested base image could not be "
            "resolved — unresolved coverage is not clean."
        ),
        pattern=SAFE_STRING_PATTERN,
    )
    base_images: list[BaseImageCoverage] = Field(
        default_factory=list,
        description=(
            "One row per Dockerfile FROM reference: which base images were "
            "actually scanned and, for any that were not, why. Empty when the "
            "scan has no Dockerfile or the base-image engine never ran."
        ),
    )
    scan_degraded: bool = Field(
        False,
        description=(
            "True when the scan could not examine everything it was asked to "
            "(files that failed to parse, or an augmentation tool that errored). "
            "A degraded scan with a clean grade is not trustworthy — consumers "
            "(e.g. the repo-jobs oracle gate) should fail closed on this."
        ),
    )
    engine_status: dict[str, EngineStatus] = Field(
        default_factory=dict,
        description=(
            "Per-engine outcome keyed by engine name (pattern, bandit, semgrep, "
            "detect-secrets, trivy-iac, trivy-image). Every engine is always "
            "present on a scan result. Any non-ok engine also sets scan_degraded=true; "
            "scan_degraded can additionally be true with every engine ok "
            "(e.g. a file failed to parse or the codebase fetch was incomplete)."
        ),
    )
    degraded_reasons: list[str] = Field(
        default_factory=list,
        description="One entry per cause of scan_degraded; empty when not degraded.",
    )
    suppressed_findings: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "False-positive filter actions counted by reason. Keys: "
            "inline_suppression, assert_in_tests, credential_label, object_id, "
            "sql_constant_interpolation (findings removed) and test_path_downgraded "
            "(findings in test paths that were KEPT but lowered to low severity)."
        ),
    )
    file_results: list[FileSecurityResult] = Field(
        default_factory=list,
        description="Detailed results per file",
    )
    vulnerability_summary: dict[str, int] = Field(
        default_factory=dict,
        description="Summary by vulnerability type",
    )
    affected_files: list[str] = Field(
        default_factory=list,
        description="List of files with vulnerabilities",
    )
    cve_count: int = Field(
        0,
        description="Total number of unique CVE identifiers found",
        ge=0,
    )
    cve_references: list[CVEReference] = Field(
        default_factory=list,
        description="List of CVE references with detailed information",
    )


# Security Report Models


class SeverityDistribution(BaseModel):
    """Distribution of vulnerabilities by severity level."""

    critical: int = Field(0, description="Critical severity count")
    high: int = Field(0, description="High severity count")
    medium: int = Field(0, description="Medium severity count")
    low: int = Field(0, description="Low severity count")
    info: int = Field(0, description="Info severity count")


class VulnerabilityTypeCount(BaseModel):
    """Count of vulnerabilities by type."""

    type: str = Field(..., description="Vulnerability type", pattern=SAFE_STRING_PATTERN)
    count: int = Field(..., description="Number of occurrences")
    severity: str = Field(..., description="Most common severity", pattern=SAFE_STRING_PATTERN)


class SecurityHotspot(BaseModel):
    """File identified as a security hotspot."""

    file_path: str = Field(..., description="Path to the file", pattern=SAFE_STRING_PATTERN)
    vulnerability_count: int = Field(..., description="Number of vulnerabilities")
    highest_severity: str = Field(
        ..., description="Highest severity level", pattern=SAFE_STRING_PATTERN
    )
    risk_score: float = Field(..., description="Risk score for this file")


class ContainerSecurityReport(BaseModel):
    """Comprehensive security report for a container."""

    container_name: str = Field(
        ..., description="Name of the container", pattern=SAFE_STRING_PATTERN
    )
    report_generated_at: datetime = Field(
        ...,
        description="Report generation timestamp",
    )
    scan_summary: SecurityScanResult = Field(..., description="Security scan summary")
    severity_distribution: SeverityDistribution = Field(
        ...,
        description="Distribution by severity",
    )
    vulnerability_types: list[VulnerabilityTypeCount] = Field(
        default_factory=list,
        description="Breakdown by vulnerability type",
    )
    security_hotspots: list[SecurityHotspot] = Field(
        default_factory=list,
        description="Files with multiple vulnerabilities",
    )
    top_priorities: list[ScanFindingViolation] = Field(
        default_factory=list,
        description="Most critical vulnerabilities",
    )
    security_score: float = Field(
        ...,
        ge=0,
        le=100,
        description="Overall security score",
    )
    security_grade: str = Field(
        ..., description="Security grade: A, B, C, D, F", pattern=SAFE_STRING_PATTERN
    )
    scan_degraded: bool = Field(
        False,
        description=(
            "True when the underlying scan could not examine everything it was "
            "asked to (zero files discovered, files that failed to parse, an "
            "augmentation tool that errored, or an overall timeout). A degraded "
            "report with a clean grade is not trustworthy — consumers (e.g. the "
            "repo-jobs oracle gate) should fail closed on this."
        ),
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Security improvement recommendations",
    )
    affected_files_count: int = Field(
        ...,
        description="Number of files with vulnerabilities",
    )
    clean_files_count: int = Field(
        ...,
        description="Number of files without vulnerabilities",
    )
    language_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Vulnerabilities by language",
    )


# Response Models


class ContainerSecurityScanResponse(BaseModel):
    """Response model for container security scan endpoint."""

    status: str = Field(..., description="Operation status", pattern=SAFE_STRING_PATTERN)
    message: str = Field(..., description="Status message", pattern=SAFE_STRING_PATTERN)
    result: SecurityScanResult = Field(..., description="Security scan result")


class ContainerSecurityReportResponse(BaseModel):
    """Response model for container security report endpoint."""

    status: str = Field(..., description="Operation status", pattern=SAFE_STRING_PATTERN)
    message: str = Field(..., description="Status message", pattern=SAFE_STRING_PATTERN)
    report: ContainerSecurityReport = Field(
        ...,
        description="Comprehensive security report",
    )


class ImageScanResponse(BaseResponse):
    """Response model for container image scan endpoint."""

    result: ImageScanResult | None = Field(None, description="Image scan result")


class SBOMResponse(BaseResponse):
    """Response model for SBOM generation endpoint."""

    result: SBOMResult | None = Field(None, description="SBOM generation result")
