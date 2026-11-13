"""Security-specific Pydantic models for code security analysis and validation.

This module provides comprehensive data models for security analysis operations,
including code vulnerability detection, security violation reporting, and
security-aware code validation.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SecurityLevel(StrEnum):
    """Enumeration of security levels for code validation and risk assessment.

    Attributes:
        LOW: Basic security checks with minimal performance impact.
        MEDIUM: Standard security validation with balanced performance.
        HIGH: Comprehensive security analysis with thorough validation.
        CRITICAL: Maximum security scrutiny with intensive analysis.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityViolation(BaseModel):
    """Model representing a security violation detected in code analysis.

    Attributes:
        type (str): The category of security violation
        severity (SecurityLevel): The severity level of the violation
        line_number (Optional[int]): The line number where the violation was detected
        pattern_matched (str): The pattern that triggered the violation
        description (str): Human-readable description of the security issue
        suggested_fix (Optional[str]): Recommended remediation
    """

    type: str = Field(..., description="Type of security violation")
    severity: SecurityLevel = Field(..., description="Severity level")
    line_number: int | None = Field(None, description="Line number where violation occurs")
    pattern_matched: str = Field(..., description="Pattern that triggered the violation")
    description: str = Field(..., description="Human-readable description")
    suggested_fix: str | None = Field(None, description="Suggested remediation")


class SupportedLanguage(StrEnum):
    """Supported programming languages for security validation."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JS = "js"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    CPP = "cpp"
    C = "c"
    CSHARP = "csharp"
    PHP = "php"
    RUBY = "ruby"


# /validate input bounds. The analysis is regex + AST over the whole snippet;
# an unbounded body let one request hold a worker for minutes. coding-testing
# (the main caller) caps its snippets at 50,000 chars.
MAX_VALIDATE_CODE_CHARS = 200_000
# Lines longer than this are still scanned but mark the result degraded (see
# SystemSecurityService._analyze_code).
MAX_ANALYZED_LINE_CHARS = 20_000


class SecurityValidationRequest(BaseModel):
    """Request model for security validation of code snippets.

    Attributes:
        code (str): The source code to be analyzed
        language (SupportedLanguage): The programming language of the code
        security_level (SecurityLevel): The required security validation level
        context (Optional[Dict[str, Any]]): Additional context information
        container_name (Optional[str]): Optional container name for context
    """

    code: str = Field(
        ...,
        max_length=MAX_VALIDATE_CODE_CHARS,
        description=f"Code to validate (at most {MAX_VALIDATE_CODE_CHARS} characters)",
    )
    language: SupportedLanguage = Field(..., description="Programming language")
    security_level: SecurityLevel = Field(
        SecurityLevel.MEDIUM, description="Required security level"
    )
    context: dict[str, Any] | None = Field(None, description="Additional context for validation")
    container_name: str | None = Field(
        None, description="Optional container name (accepted but not used)"
    )


class SecurityValidationResult(BaseModel):
    """Result model for security validation outcomes.

    Attributes:
        is_safe (bool): Whether the code passes security validation
        violations (List[SecurityViolation]): List of detected violations
        risk_score (float): Overall risk score from 0-100
        sandbox_config (Optional[Dict[str, Any]]): Recommended sandbox configuration
    """

    is_safe: bool = Field(..., description="Whether code passes security validation")
    violations: list[SecurityViolation] = Field(default_factory=list)
    risk_score: float = Field(..., ge=0, le=100, description="Overall risk score")
    sandbox_config: dict[str, Any] | None = Field(
        None, description="Recommended sandbox configuration"
    )
    analysis_degraded: bool = Field(
        False,
        description=(
            "True when part of the analysis could not run (an engine failed or the "
            "code could not be examined). A degraded result is never reported safe."
        ),
    )
    degraded_reasons: list[str] = Field(
        default_factory=list, description="Why the analysis is degraded, one entry per cause"
    )


class SecurityScanRequest(BaseModel):
    """Request model for initiating a security scan on a container.

    Attributes:
        container_name (str): The name of the container to scan
        scan_type (Optional[str]): The type of security scan to perform
        include_dependencies (bool): Whether to include dependency scanning
    """

    container_name: str = Field(..., description="Name of the container to scan")
    scan_type: str | None = Field("full", description="Type of security scan to perform")
    include_dependencies: bool = Field(True, description="Whether to include dependency scanning")


class SecurityReportRequest(BaseModel):
    """Request model for generating a security report for a container.

    Attributes:
        container_name (str): The name of the container
        format (str): The output format for the report
    """

    container_name: str = Field(..., description="Name of the container for security report")
    format: str = Field("json", description="Output format for the report")


class VulnerabilityScanResult(BaseModel):
    """Result model for vulnerability scanning operations.

    Attributes:
        container_name (str): The name of the container that was scanned
        vulnerabilities (List[Dict]): List of detected vulnerabilities
        scan_timestamp (datetime): When the scan was completed
    """

    container_name: str = Field(..., description="Name of the scanned container")
    vulnerabilities: list[dict] = Field(
        default_factory=list, description="List of detected vulnerabilities"
    )
    scan_timestamp: datetime = Field(..., description="Timestamp when the scan was completed")


class OSVPackageInfo(BaseModel):
    """Model representing package information for OSV.dev queries.

    Attributes:
        name (str): Package name.
        ecosystem (str): Package ecosystem (npm, PyPI, crates.io, Go, Maven, etc).
    """

    name: str = Field(..., description="Package name")
    ecosystem: str = Field(..., description="Package ecosystem")


class OSVVulnerability(BaseModel):
    """Model representing an OSV.dev vulnerability.

    Attributes:
        id (str): Unique vulnerability identifier.
        summary (str): Brief summary of the vulnerability.
        details (Optional[str]): Detailed description.
        severity (Optional[str]): Severity level.
        affected_versions (List[str]): Affected package versions.
        fixed_versions (Optional[List[str]]): Versions where the issue is fixed.
        cve_ids (List[str]): Associated CVE identifiers.
        references (List[str]): Links to additional information.
        published_date (Optional[str]): Publication date.
        package_name (str): Name of the affected package.
        ecosystem (str): Package ecosystem.
    """

    id: str = Field(..., description="Vulnerability identifier (e.g., GHSA-xxxx)")
    summary: str = Field(..., description="Vulnerability summary")
    details: str | None = Field(None, description="Detailed description")
    severity: str | None = Field(None, description="Severity level")
    affected_versions: list[str] = Field(default_factory=list, description="Affected versions")
    fixed_versions: list[str] | None = Field(None, description="Versions where issue is fixed")
    cve_ids: list[str] = Field(default_factory=list, description="Associated CVE IDs")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    published_date: str | None = Field(None, description="Publication date")
    package_name: str = Field(..., description="Affected package name")
    ecosystem: str = Field(..., description="Package ecosystem")


class PackageInfo(BaseModel):
    """Model representing package information for batch queries.

    Attributes:
        name (str): Package name.
        version (str): Package version.
        ecosystem (str): Package ecosystem.
    """

    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: str = Field(..., description="Package ecosystem")


class PipAuditVulnerability(BaseModel):
    """Model representing a vulnerability detected by pip-audit.

    Attributes:
        package_name (str): Name of the vulnerable package.
        installed_version (str): Currently installed version.
        vulnerability_id (str): PYSEC or CVE identifier.
        fix_versions (List[str]): Versions that fix the issue.
        description (str): Vulnerability description.
        aliases (List[str]): CVE/GHSA cross-references.
        severity (Optional[str]): Severity if available.
    """

    package_name: str = Field(..., description="Name of vulnerable package")
    installed_version: str = Field(..., description="Currently installed version")
    vulnerability_id: str = Field(..., description="PYSEC or CVE identifier")
    fix_versions: list[str] = Field(default_factory=list, description="Versions that fix the issue")
    description: str = Field("", description="Vulnerability description")
    aliases: list[str] = Field(default_factory=list, description="CVE/GHSA cross-references")
    severity: str | None = Field(None, description="Severity if available")


class NVDCVSSData(BaseModel):
    """CVSS data from NVD for a specific CVE.

    Attributes:
        cve_id (str): CVE identifier.
        cvss_v31_score (Optional[float]): CVSS v3.1 base score.
        cvss_v31_severity (Optional[str]): LOW/MEDIUM/HIGH/CRITICAL.
        cvss_v31_vector (Optional[str]): CVSS v3.1 vector string.
        description (str): CVE description.
        published_date (Optional[str]): Publication date.
        references (List[str]): Reference URLs.
    """

    cve_id: str = Field(..., description="CVE identifier")
    cvss_v31_score: float | None = Field(None, description="CVSS v3.1 base score")
    cvss_v31_severity: str | None = Field(None, description="LOW/MEDIUM/HIGH/CRITICAL")
    cvss_v31_vector: str | None = Field(None, description="CVSS v3.1 vector string")
    description: str = Field("", description="CVE description")
    published_date: str | None = Field(None, description="Publication date")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
