"""Base types for unified security scanning.

Enums, dataclasses, Pydantic models, and severity/confidence mappers shared
across all unified-security source modules and the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from services.security_detector import VulnerabilitySeverity


class SecurityFindingSeverity(StrEnum):
    """Severity levels for unified findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityFindingSource(StrEnum):
    """Source of security finding."""

    PATTERN = "pattern"
    OSV = "osv"
    SAFETY = "safety"
    PIP_AUDIT = "pip_audit"
    TRIVY = "trivy"
    GRYPE = "grype"


@dataclass
class SecurityFinding:
    """Unified security finding from any scanner."""

    id: str
    title: str
    description: str
    severity: SecurityFindingSeverity
    confidence: float  # 0.0-1.0
    source: SecurityFindingSource
    cve_id: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    package_name: str | None = None
    affected_version: str | None = None
    fixed_version: str | None = None
    remediation_advice: str = ""
    references: list[str] = field(default_factory=list)
    context_evidence: dict = field(default_factory=dict)
    cvss_score: float | None = None
    cvss_severity: str | None = None


class UnifiedSecurityReport(BaseModel):
    """Comprehensive security analysis report."""

    container_name: str = Field(..., description="Name of scanned container")
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When scan was performed",
    )
    total_vulnerabilities: int = Field(default=0, description="Total vulnerabilities found")
    by_source: dict[str, int] = Field(
        default_factory=dict,
        description="Count by scanner source (pattern, osv, safety)",
    )
    by_severity: dict[str, int] = Field(default_factory=dict, description="Count by severity level")
    cve_count: int = Field(default=0, description="Number of CVE identifiers found")
    security_score: float = Field(
        default=100.0, ge=0, le=100, description="Overall security score (0-100)"
    )
    findings: list[SecurityFinding] = Field(
        default_factory=list, description="Detailed security findings"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Actionable remediation recommendations"
    )
    scan_duration_seconds: float = Field(default=0.0, description="Scan execution time")
    errors: list[str] = Field(default_factory=list, description="Non-fatal errors during scanning")
    scan_degraded: bool = Field(
        default=False,
        description=(
            "True when a scanner failed or was unavailable, so the scan was "
            "incomplete. When True, a clean result (security_score=100, zero "
            "findings) is NOT trustworthy — some sources never ran. Consumers "
            "that gate on this report MUST fail closed when scan_degraded is True."
        ),
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)


def map_severity(vuln_severity: VulnerabilitySeverity) -> SecurityFindingSeverity:
    """Map VulnerabilitySeverity to SecurityFindingSeverity.

    Args:
        vuln_severity: Severity from pattern detector

    Returns:
        Mapped severity
    """
    severity_map = {
        VulnerabilitySeverity.CRITICAL: SecurityFindingSeverity.CRITICAL,
        VulnerabilitySeverity.HIGH: SecurityFindingSeverity.HIGH,
        VulnerabilitySeverity.MEDIUM: SecurityFindingSeverity.MEDIUM,
        VulnerabilitySeverity.LOW: SecurityFindingSeverity.LOW,
        VulnerabilitySeverity.INFO: SecurityFindingSeverity.INFO,
    }
    return severity_map.get(vuln_severity, SecurityFindingSeverity.MEDIUM)


def map_confidence(confidence_str: str) -> float:
    """Map confidence string to float value.

    Args:
        confidence_str: Confidence from pattern detector

    Returns:
        Confidence value 0.0-1.0
    """
    confidence_map = {
        "very_high": 0.95,
        "high": 0.80,
        "medium": 0.60,
        "low": 0.40,
        "very_low": 0.20,
    }
    return confidence_map.get(confidence_str.lower(), 0.5)


__all__ = [
    "SecurityFinding",
    "SecurityFindingSeverity",
    "SecurityFindingSource",
    "UnifiedSecurityReport",
    "map_confidence",
    "map_severity",
]
