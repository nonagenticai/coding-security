"""Models for dependency risk assessment used by the dependencies endpoint.

This module extracts only the models needed for the security service's
dependency analysis capabilities.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from models.package_manager_models import ExternalPackage


class Vulnerability(BaseModel):
    """Security vulnerability information.

    ``package_name`` carries the name of the affected package; populated by
    the OSV scanner (and any other scanner that knows the source package).
    Defaulted to empty for backwards-compat with callers that constructed
    ``Vulnerability`` instances before the field existed.
    """

    id: str
    severity: str
    summary: str
    details: str
    affected_versions: list[str]
    fixed_versions: list[str]
    references: list[str]
    published_date: str
    modified_date: str
    package_name: str = ""
    #: Version of ``package_name`` the record was matched against ("" = unknown).
    #: A lockfile can resolve two versions of one name; this keeps them apart.
    package_version: str = ""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class DependencyRiskSummary(BaseModel):
    """Summary statistics for dependency risk assessment."""

    total_packages: int
    vulnerable_packages: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    moderate_vulnerabilities: int
    low_vulnerabilities: int

    model_config = ConfigDict(extra="forbid", protected_namespaces=())


class DependencyRiskReport(BaseModel):
    """Report of external dependencies and their risk assessment."""

    codebase_id: str
    generated_at: str  # ISO format datetime string
    packages: list[ExternalPackage]
    vulnerabilities: list[Vulnerability]
    risk_score: float
    summary: DependencyRiskSummary
    # True when the scan examined LESS than the repo holds — a manifest fetch
    # that dropped a file (failed cat, or a traversal-guarded out-of-tree path).
    # A grade over an unknown-incomplete manifest set is not trustworthy, so the
    # caller flags it degraded rather than reporting a clean scan.
    scan_degraded: bool = False
    # One entry per CAUSE of scan_degraded; empty when not degraded. A bare flag
    # cannot tell a caller that a pom.xml was never checked, or that the
    # advisory lookup was an outage — and an unexplained degrade gets ignored.
    # Mirrors ``SecurityScanResult.degraded_reasons`` on the container scan.
    degraded_reasons: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", protected_namespaces=())


def mark_degraded(report: DependencyRiskReport, reason: str) -> None:
    """Mark *report* degraded and record WHY (idempotent per reason).

    Attribute-based rather than a model method: callers receive the report from
    an injected analyzer, and a report-shaped stand-in that carries
    ``scan_degraded`` (but not the reasons list) must still degrade rather than
    silently do nothing. A bare ``scan_degraded=True`` with no reason is what
    makes a degraded scan indistinguishable from a bug.
    """
    report.scan_degraded = True
    reasons = getattr(report, "degraded_reasons", None)
    if isinstance(reasons, list) and reason not in reasons:
        reasons.append(reason)
