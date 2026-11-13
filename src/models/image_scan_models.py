"""Models for container image scanning and SBOM generation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ImageVulnerability(BaseModel):
    """Vulnerability found in a container image."""

    vulnerability_id: str = Field(..., description="CVE or other vulnerability ID")
    package_name: str = Field(..., description="Affected OS/library package name")
    installed_version: str = Field(..., description="Installed version")
    fixed_version: str | None = Field(None, description="Version that fixes the vulnerability")
    severity: str = Field(..., description="CRITICAL/HIGH/MEDIUM/LOW")
    title: str = Field("", description="Short vulnerability title")
    description: str = Field("", description="Vulnerability description")
    target: str = Field("", description="Scan target (e.g. OS layer, Python packages)")


class ImageScanResult(BaseModel):
    """Result of a container image vulnerability scan."""

    container_name: str
    image_ref: str
    scanner: str  # "trivy" or "grype"
    scan_timestamp: datetime
    scan_duration_seconds: float
    total_vulnerabilities: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    vulnerabilities: list[ImageVulnerability] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SBOMPackage(BaseModel):
    """A package entry in a Software Bill of Materials."""

    name: str
    version: str
    type: str  # python, deb, npm, etc.
    purl: str | None = None
    licenses: list[str] = Field(default_factory=list)
    ecosystem: str | None = Field(
        None, description="Ecosystem from the purl type (pypi, crates.io, npm, ...)"
    )


class SBOMResult(BaseModel):
    """Result of SBOM generation."""

    container_name: str
    image_ref: str
    format: str  # cyclonedx-json / spdx-json
    generated_at: datetime
    total_packages: int
    packages_by_type: dict[str, int] = Field(default_factory=dict)
    packages: list[SBOMPackage] = Field(default_factory=list)
    raw_sbom: str | None = None
    errors: list[str] = Field(default_factory=list)
    repo: str = Field(
        "primary",
        description="Workspace repo selector the SBOM covers ('primary' excludes .repos/)",
    )
