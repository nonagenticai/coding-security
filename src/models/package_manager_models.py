"""Base models for package management across system and language package managers.

This module provides clear separation between system-level package managers
(apt, brew, yum) and language-specific package managers (pip, npm, cargo).
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

#: PEP 503 name separators, collapsed for OSV lookups and offline-DB filenames.
_NAME_SEPARATORS_RE = re.compile(r"[-_.]+")


def normalize_package_name(name: str) -> str:
    """Normalise a package name for the OSV lookup (and offline record files).

    ONE definition, imported by both the scanner and the extractor: a second
    copy would drift and reintroduce the phantom-row bug it exists to prevent
    (a manifest row for a package a lockfile already resolved).
    Must mirror ``normalize_name`` in ``scripts/build_osv_offline_db.py``:
    lower-case and collapse runs of ``- _ .`` to a single ``-`` (PEP 503).
    """
    return _NAME_SEPARATORS_RE.sub("-", name.strip().lower())


class SystemPackageManager(Enum):
    """System-level package managers for OS dependencies."""

    # Linux distributions
    APT = "apt-get"  # Debian/Ubuntu
    YUM = "yum"  # RHEL/CentOS (older)
    DNF = "dnf"  # Fedora/RHEL/CentOS (newer)
    PACMAN = "pacman"  # Arch Linux
    ZYPPER = "zypper"  # openSUSE
    APK = "apk"  # Alpine Linux

    # macOS
    BREW = "brew"  # Homebrew

    # Windows
    CHOCO = "choco"  # Chocolatey

    @property
    def install_command(self) -> list[str]:
        """Get the base install command for this package manager."""
        commands: dict[SystemPackageManager, list[str]] = {
            SystemPackageManager.APT: ["sudo", "apt-get", "install", "-y"],
            SystemPackageManager.YUM: ["sudo", "yum", "install", "-y"],
            SystemPackageManager.DNF: ["sudo", "dnf", "install", "-y"],
            SystemPackageManager.PACMAN: ["sudo", "pacman", "-S", "--noconfirm"],
            SystemPackageManager.ZYPPER: ["sudo", "zypper", "install", "-y"],
            SystemPackageManager.APK: ["sudo", "apk", "add"],
            SystemPackageManager.BREW: ["brew", "install"],
            SystemPackageManager.CHOCO: ["choco", "install", "-y"],
        }
        return commands.get(self, [])

    @property
    def update_command(self) -> list[str]:
        """Get the update command for this package manager."""
        commands: dict[SystemPackageManager, list[str]] = {
            SystemPackageManager.APT: ["sudo", "apt-get", "update"],
            SystemPackageManager.YUM: ["sudo", "yum", "update", "-y"],
            SystemPackageManager.DNF: ["sudo", "dnf", "update", "-y"],
            SystemPackageManager.PACMAN: ["sudo", "pacman", "-Syu", "--noconfirm"],
            SystemPackageManager.ZYPPER: ["sudo", "zypper", "refresh"],
            SystemPackageManager.APK: ["sudo", "apk", "update"],
            SystemPackageManager.BREW: ["brew", "update"],
            SystemPackageManager.CHOCO: ["choco", "upgrade", "all", "-y"],
        }
        return commands.get(self, [])


class LanguagePackageManager(Enum):
    """Language-specific package managers."""

    # Python
    PIP = "pip"
    POETRY = "poetry"
    PIPENV = "pipenv"
    UV = "uv"
    CONDA = "conda"

    # JavaScript/TypeScript
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"
    BUN = "bun"

    # Rust
    CARGO = "cargo"

    # Java
    MAVEN = "maven"
    GRADLE = "gradle"

    # Ruby
    GEM = "gem"
    BUNDLER = "bundler"

    # Go
    GO_MOD = "go mod"

    # PHP
    COMPOSER = "composer"

    # .NET
    NUGET = "nuget"
    DOTNET = "dotnet"

    @property
    def manifest_files(self) -> list[str]:
        """Get typical manifest files for this package manager."""
        manifests: dict[LanguagePackageManager, list[str]] = {
            LanguagePackageManager.PIP: ["requirements.txt", "requirements/*.txt"],
            LanguagePackageManager.POETRY: ["pyproject.toml", "poetry.lock"],
            LanguagePackageManager.PIPENV: ["Pipfile", "Pipfile.lock"],
            LanguagePackageManager.UV: ["pyproject.toml", "uv.lock"],
            LanguagePackageManager.CONDA: ["environment.yml", "environment.yaml"],
            LanguagePackageManager.NPM: ["package.json", "package-lock.json"],
            LanguagePackageManager.YARN: ["package.json", "yarn.lock"],
            LanguagePackageManager.PNPM: ["package.json", "pnpm-lock.yaml"],
            LanguagePackageManager.BUN: ["package.json", "bun.lockb"],
            LanguagePackageManager.CARGO: ["Cargo.toml", "Cargo.lock"],
            LanguagePackageManager.MAVEN: ["pom.xml"],
            LanguagePackageManager.GRADLE: ["build.gradle", "build.gradle.kts"],
            LanguagePackageManager.GEM: ["Gemfile", "Gemfile.lock"],
            LanguagePackageManager.BUNDLER: ["Gemfile", "Gemfile.lock"],
            LanguagePackageManager.GO_MOD: ["go.mod", "go.sum"],
            LanguagePackageManager.COMPOSER: ["composer.json", "composer.lock"],
            LanguagePackageManager.NUGET: ["packages.config", "*.csproj"],
            LanguagePackageManager.DOTNET: ["*.csproj", "*.fsproj", "*.vbproj"],
        }
        return manifests.get(self, [])

    @property
    def install_command(self) -> list[str]:
        """Get the install command for this package manager."""
        commands: dict[LanguagePackageManager, list[str]] = {
            LanguagePackageManager.PIP: ["pip", "install"],
            LanguagePackageManager.POETRY: ["poetry", "install"],
            LanguagePackageManager.PIPENV: ["pipenv", "install"],
            LanguagePackageManager.UV: ["uv", "pip", "install"],
            LanguagePackageManager.CONDA: ["conda", "install"],
            LanguagePackageManager.NPM: ["npm", "install"],
            LanguagePackageManager.YARN: ["yarn", "install"],
            LanguagePackageManager.PNPM: ["pnpm", "install"],
            LanguagePackageManager.BUN: ["bun", "install"],
            LanguagePackageManager.CARGO: ["cargo", "build"],
            LanguagePackageManager.MAVEN: ["mvn", "install"],
            LanguagePackageManager.GRADLE: ["gradle", "build"],
            LanguagePackageManager.GEM: ["gem", "install"],
            LanguagePackageManager.BUNDLER: ["bundle", "install"],
            LanguagePackageManager.GO_MOD: ["go", "mod", "download"],
            LanguagePackageManager.COMPOSER: ["composer", "install"],
            LanguagePackageManager.NUGET: ["nuget", "restore"],
            LanguagePackageManager.DOTNET: ["dotnet", "restore"],
        }
        return commands.get(self, [])


class PackageVulnerability(BaseModel):
    """One known vulnerability of an ``ExternalPackage``, with ITS OWN fix.

    Kept per vulnerability because a package-level union of fixed versions
    cannot say that one of several CVEs has no fix at all.
    """

    id: str = Field(..., description="Vulnerability id (OSV / CVE / GHSA)")
    severity: str = Field(
        ..., description="CRITICAL, HIGH, MODERATE, LOW or UNKNOWN (no usable rating)"
    )
    fixed_versions: list[str] = Field(
        default_factory=list,
        description="Versions that fix THIS vulnerability; empty means no known fix",
    )

    model_config = ConfigDict(extra="forbid")


class ExternalPackage(BaseModel):
    """Represents an external package dependency with optional enrichment data."""

    name: str = Field(..., description="Package name")
    # NOT a specification, despite what this field was documented as until 2026-08-29 — the
    # manifest parsers strip the comparison operator, so `fastmcp==3.4.7` and `fastmcp>=3.4.7`
    # BOTH arrive here as "3.4.7". Kept bare deliberately: osv_scanner.py puts this value RAW
    # into the OSV query payload with no cleaning, and an operator there makes OSV return zero
    # vulnerabilities SILENTLY. Read `specifier` when you need the constraint.
    version: str | None = Field(
        None, description="Resolved version, WITHOUT any comparison operator (e.g. 1.0.0)"
    )
    manager: LanguagePackageManager | None = Field(None, description="Package manager used")
    is_dev: bool = Field(False, description="Whether this is a development dependency")
    source: str | None = Field(None, description="Source file where this dependency was found")
    # The constraint AS WRITTEN in the manifest, operator included (e.g. "==3.4.7", ">=2.3.4").
    # `version` cannot answer "is this pinned AT the target, or merely permitted by a range?",
    # and that distinction is the whole difference between a no-op and a real alignment diff.
    # None for lockfile parsers, whose values are resolved concretes rather than constraints.
    specifier: str | None = Field(
        None, description="Constraint as written in the manifest, operator included (e.g. ==3.4.7)"
    )
    extras: list[str] = Field(
        default_factory=list,
        description="Extra features requested (e.g., package[extra1,extra2])",
    )

    # Extended fields for enrichment and security analysis
    license: str | None = Field(None, description="Package license")
    ecosystem: str | None = Field(None, description="Package ecosystem (pypi, npm, etc.)")
    description: str | None = Field(None, description="Package description")
    homepage: str | None = Field(None, description="Package homepage URL")
    repository: str | None = Field(None, description="Package repository URL")

    # Legacy fields for compatibility
    current_version: str | None = Field(None, description="Currently installed version")
    latest_version: str | None = Field(None, description="Latest available version")
    severity: str | None = Field(
        None,
        description=(
            "Highest severity among this package's known vulnerabilities (CRITICAL, HIGH, "
            "MODERATE, UNKNOWN, LOW); None when no vulnerability is known"
        ),
    )
    # Set together with ``severity`` from the OSV scan; None when no vulnerability is known.
    vulnerability_ids: list[str] | None = Field(
        None, description="IDs of the known vulnerabilities affecting this package (OSV/CVE/GHSA)"
    )
    vulnerabilities: list[PackageVulnerability] | None = Field(
        None,
        description=(
            "This package's known vulnerabilities, each with its own fixed_versions "
            "(empty = no known fix); None when no vulnerability is known"
        ),
    )
    fixed_versions: list[str] | None = Field(
        None,
        description=(
            "Union of the fixed versions of this package's vulnerabilities; None when no "
            "vulnerability is known OR when at least one of them has no known fix"
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @property
    def full_spec(self) -> str:
        """Get the full package specification including version."""
        spec = self.name
        if self.extras:
            spec = f"{spec}[{','.join(self.extras)}]"
        if self.version:
            spec = f"{spec}{self.version}"
        return spec


class SystemDependency(BaseModel):
    """Represents a system-level dependency required by a package."""

    name: str = Field(..., description="Dependency name")
    packages: dict[SystemPackageManager, list[str]] = Field(
        ..., description="Mapping of system package managers to their package names"
    )
    description: str = Field(..., description="Human-readable description")
    required_by: list[str] = Field(
        default_factory=list,
        description="List of language packages that require this system dependency",
    )
    test_command: str | None = Field(None, description="Command to test if dependency is installed")
    version_command: str | None = Field(None, description="Command to get installed version")
    min_version: str | None = Field(None, description="Minimum required version")

    model_config = ConfigDict(extra="forbid")


class PackageManagerCapability(BaseModel):
    """Describes capabilities of a package manager."""

    manager: SystemPackageManager | LanguagePackageManager = Field(
        ..., description="The package manager"
    )
    supports_lockfile: bool = Field(False, description="Whether this manager supports lock files")
    supports_virtual_env: bool = Field(
        False, description="Whether this manager supports virtual environments"
    )
    supports_dev_dependencies: bool = Field(
        False, description="Whether this manager distinguishes dev dependencies"
    )
    supports_workspaces: bool = Field(
        False, description="Whether this manager supports workspaces/monorepos"
    )

    model_config = ConfigDict(extra="forbid")


# Pre-defined capabilities for common package managers
PACKAGE_MANAGER_CAPABILITIES = {
    LanguagePackageManager.PIP: PackageManagerCapability(
        manager=LanguagePackageManager.PIP,
        supports_lockfile=False,
        supports_virtual_env=True,
        supports_dev_dependencies=False,
        supports_workspaces=False,
    ),
    LanguagePackageManager.POETRY: PackageManagerCapability(
        manager=LanguagePackageManager.POETRY,
        supports_lockfile=True,
        supports_virtual_env=True,
        supports_dev_dependencies=True,
        supports_workspaces=False,
    ),
    LanguagePackageManager.NPM: PackageManagerCapability(
        manager=LanguagePackageManager.NPM,
        supports_lockfile=True,
        supports_virtual_env=False,
        supports_dev_dependencies=True,
        supports_workspaces=True,
    ),
    LanguagePackageManager.CARGO: PackageManagerCapability(
        manager=LanguagePackageManager.CARGO,
        supports_lockfile=True,
        supports_virtual_env=False,
        supports_dev_dependencies=True,
        supports_workspaces=True,
    ),
}
