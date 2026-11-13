"""System-level models for package management and dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PackageManager(Enum):
    """Supported system package managers."""

    APT = "apt"  # Debian/Ubuntu
    YUM = "yum"  # RHEL/CentOS (older)
    DNF = "dnf"  # RHEL/CentOS/Fedora (newer)
    BREW = "brew"  # macOS
    PACMAN = "pacman"  # Arch Linux
    APK = "apk"  # Alpine Linux
    ZYPPER = "zypper"  # openSUSE
    CHOCO = "choco"  # Windows

    @property
    def command(self) -> str:
        """Get the actual command to run for this package manager."""
        if self == PackageManager.APT:
            return "apt-get"
        return self.value


class DependencyType(Enum):
    """Types of dependencies."""

    BUILD = "build"
    RUNTIME = "runtime"
    OPTIONAL = "optional"


@dataclass
class SystemDependency:
    """Represents a system-level dependency."""

    name: str
    packages: dict[PackageManager, list[str]]
    description: str
    dependency_type: DependencyType = DependencyType.RUNTIME
    test_command: str | None = None
    test_import: str | None = None
    version_command: str | None = None
    min_version: str | None = None
