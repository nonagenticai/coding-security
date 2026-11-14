"""
System dependency detection and installation manager.

This module provides functionality to detect and install system-level dependencies
based on Python and Node.js package requirements.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import subprocess
from pathlib import Path

from models.system_models import DependencyType, PackageManager, SystemDependency

logger = logging.getLogger(__name__)


class SystemDependencyManager:
    """Manages detection and installation of system dependencies."""

    # Mapping of Python/Node packages to their system dependencies
    DEPENDENCY_MAP: dict[str, SystemDependency] = {
        # Python packages
        "lxml": SystemDependency(
            name="lxml",
            packages={
                PackageManager.APT: ["libxml2-dev", "libxslt1-dev"],
                PackageManager.YUM: ["libxml2-devel", "libxslt-devel"],
                PackageManager.DNF: ["libxml2-devel", "libxslt-devel"],
                PackageManager.BREW: ["libxml2", "libxslt"],
                PackageManager.PACMAN: ["libxml2", "libxslt"],
                PackageManager.APK: ["libxml2-dev", "libxslt-dev"],
                PackageManager.ZYPPER: ["libxml2-devel", "libxslt-devel"],
            },
            description="XML processing libraries",
            dependency_type=DependencyType.BUILD,
            test_command="xml2-config --version",
        ),
        "psycopg2": SystemDependency(
            name="psycopg2",
            packages={
                PackageManager.APT: ["libpq-dev"],
                PackageManager.YUM: ["postgresql-devel"],
                PackageManager.DNF: ["postgresql-devel"],
                PackageManager.BREW: ["postgresql"],
                PackageManager.PACMAN: ["postgresql-libs"],
                PackageManager.APK: ["postgresql-dev"],
                PackageManager.ZYPPER: ["postgresql-devel"],
            },
            description="PostgreSQL client libraries",
            dependency_type=DependencyType.BUILD,
            test_command="pg_config --version",
        ),
        "mysqlclient": SystemDependency(
            name="mysqlclient",
            packages={
                PackageManager.APT: ["libmysqlclient-dev"],
                PackageManager.YUM: ["mysql-devel"],
                PackageManager.DNF: ["mysql-devel"],
                PackageManager.BREW: ["mysql"],
                PackageManager.PACMAN: ["mariadb-libs"],
                PackageManager.APK: ["mariadb-dev"],
                PackageManager.ZYPPER: ["libmysqlclient-devel"],
            },
            description="MySQL client libraries",
            dependency_type=DependencyType.BUILD,
            test_command="mysql_config --version",
        ),
        "Pillow": SystemDependency(
            name="Pillow",
            packages={
                PackageManager.APT: ["libjpeg-dev", "zlib1g-dev", "libpng-dev"],
                PackageManager.YUM: [
                    "libjpeg-turbo-devel",
                    "zlib-devel",
                    "libpng-devel",
                ],
                PackageManager.DNF: [
                    "libjpeg-turbo-devel",
                    "zlib-devel",
                    "libpng-devel",
                ],
                PackageManager.BREW: ["jpeg", "libpng", "libtiff"],
                PackageManager.PACMAN: ["libjpeg-turbo", "libpng", "libtiff"],
                PackageManager.APK: ["jpeg-dev", "zlib-dev", "libpng-dev"],
                PackageManager.ZYPPER: ["libjpeg-devel", "zlib-devel", "libpng-devel"],
            },
            description="Image processing libraries",
            dependency_type=DependencyType.BUILD,
        ),
        "cryptography": SystemDependency(
            name="cryptography",
            packages={
                PackageManager.APT: ["libssl-dev", "libffi-dev"],
                PackageManager.YUM: ["openssl-devel", "libffi-devel"],
                PackageManager.DNF: ["openssl-devel", "libffi-devel"],
                PackageManager.BREW: ["openssl", "libffi"],
                PackageManager.PACMAN: ["openssl", "libffi"],
                PackageManager.APK: ["openssl-dev", "libffi-dev"],
                PackageManager.ZYPPER: ["openssl-devel", "libffi-devel"],
            },
            description="Cryptography libraries",
            dependency_type=DependencyType.BUILD,
        ),
        "scipy": SystemDependency(
            name="scipy",
            packages={
                PackageManager.APT: ["gfortran", "libopenblas-dev", "liblapack-dev"],
                PackageManager.YUM: ["gcc-gfortran", "openblas-devel", "lapack-devel"],
                PackageManager.DNF: ["gcc-gfortran", "openblas-devel", "lapack-devel"],
                PackageManager.BREW: ["gcc", "openblas", "lapack"],
                PackageManager.PACMAN: ["gcc-fortran", "openblas", "lapack"],
                PackageManager.APK: ["gfortran", "openblas-dev", "lapack-dev"],
                PackageManager.ZYPPER: [
                    "gcc-fortran",
                    "openblas-devel",
                    "lapack-devel",
                ],
            },
            description="Scientific computing libraries",
            dependency_type=DependencyType.BUILD,
        ),
        "h5py": SystemDependency(
            name="h5py",
            packages={
                PackageManager.APT: ["libhdf5-dev"],
                PackageManager.YUM: ["hdf5-devel"],
                PackageManager.DNF: ["hdf5-devel"],
                PackageManager.BREW: ["hdf5"],
                PackageManager.PACMAN: ["hdf5"],
                PackageManager.APK: ["hdf5-dev"],
                PackageManager.ZYPPER: ["hdf5-devel"],
            },
            description="HDF5 data format libraries",
            dependency_type=DependencyType.BUILD,
        ),
        "pyaudio": SystemDependency(
            name="pyaudio",
            packages={
                PackageManager.APT: ["portaudio19-dev"],
                PackageManager.YUM: ["portaudio-devel"],
                PackageManager.DNF: ["portaudio-devel"],
                PackageManager.BREW: ["portaudio"],
                PackageManager.PACMAN: ["portaudio"],
                PackageManager.APK: ["portaudio-dev"],
                PackageManager.ZYPPER: ["portaudio-devel"],
            },
            description="Audio I/O libraries",
            dependency_type=DependencyType.BUILD,
        ),
        "cairocffi": SystemDependency(
            name="cairocffi",
            packages={
                PackageManager.APT: ["libcairo2-dev", "libpango1.0-dev"],
                PackageManager.YUM: ["cairo-devel", "pango-devel"],
                PackageManager.DNF: ["cairo-devel", "pango-devel"],
                PackageManager.BREW: ["cairo", "pango"],
                PackageManager.PACMAN: ["cairo", "pango"],
                PackageManager.APK: ["cairo-dev", "pango-dev"],
                PackageManager.ZYPPER: ["cairo-devel", "pango-devel"],
            },
            description="Cairo graphics libraries",
            dependency_type=DependencyType.BUILD,
        ),
        # Node.js packages
        "node-canvas": SystemDependency(
            name="node-canvas",
            packages={
                PackageManager.APT: [
                    "libcairo2-dev",
                    "libjpeg-dev",
                    "libpango1.0-dev",
                    "libgif-dev",
                    "build-essential",
                ],
                PackageManager.YUM: [
                    "cairo-devel",
                    "libjpeg-turbo-devel",
                    "pango-devel",
                    "giflib-devel",
                ],
                PackageManager.DNF: [
                    "cairo-devel",
                    "libjpeg-turbo-devel",
                    "pango-devel",
                    "giflib-devel",
                ],
                PackageManager.BREW: ["cairo", "jpeg", "pango", "giflib"],
                PackageManager.PACMAN: ["cairo", "libjpeg-turbo", "pango", "giflib"],
                PackageManager.APK: [
                    "cairo-dev",
                    "jpeg-dev",
                    "pango-dev",
                    "giflib-dev",
                    "build-base",
                ],
                PackageManager.ZYPPER: [
                    "cairo-devel",
                    "libjpeg-devel",
                    "pango-devel",
                    "giflib-devel",
                ],
            },
            description="Canvas rendering for Node.js",
            dependency_type=DependencyType.BUILD,
        ),
        "node-sqlite3": SystemDependency(
            name="node-sqlite3",
            packages={
                PackageManager.APT: ["sqlite3", "libsqlite3-dev"],
                PackageManager.YUM: ["sqlite", "sqlite-devel"],
                PackageManager.DNF: ["sqlite", "sqlite-devel"],
                PackageManager.BREW: ["sqlite"],
                PackageManager.PACMAN: ["sqlite"],
                PackageManager.APK: ["sqlite", "sqlite-dev"],
                PackageManager.ZYPPER: ["sqlite3", "sqlite3-devel"],
            },
            description="SQLite database for Node.js",
            dependency_type=DependencyType.BUILD,
        ),
        "sharp": SystemDependency(
            name="sharp",
            packages={
                PackageManager.APT: ["libvips-dev"],
                PackageManager.YUM: ["vips-devel"],
                PackageManager.DNF: ["vips-devel"],
                PackageManager.BREW: ["vips"],
                PackageManager.PACMAN: ["libvips"],
                PackageManager.APK: ["vips-dev"],
                PackageManager.ZYPPER: ["libvips-devel"],
            },
            description="High-performance image processing",
            dependency_type=DependencyType.BUILD,
        ),
    }

    def __init__(self):
        """Initialize the system dependency manager."""
        self.os_type = platform.system().lower()
        self.package_manager = self._detect_package_manager()
        self.detected_dependencies: set[str] = set()
        self.missing_dependencies: list[SystemDependency] = []
        self._install_cache: set[str] = set()  # Cache for installation checks
        self._dependency_cache: dict[str, bool] = {}  # Cache for dependency installation status

    def _detect_package_manager(self) -> PackageManager | None:
        """Detect the system package manager."""
        if self.os_type == "darwin":
            return PackageManager.BREW if self._command_exists("brew") else None
        elif self.os_type == "windows":
            return PackageManager.CHOCO if self._command_exists("choco") else None
        elif self.os_type == "linux":
            # Try common Linux package managers
            for pm in [
                PackageManager.APT,
                PackageManager.YUM,
                PackageManager.DNF,
                PackageManager.PACMAN,
                PackageManager.APK,
                PackageManager.ZYPPER,
            ]:
                if self._command_exists(pm.command):
                    return pm
        return None

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system."""
        try:
            result = subprocess.run(
                ["which", command],
                capture_output=True,
                check=False,
                timeout=5,  # Prevent hanging
            )
            return result.returncode == 0
        except (
            subprocess.SubprocessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            return False

    def _parse_requirements_txt(self, file_path: Path) -> set[str]:
        """Parse requirements.txt file for package names."""
        packages = set()
        if not file_path.exists():
            return packages

        try:
            with open(file_path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        # Extract package name (handle various formats)
                        # Support: package, package==1.0, package>=1.0, package[extra]
                        match = re.match(
                            r"^([a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]|[a-zA-Z0-9])",
                            line,
                        )
                        if match:
                            package_name = match.group(1).lower().replace("_", "-")
                            # Normalize common package name variations
                            if package_name:
                                packages.add(package_name)
                        else:
                            logger.debug(
                                f"Skipping invalid package line {line_num} in {file_path}: {line}"
                            )
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to parse {file_path}: {e}")
        return packages

    def _parse_pyproject_toml(self, file_path: Path) -> set[str]:
        """Parse pyproject.toml for package names."""
        packages = set()
        if not file_path.exists():
            return packages

        try:
            try:
                import tomllib
            except ImportError:
                try:
                    import tomli as tomllib
                except ImportError:
                    logger.warning("No TOML library available, skipping pyproject.toml parsing")
                    return packages

            with open(file_path, "rb") as f:
                data = tomllib.load(f)

            # Check project.dependencies
            if "project" in data and "dependencies" in data["project"]:
                for dep in data["project"]["dependencies"]:
                    if isinstance(dep, str):
                        match = re.match(
                            r"^([a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]|[a-zA-Z0-9])", dep
                        )
                        if match:
                            package_name = match.group(1).lower().replace("_", "-")
                            if package_name:
                                packages.add(package_name)

            # Check tool.poetry.dependencies
            if (
                "tool" in data
                and "poetry" in data["tool"]
                and "dependencies" in data["tool"]["poetry"]
            ):
                poetry_deps = data["tool"]["poetry"]["dependencies"]
                if isinstance(poetry_deps, dict):
                    for pkg in poetry_deps:
                        if pkg.lower() != "python":  # Skip Python version requirement
                            normalized_pkg = pkg.lower().replace("_", "-")
                            if normalized_pkg:
                                packages.add(normalized_pkg)

        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to parse {file_path}: {e}")

        return packages

    def _parse_package_json(self, file_path: Path) -> set[str]:
        """Parse package.json for package names."""
        packages = set()
        if not file_path.exists():
            return packages

        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            for key in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ]:
                if key in data and isinstance(data[key], dict):
                    for pkg in data[key]:
                        if isinstance(pkg, str) and pkg:
                            # Normalize package name
                            normalized_pkg = pkg.lower().strip()
                            if normalized_pkg:
                                packages.add(normalized_pkg)

        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to parse {file_path}: {e}")

        return packages

    def detect_required_dependencies(
        self,
        project_root: Path,
        include_optional: bool = False,
        fast_mode: bool = False,
    ) -> list[SystemDependency]:
        """Detect system dependencies required by the project."""
        self.detected_dependencies.clear()
        self.missing_dependencies.clear()

        if not project_root.exists() or not project_root.is_dir():
            logger.warning(f"Project root does not exist or is not a directory: {project_root}")
            return []

        # Parse Python dependencies with early exit optimization
        requirements_files = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "requirements-test.txt",
        ]

        # Check if any requirements files exist before parsing
        existing_req_files = [f for f in requirements_files if (project_root / f).exists()]
        if (
            not existing_req_files
            and not (project_root / "pyproject.toml").exists()
            and not (project_root / "package.json").exists()
        ):
            logger.debug("No dependency files found in project")
            return []

        for req_file in existing_req_files:
            file_path = project_root / req_file
            detected = self._parse_requirements_txt(file_path)
            if detected:
                logger.debug(f"Found {len(detected)} packages in {req_file}")
            self.detected_dependencies.update(detected)

            # Early exit if we already have many dependencies to avoid scanning all files
            if len(self.detected_dependencies) > 50:
                logger.debug(
                    f"Found {len(self.detected_dependencies)} dependencies, stopping early scan"
                )
                break

        # Parse pyproject.toml
        pyproject_path = project_root / "pyproject.toml"
        pyproject_deps = self._parse_pyproject_toml(pyproject_path)
        if pyproject_deps:
            logger.debug(f"Found {len(pyproject_deps)} packages in pyproject.toml")
        self.detected_dependencies.update(pyproject_deps)

        # Parse package.json
        package_json_path = project_root / "package.json"
        node_packages = self._parse_package_json(package_json_path)
        if node_packages:
            logger.debug(f"Found {len(node_packages)} Node.js packages")

        # Optimize dependency checking with pre-filtering
        if not self.detected_dependencies and not node_packages:
            logger.debug("No dependencies detected")
            return []

        # Create lookup map for faster searching
        dep_lookup = {}
        for dep_key, dep in self.DEPENDENCY_MAP.items():
            dep_lookup[dep_key.lower()] = (dep_key, dep)
            # Add common variations to lookup
            dep_lookup[dep_key.replace("-", "_").lower()] = (dep_key, dep)
            dep_lookup[dep_key.replace("_", "-").lower()] = (dep_key, dep)

        # Check for system dependencies
        checked_deps = set()
        for pkg_name in self.detected_dependencies:
            pkg_lower = pkg_name.lower()

            # Try direct lookup first (fastest)
            if pkg_lower in dep_lookup and dep_lookup[pkg_lower][0] not in checked_deps:
                dep_key, dep = dep_lookup[pkg_lower]
                checked_deps.add(dep_key)

                if not include_optional and dep.dependency_type == DependencyType.OPTIONAL:
                    continue

                if fast_mode:
                    # In fast mode, assume all dependencies are missing (skip installation check)
                    self.missing_dependencies.append(dep)
                    logger.debug(f"Dependency (fast mode): {dep.name}")
                elif not self._is_dependency_installed(dep):
                    self.missing_dependencies.append(dep)
                    logger.debug(f"Missing dependency: {dep.name}")
                continue

            # If not found, try case variations (slower)
            found = False
            for variant in [pkg_name.capitalize(), pkg_name.title()]:
                variant_lower = variant.lower()
                if variant_lower in dep_lookup and dep_lookup[variant_lower][0] not in checked_deps:
                    dep_key, dep = dep_lookup[variant_lower]
                    checked_deps.add(dep_key)

                    if not include_optional and dep.dependency_type == DependencyType.OPTIONAL:
                        continue

                    if fast_mode:
                        self.missing_dependencies.append(dep)
                        logger.debug(f"Dependency (fast mode, case variant): {dep.name}")
                    elif not self._is_dependency_installed(dep):
                        self.missing_dependencies.append(dep)
                        logger.debug(f"Missing dependency (case variant): {dep.name}")
                    found = True
                    break

            if found:
                continue

        # Check Node.js dependencies with optimized lookup
        for pkg_name in node_packages:
            # Try different naming conventions for Node packages
            node_variations = [f"node-{pkg_name}", pkg_name, f"node_{pkg_name}"]

            for node_name in node_variations:
                node_lower = node_name.lower()
                if node_lower in dep_lookup and dep_lookup[node_lower][0] not in checked_deps:
                    dep_key, dep = dep_lookup[node_lower]
                    checked_deps.add(dep_key)

                    if not include_optional and dep.dependency_type == DependencyType.OPTIONAL:
                        continue

                    if fast_mode:
                        self.missing_dependencies.append(dep)
                        logger.debug(f"Node.js dependency (fast mode): {dep.name}")
                    elif not self._is_dependency_installed(dep):
                        self.missing_dependencies.append(dep)
                        logger.debug(f"Missing Node.js dependency: {dep.name}")
                    break

        logger.info(
            f"Detected {len(self.detected_dependencies)} total packages, {len(self.missing_dependencies)} missing system dependencies"
        )
        return self.missing_dependencies

    def _is_dependency_installed(self, dep: SystemDependency) -> bool:
        """Check if a system dependency is installed with caching."""
        # Check cache first
        cache_key = f"{dep.name}_{self.package_manager.value if self.package_manager else 'none'}"
        if cache_key in self._dependency_cache:
            return self._dependency_cache[cache_key]

        result = self._check_dependency_installed_uncached(dep)
        self._dependency_cache[cache_key] = result
        return result

    def _check_dependency_installed_uncached(self, dep: SystemDependency) -> bool:
        """Check if a system dependency is installed without caching."""
        # Try test import first (fastest)
        if dep.test_import:
            try:
                __import__(dep.test_import)
                return True
            except ImportError:
                pass

        # Try package manager check (faster than test command)
        if self.package_manager and self.package_manager in dep.packages:
            packages = dep.packages[self.package_manager]
            if packages:
                installed = self._check_package_installed(packages[0])  # Check first package
                if installed:
                    return True

        # Try test command last (slowest)
        if dep.test_command:
            try:
                result = subprocess.run(
                    dep.test_command.split(),
                    capture_output=True,
                    check=False,
                    timeout=5,  # Reduced timeout for faster response
                )
                return result.returncode == 0
            except (
                subprocess.SubprocessError,
                FileNotFoundError,
                subprocess.TimeoutExpired,
            ):
                pass

        # Default to not installed if no reliable check available
        return False

    def _check_package_installed(self, package_name: str) -> bool:
        """Check if a specific package is installed using package manager."""
        if not self.package_manager:
            return False

        try:
            if self.package_manager == PackageManager.APT:
                result = subprocess.run(
                    ["dpkg", "-l", package_name],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0 and "ii" in result.stdout.decode()
            elif self.package_manager == PackageManager.BREW:
                result = subprocess.run(
                    ["brew", "list", package_name],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0
            elif self.package_manager in [PackageManager.YUM, PackageManager.DNF]:
                result = subprocess.run(
                    [self.package_manager.value, "list", "installed", package_name],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0
            elif self.package_manager == PackageManager.PACMAN:
                result = subprocess.run(
                    ["pacman", "-Q", package_name],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0
            elif self.package_manager == PackageManager.APK:
                result = subprocess.run(
                    ["apk", "info", "-e", package_name],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                return result.returncode == 0
        except (
            subprocess.SubprocessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            pass

        return False

    def generate_install_script(
        self,
        dependencies: list[SystemDependency] | None = None,
        output_path: Path | None = None,
    ) -> str:
        """Generate installation script for missing dependencies."""
        if dependencies is None:
            dependencies = self.missing_dependencies

        if not dependencies or not self.package_manager:
            return ""

        script_lines = ["#!/bin/bash", "set -e", ""]

        # Add package manager update command
        if self.package_manager == PackageManager.APT:
            script_lines.append("sudo apt-get update")
        elif self.package_manager == PackageManager.YUM:
            script_lines.append("sudo yum update -y")
        elif self.package_manager == PackageManager.DNF:
            script_lines.append("sudo dnf update -y")
        elif self.package_manager == PackageManager.BREW:
            script_lines.append("brew update")

        script_lines.append("")

        # Add installation commands
        for dep in dependencies:
            if self.package_manager in dep.packages:
                packages = dep.packages[self.package_manager]
                if packages:
                    script_lines.append(f"# Install {dep.description}")
                    if self.package_manager == PackageManager.APT:
                        cmd = f"sudo apt-get install -y {' '.join(packages)}"
                    elif self.package_manager in [
                        PackageManager.YUM,
                        PackageManager.DNF,
                    ]:
                        cmd = f"sudo {self.package_manager.value} install -y {' '.join(packages)}"
                    elif self.package_manager == PackageManager.BREW:
                        cmd = f"brew install {' '.join(packages)}"
                    elif self.package_manager == PackageManager.PACMAN:
                        cmd = f"sudo pacman -S --noconfirm {' '.join(packages)}"
                    elif self.package_manager == PackageManager.APK:
                        cmd = f"sudo apk add {' '.join(packages)}"
                    elif self.package_manager == PackageManager.ZYPPER:
                        cmd = f"sudo zypper install -y {' '.join(packages)}"
                    else:
                        cmd = f"# Manual installation required for {' '.join(packages)}"

                    script_lines.append(cmd)
                    script_lines.append("")

        script_content = "\n".join(script_lines)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            os.chmod(output_path, 0o755)

        return script_content

    def install_dependencies(
        self,
        dependencies: list[SystemDependency] | None = None,
        dry_run: bool = False,
        timeout: int = 300,
    ) -> bool:
        """Install missing system dependencies."""
        if dependencies is None:
            dependencies = self.missing_dependencies

        if not dependencies:
            logger.info("No dependencies to install")
            return True

        if not self.package_manager:
            logger.error("No supported package manager detected")
            return False

        success = True
        failed_deps = []

        # Update package manager first (except for brew)
        if not dry_run and self.package_manager != PackageManager.BREW:
            try:
                self._update_package_manager(timeout=60)
            except Exception as e:
                logger.warning(f"Failed to update package manager: {e}")

        for dep in dependencies:
            if self.package_manager not in dep.packages:
                logger.warning(
                    f"No packages defined for {dep.name} on {self.package_manager.value}"
                )
                failed_deps.append(dep.name)
                continue

            packages = dep.packages[self.package_manager]
            if not packages:
                logger.warning(f"Empty package list for {dep.name}")
                continue

            logger.info(f"Installing {dep.description}: {packages}")

            if dry_run:
                logger.info(f"[DRY RUN] Would install: {packages}")
                continue

            try:
                install_success = self._install_packages_with_retry(packages, timeout)
                if not install_success:
                    success = False
                    failed_deps.append(dep.name)

            except Exception as e:
                logger.error(f"Failed to install {dep.name}: {e}")
                success = False
                failed_deps.append(dep.name)

        if failed_deps:
            logger.error(f"Failed to install dependencies: {failed_deps}")

        return success

    def _update_package_manager(self, timeout: int = 60) -> None:
        """Update package manager repositories."""
        if self.package_manager == PackageManager.APT:
            subprocess.run(
                ["sudo", "apt-get", "update"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        elif self.package_manager == PackageManager.YUM:
            subprocess.run(
                ["sudo", "yum", "update", "-y"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        elif self.package_manager == PackageManager.DNF:
            subprocess.run(
                ["sudo", "dnf", "update", "-y"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        elif self.package_manager == PackageManager.PACMAN:
            subprocess.run(
                ["sudo", "pacman", "-Sy"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        elif self.package_manager == PackageManager.APK:
            subprocess.run(
                ["sudo", "apk", "update"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        elif self.package_manager == PackageManager.ZYPPER:
            subprocess.run(
                ["sudo", "zypper", "refresh"],
                check=True,
                timeout=timeout,
                capture_output=True,
            )

    def _install_packages_with_retry(
        self, packages: list[str], timeout: int = 300, max_retries: int = 2
    ) -> bool:
        """Install packages with retry logic."""
        if not self.package_manager:
            logger.error("No supported package manager detected")
            return False

        for attempt in range(max_retries + 1):
            try:
                if self.package_manager == PackageManager.APT:
                    subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "--no-install-recommends"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                elif self.package_manager in [PackageManager.YUM, PackageManager.DNF]:
                    subprocess.run(
                        ["sudo", self.package_manager.value, "install", "-y"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                elif self.package_manager == PackageManager.BREW:
                    subprocess.run(
                        ["brew", "install"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                elif self.package_manager == PackageManager.PACMAN:
                    subprocess.run(
                        ["sudo", "pacman", "-S", "--noconfirm"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                elif self.package_manager == PackageManager.APK:
                    subprocess.run(
                        ["sudo", "apk", "add", "--no-cache"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                elif self.package_manager == PackageManager.ZYPPER:
                    subprocess.run(
                        ["sudo", "zypper", "install", "-y"] + packages,
                        check=True,
                        timeout=timeout,
                        capture_output=True,
                    )
                else:
                    pm_name = self.package_manager.value
                    logger.error(f"Unsupported package manager: {pm_name}")
                    return False

                return True

            except subprocess.TimeoutExpired:
                if attempt < max_retries:
                    logger.warning(
                        f"Installation timeout, retrying... (attempt {attempt + 1}/{max_retries + 1})"
                    )
                    continue
                else:
                    logger.error(f"Installation timed out after {max_retries + 1} attempts")
                    return False

            except subprocess.CalledProcessError as e:
                if attempt < max_retries:
                    logger.warning(
                        f"Installation failed, retrying... (attempt {attempt + 1}/{max_retries + 1}): {e}"
                    )
                    continue
                else:
                    logger.error(f"Installation failed after {max_retries + 1} attempts: {e}")
                    if e.stderr:
                        logger.error(f"Error output: {e.stderr.decode()}")
                    return False

        return False

    def generate_dockerfile_snippet(
        self,
        dependencies: list[SystemDependency] | None = None,
    ) -> str:
        """Generate Dockerfile snippet for installing dependencies."""
        if dependencies is None:
            dependencies = list(self.DEPENDENCY_MAP.values())

        # Group by package manager
        apt_packages = set()
        apk_packages = set()

        for dep in dependencies:
            if PackageManager.APT in dep.packages:
                apt_packages.update(dep.packages[PackageManager.APT])
            if PackageManager.APK in dep.packages:
                apk_packages.update(dep.packages[PackageManager.APK])

        snippet_lines = []

        if apt_packages:
            snippet_lines.extend(
                [
                    "# Install system dependencies for Debian/Ubuntu",
                    "RUN apt-get update && apt-get install -y --no-install-recommends \\",
                ]
            )
            for pkg in sorted(apt_packages):
                snippet_lines.append(f"    {pkg} \\")
            snippet_lines[-1] = snippet_lines[-1].rstrip(" \\")
            snippet_lines.extend(
                [
                    "    && apt-get clean \\",
                    "    && rm -rf /var/lib/apt/lists/*",
                    "",
                ]
            )

        if apk_packages:
            snippet_lines.extend(
                [
                    "# Install system dependencies for Alpine",
                    "RUN apk add --no-cache \\",
                ]
            )
            for pkg in sorted(apk_packages):
                snippet_lines.append(f"    {pkg} \\")
            snippet_lines[-1] = snippet_lines[-1].rstrip(" \\")
            snippet_lines.append("")

        return "\n".join(snippet_lines)

    def generate_ci_config(
        self,
        ci_platform: str = "github",
        dependencies: list[SystemDependency] | None = None,
    ) -> str:
        """Generate CI configuration for installing dependencies."""
        if dependencies is None:
            dependencies = self.missing_dependencies

        if ci_platform.lower() == "github":
            return self._generate_github_actions_config(dependencies)
        elif ci_platform.lower() == "gitlab":
            return self._generate_gitlab_ci_config(dependencies)
        else:
            raise ValueError(f"Unsupported CI platform: {ci_platform}")

    def _generate_github_actions_config(
        self,
        dependencies: list[SystemDependency],
    ) -> str:
        """Generate GitHub Actions configuration."""
        apt_packages = set()
        brew_packages = set()

        for dep in dependencies:
            if PackageManager.APT in dep.packages:
                apt_packages.update(dep.packages[PackageManager.APT])
            if PackageManager.BREW in dep.packages:
                brew_packages.update(dep.packages[PackageManager.BREW])

        config_lines = []

        if apt_packages:
            config_lines.extend(
                [
                    "      - name: Install system dependencies (Ubuntu)",
                    "        if: runner.os == 'Linux'",
                    "        run: |",
                    "          sudo apt-get update",
                    f"          sudo apt-get install -y {' '.join(sorted(apt_packages))}",
                    "",
                ]
            )

        if brew_packages:
            config_lines.extend(
                [
                    "      - name: Install system dependencies (macOS)",
                    "        if: runner.os == 'macOS'",
                    "        run: |",
                    f"          brew install {' '.join(sorted(brew_packages))}",
                    "",
                ]
            )

        return "\n".join(config_lines)

    def _generate_gitlab_ci_config(
        self,
        dependencies: list[SystemDependency],
    ) -> str:
        """Generate GitLab CI configuration."""
        apt_packages = set()

        for dep in dependencies:
            if PackageManager.APT in dep.packages:
                apt_packages.update(dep.packages[PackageManager.APT])

        config_lines = []

        if apt_packages:
            config_lines.extend(
                [
                    "before_script:",
                    "  - apt-get update -qq",
                    f"  - apt-get install -y {' '.join(sorted(apt_packages))}",
                    "",
                ]
            )

        return "\n".join(config_lines)
