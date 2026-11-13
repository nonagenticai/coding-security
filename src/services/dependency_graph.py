"""Dependency Graph Construction Module.

Handles building dependency graphs, resolving transitive dependencies,
and managing the dependency tree structure.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from models.package_manager_models import ExternalPackage
from services.dependency_extraction import EXTRAS_RE

logger = logging.getLogger(__name__)


class DependencyGraphBuilder:
    """Builds dependency graphs and resolves transitive dependencies.

    Supports multiple ecosystems and provides recursive dependency resolution
    with configurable depth limits to prevent infinite loops.
    """

    def __init__(self, timeout: int = 30) -> None:
        """Initialize the dependency graph builder.

        Args:
            timeout: HTTP timeout for API requests in seconds
        """
        self.timeout = timeout
        logger.info("DependencyGraphBuilder initialized with timeout: %ds", timeout)

    async def build_dependency_graph(
        self, packages: list[ExternalPackage], max_depth: int = 3
    ) -> list[ExternalPackage]:
        """Build a complete dependency graph including transitive dependencies.

        Args:
            packages: Direct dependencies to start resolution from
            max_depth: Maximum depth for recursive resolution

        Returns:
            List of all dependencies including transitive ones

        Raises:
            RuntimeError: If graph building fails
        """
        logger.info(
            "Building dependency graph for %d packages (max depth: %d)",
            len(packages),
            max_depth,
        )

        try:
            all_packages = await self.analyze_transitive_dependencies(packages, max_depth)
            logger.info(
                "Successfully built dependency graph with %d total packages",
                len(all_packages),
            )
            return all_packages
        except Exception as e:
            logger.error("Failed to build dependency graph: %s", e)
            raise RuntimeError(f"Dependency graph building failed: {e}") from e

    async def analyze_transitive_dependencies(
        self, packages: list[ExternalPackage], max_depth: int = 3
    ) -> list[ExternalPackage]:
        """Recursively resolve and analyze transitive dependencies.

        Args:
            packages: Direct dependencies to start resolution from
            max_depth: Maximum depth for recursive resolution to prevent infinite loops

        Returns:
            List of all dependencies including transitive ones
        """
        # The input set is resolved (a lockfile can hold two versions of one name, and
        # both are kept); a transitive dep is added only for a name the input does not
        # lock and no earlier step added, so it never adds a second copy of a name.
        all_packages: dict[tuple[str, str], ExternalPackage] = {}
        names: set[str] = {package.name for package in packages}

        async def resolve_recursive(current_packages: list[ExternalPackage], depth: int = 0):
            if depth >= max_depth:
                logger.warning(
                    "Maximum dependency resolution depth reached (%d)",
                    max_depth,
                )
                return

            for package in current_packages:
                key = (package.name, package.version or "")
                if key in all_packages or (depth > 0 and package.name in names):
                    continue

                names.add(package.name)
                all_packages[key] = package

                # Resolve transitive dependencies for this package
                try:
                    transitive_deps = await self._resolve_package_dependencies(package)
                    if transitive_deps:
                        await resolve_recursive(transitive_deps, depth + 1)
                except Exception as e:
                    logger.warning(
                        "Failed to resolve transitive dependencies for %s: %s",
                        package.name,
                        e,
                    )

        # Start recursive resolution
        await resolve_recursive(packages, 0)

        logger.info(
            "Resolved %d total dependencies (including transitive)",
            len(all_packages),
        )
        return list(all_packages.values())

    async def _resolve_package_dependencies(
        self, package: ExternalPackage
    ) -> list[ExternalPackage]:
        """Resolve dependencies for a specific package.

        Args:
            package: Package to resolve dependencies for

        Returns:
            List of direct dependencies for the package
        """
        dependencies: list[ExternalPackage] = []

        try:
            if package.ecosystem == "pypi":
                dependencies = await self._resolve_pypi_dependencies(package)
            elif package.ecosystem == "npm":
                dependencies = await self._resolve_npm_dependencies(package)
            elif package.ecosystem == "crates.io":
                dependencies = await self._resolve_crates_dependencies(package)
            else:
                logger.debug(
                    "Dependency resolution not implemented for ecosystem: %s",
                    package.ecosystem,
                )

        except Exception as e:
            logger.warning("Error resolving dependencies for %s: %s", package.name, e)

        return dependencies

    async def _resolve_pypi_dependencies(self, package: ExternalPackage) -> list[ExternalPackage]:
        """Resolve PyPI package dependencies using the PyPI API.

        Args:
            package: PyPI package to resolve dependencies for

        Returns:
            List of direct dependencies
        """
        dependencies: list[ExternalPackage] = []

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10)) as client:
                url = f"https://pypi.org/pypi/{package.name}/json"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    info = data.get("info", {})

                    # Extract requires_dist information
                    requires_dist = info.get("requires_dist") or []

                    for req in requires_dist:
                        if isinstance(req, str):
                            dep_name, dep_version = self._parse_pypi_requirement(req)
                            if dep_name:
                                dep_package = ExternalPackage(
                                    name=dep_name,
                                    version=dep_version or "*",
                                    license="Unknown",
                                    ecosystem="pypi",
                                    description=f"Transitive dependency of {package.name}",
                                )
                                dependencies.append(dep_package)

        except Exception as e:
            logger.warning(
                "Failed to resolve PyPI dependencies for %s: %s",
                package.name,
                e,
            )

        return dependencies

    async def _resolve_npm_dependencies(self, package: ExternalPackage) -> list[ExternalPackage]:
        """Resolve npm package dependencies using the npm registry API.

        Args:
            package: npm package to resolve dependencies for

        Returns:
            List of direct dependencies
        """
        dependencies: list[ExternalPackage] = []

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10)) as client:
                url = f"https://registry.npmjs.org/{package.name}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()

                    # Get the latest version or specified version
                    version = package.version
                    if version == "*" or not version:
                        version = data.get("dist-tags", {}).get("latest", "")

                    if version and "versions" in data and version in data["versions"]:
                        version_info = data["versions"][version]
                        deps = version_info.get("dependencies", {})

                        for dep_name, dep_version in deps.items():
                            dep_package = ExternalPackage(
                                name=dep_name,
                                version=dep_version,
                                license="Unknown",
                                ecosystem="npm",
                                description=f"Transitive dependency of {package.name}",
                            )
                            dependencies.append(dep_package)

        except Exception as e:
            logger.warning(
                "Failed to resolve npm dependencies for %s: %s",
                package.name,
                e,
            )

        return dependencies

    async def _resolve_crates_dependencies(self, package: ExternalPackage) -> list[ExternalPackage]:
        """Resolve Rust crate dependencies using the crates.io API.

        Args:
            package: Rust crate to resolve dependencies for

        Returns:
            List of direct dependencies
        """
        dependencies: list[ExternalPackage] = []

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10)) as client:
                # Get crate info and determine version
                crates_url = f"https://crates.io/api/v1/crates/{package.name}"
                response = await client.get(crates_url)
                if response.status_code != 200:
                    return dependencies
                crate_data = response.json()
                version = (
                    package.version
                    if package.version not in ("*", None, "")
                    else crate_data.get("crate", {}).get("newest_version", "")
                )

                if not version:
                    return dependencies

                # Get dependencies for the version
                deps_url = f"https://crates.io/api/v1/crates/{package.name}/{version}/dependencies"
                deps_response = await client.get(deps_url)
                if deps_response.status_code == 200:
                    for dep in deps_response.json().get("dependencies", []):
                        if dep.get("kind") == "normal":  # Only runtime dependencies
                            dependencies.append(
                                ExternalPackage(
                                    name=dep["crate_id"],
                                    version=dep.get("req", "*"),
                                    license="Unknown",
                                    ecosystem="crates.io",
                                    description=f"Transitive dependency of {package.name}",
                                )
                            )

        except Exception as e:
            logger.warning(
                "Failed to resolve crates dependencies for %s: %s",
                package.name,
                e,
            )

        return dependencies

    def _parse_pypi_requirement(self, requirement: str) -> tuple[str | None, str | None]:
        """Parse a PyPI requirement string to extract name and version.

        Args:
            requirement: PyPI requirement string

        Returns:
            Tuple of (package_name, version) or (None, None) if parsing fails
        """
        # Handle requirements with extras: package[extra]==version
        requirement = EXTRAS_RE.sub("", requirement)  # linear; see dependency_extraction

        # Handle various version specifiers
        patterns = [
            r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([^\s;,]+)",  # package>=1.0
            r"^([a-zA-Z0-9_.-]+)\s*$",  # just package name
        ]

        for pattern in patterns:
            match = re.match(pattern, requirement.strip())
            if match:
                name = match.group(1)
                version = match.group(3) if len(match.groups()) >= 3 else None
                return name, version

        return None, None

    def build_dependency_tree(self, packages: list[ExternalPackage]) -> dict[str, dict[str, Any]]:
        """Build a tree representation of package dependencies.

        Args:
            packages: List of packages to build tree for

        Returns:
            Dictionary representing the dependency tree
        """
        tree = {}

        for package in packages:
            tree[package.name] = {
                "version": package.version or package.current_version or "*",
                "ecosystem": package.ecosystem,
                "license": package.license or "Unknown",
                "description": package.description or "",
                "dependencies": [],  # Will be populated with resolved deps
            }

        return tree

    def find_dependency_paths(
        self, packages: list[ExternalPackage], target_package: str
    ) -> list[list[str]]:
        """Find all dependency paths that lead to a target package.

        Args:
            packages: List of all packages in the dependency graph
            target_package: Name of the target package to find paths to

        Returns:
            List of dependency paths (each path is a list of package names)
        """
        paths = []

        def find_paths_recursive(current_package: str, current_path: list[str], visited: set[str]):
            if current_package == target_package:
                paths.append(current_path + [current_package])
                return

            if current_package in visited:
                return  # Avoid cycles

            visited.add(current_package)

            # This is a simplified implementation
            # In a real scenario, we'd need to track actual dependency relationships
            for pkg in packages:
                if pkg.name != current_package and current_package not in visited:
                    find_paths_recursive(pkg.name, current_path + [current_package], visited.copy())

        # Start from all root packages (packages that aren't dependencies of others)
        root_packages = [pkg.name for pkg in packages]  # Simplified

        for root in root_packages:
            find_paths_recursive(root, [], set())

        return paths
