"""Circular Dependency Detection Module.

Detects circular dependencies in dependency graphs and provides
analysis and reporting of cyclic relationships.
"""

from __future__ import annotations

import logging
from typing import Any

from models.package_manager_models import ExternalPackage

logger = logging.getLogger(__name__)


class CircularDependencyDetector:
    """Detects and analyzes circular dependencies in package dependency graphs.

    Uses depth-first search and topological sorting algorithms to identify
    cycles and provide detailed analysis of circular dependency chains.
    """

    def __init__(self) -> None:
        """Initialize the circular dependency detector."""
        logger.info("CircularDependencyDetector initialized")

    def detect_circular_dependencies(
        self, packages: list[ExternalPackage], dependency_map: dict[str, list[str]]
    ) -> list[list[str]]:
        """Detect all circular dependencies in the package graph.

        Args:
            packages: List of all packages
            dependency_map: Mapping of package names to their dependencies

        Returns:
            List of circular dependency chains (each chain is a list of package names)
        """
        logger.info(
            "Detecting circular dependencies in %d packages",
            len(packages),
        )

        # Build adjacency list if dependency_map is not provided
        if not dependency_map:
            dependency_map = self._build_dependency_map(packages)

        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        current_path: list[str] = []

        def dfs_detect_cycle(node: str) -> bool:
            """Depth-first search to detect cycles."""
            if node in rec_stack:
                # Found a cycle - extract the cycle from current_path
                cycle_start = current_path.index(node)
                cycle = current_path[cycle_start:] + [node]
                cycles.append(cycle)
                return True

            if node in visited:
                return False

            visited.add(node)
            rec_stack.add(node)
            current_path.append(node)

            # Visit all dependencies
            for dependency in dependency_map.get(node, []):
                if dfs_detect_cycle(dependency):
                    pass  # Continue to find all cycles

            rec_stack.remove(node)
            current_path.pop()
            return False

        # Check each package as a potential starting point
        for package in packages:
            if package.name not in visited:
                dfs_detect_cycle(package.name)

        # Remove duplicate cycles
        unique_cycles = self._deduplicate_cycles(cycles)

        logger.info(
            "Found %d circular dependency chains",
            len(unique_cycles),
        )

        return unique_cycles

    def _build_dependency_map(self, packages: list[ExternalPackage]) -> dict[str, list[str]]:
        """Build a dependency map from package list.

        Note: This is a simplified implementation. In a real scenario,
        we would need access to the actual dependency relationships.

        Args:
            packages: List of packages

        Returns:
            Dictionary mapping package names to their dependencies
        """
        dependency_map: dict[str, list[str]] = {}

        # This is a placeholder implementation
        # In reality, we would extract actual dependency relationships
        for package in packages:
            dependency_map[package.name] = []

        return dependency_map

    def _deduplicate_cycles(self, cycles: list[list[str]]) -> list[list[str]]:
        """Remove duplicate cycles (cycles that represent the same circular dependency).

        Args:
            cycles: List of cycles to deduplicate

        Returns:
            List of unique cycles
        """
        unique_cycles = []
        seen_cycles = set()

        for cycle in cycles:
            # Normalize the cycle by starting from the lexicographically smallest element
            if not cycle:
                continue

            min_idx = cycle.index(min(cycle))
            normalized_cycle = cycle[min_idx:] + cycle[:min_idx]

            # Create a canonical representation
            cycle_key = tuple(normalized_cycle)
            reverse_cycle_key = tuple(reversed(normalized_cycle))

            # Check if we've seen this cycle or its reverse
            if cycle_key not in seen_cycles and reverse_cycle_key not in seen_cycles:
                unique_cycles.append(normalized_cycle)
                seen_cycles.add(cycle_key)

        return unique_cycles

    def analyze_circular_dependency_impact(
        self, cycles: list[list[str]], packages: list[ExternalPackage]
    ) -> dict[str, Any]:
        """Analyze the impact of circular dependencies.

        Args:
            cycles: List of circular dependency chains
            packages: List of all packages

        Returns:
            Dictionary containing impact analysis
        """
        if not cycles:
            return {
                "total_cycles": 0,
                "packages_involved": 0,
                "largest_cycle_size": 0,
                "average_cycle_size": 0.0,
                "impact_score": 0.0,
                "affected_packages": [],
            }

        # Collect statistics
        total_cycles = len(cycles)
        affected_packages = set()
        cycle_sizes = []

        for cycle in cycles:
            cycle_sizes.append(len(cycle))
            affected_packages.update(cycle)

        largest_cycle_size = max(cycle_sizes) if cycle_sizes else 0
        average_cycle_size = sum(cycle_sizes) / len(cycle_sizes) if cycle_sizes else 0.0

        # Calculate impact score (0-10, where 10 is highest impact)
        impact_score = min(
            10.0,
            (
                (total_cycles * 2.0)  # Base impact from number of cycles
                + (len(affected_packages) * 1.5)  # Impact from affected packages
                + (largest_cycle_size * 0.5)  # Impact from cycle complexity
            ),
        )

        return {
            "total_cycles": total_cycles,
            "packages_involved": len(affected_packages),
            "largest_cycle_size": largest_cycle_size,
            "average_cycle_size": round(average_cycle_size, 1),
            "impact_score": round(impact_score, 1),
            "affected_packages": sorted(list(affected_packages)),
            "cycle_details": [
                {
                    "cycle_id": i + 1,
                    "packages": cycle,
                    "size": len(cycle),
                }
                for i, cycle in enumerate(cycles)
            ],
        }

    def get_breaking_recommendations(self, cycles: list[list[str]]) -> list[dict[str, Any]]:
        """Get recommendations for breaking circular dependencies.

        Args:
            cycles: List of circular dependency chains

        Returns:
            List of recommendations for breaking cycles
        """
        recommendations: list[dict[str, Any]] = []

        for i, cycle in enumerate(cycles):
            if len(cycle) < 2:
                continue

            # For each cycle, suggest potential breaking points
            breaking_points: list[dict[str, Any]] = []

            # Strategy 1: Break at the weakest link (package with most dependencies)
            # This is a simplified heuristic
            for j in range(len(cycle) - 1):
                source = cycle[j]
                target = cycle[j + 1]
                breaking_points.append(
                    {
                        "source": source,
                        "target": target,
                        "strategy": "Remove direct dependency",
                        "difficulty": "medium",
                    }
                )

            # Strategy 2: Introduce abstraction layer
            if len(cycle) >= 3:
                middle_packages = cycle[1:-1]
                breaking_points.append(
                    {
                        "strategy": "Introduce abstraction layer",
                        "packages": middle_packages,
                        "difficulty": "high",
                        "description": f"Create interface/abstraction for {', '.join(middle_packages)}",
                    }
                )

            recommendations.append(
                {
                    "cycle_id": i + 1,
                    "cycle": cycle,
                    "cycle_size": len(cycle),
                    "breaking_points": breaking_points,
                    "priority": "high" if len(cycle) <= 3 else "medium",
                }
            )

        return recommendations

    def validate_acyclic_graph(
        self, packages: list[ExternalPackage], dependency_map: dict[str, list[str]]
    ) -> bool:
        """Validate that the dependency graph is acyclic using topological sorting.

        Args:
            packages: List of packages
            dependency_map: Mapping of package names to their dependencies

        Returns:
            True if the graph is acyclic, False otherwise
        """
        # Use Kahn's algorithm for topological sorting
        in_degree = {pkg.name: 0 for pkg in packages}

        # Calculate in-degrees
        for package_name, dependencies in dependency_map.items():
            for dep in dependencies:
                if dep in in_degree:
                    in_degree[dep] += 1

        # Initialize queue with nodes having no incoming edges
        queue = [pkg for pkg, degree in in_degree.items() if degree == 0]
        processed_count = 0

        while queue:
            current = queue.pop(0)
            processed_count += 1

            # Remove edges from current node
            for dependency in dependency_map.get(current, []):
                if dependency in in_degree:
                    in_degree[dependency] -= 1
                    if in_degree[dependency] == 0:
                        queue.append(dependency)

        # If we processed all nodes, the graph is acyclic
        is_acyclic = processed_count == len(packages)

        logger.info(
            "Graph validation: %s (processed %d/%d packages)",
            "acyclic" if is_acyclic else "contains cycles",
            processed_count,
            len(packages),
        )

        return is_acyclic

    def find_strongly_connected_components(
        self, packages: list[ExternalPackage], dependency_map: dict[str, list[str]]
    ) -> list[list[str]]:
        """Find strongly connected components using Tarjan's algorithm.

        Args:
            packages: List of packages
            dependency_map: Mapping of package names to their dependencies

        Returns:
            List of strongly connected components
        """
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        components = []

        def strongconnect(node: str) -> None:
            # Set the depth index for this node to the smallest unused index
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True

            # Consider successors of node
            for dependency in dependency_map.get(node, []):
                if dependency not in index:
                    # Successor has not yet been visited; recurse on it
                    strongconnect(dependency)
                    lowlinks[node] = min(lowlinks[node], lowlinks[dependency])
                elif on_stack.get(dependency, False):
                    # Successor is in stack and hence in the current SCC
                    lowlinks[node] = min(lowlinks[node], index[dependency])

            # If node is a root node, pop the stack and print an SCC
            if lowlinks[node] == index[node]:
                component = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == node:
                        break
                if len(component) > 1:  # Only include components with more than one node
                    components.append(component)

        # Run the algorithm on all unvisited nodes
        for package in packages:
            if package.name not in index:
                strongconnect(package.name)

        logger.info(
            "Found %d strongly connected components",
            len(components),
        )

        return components
