"""Tests for DependencyGraphBuilder (dependency_graph.py)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.package_manager_models import ExternalPackage
from services.dependency_graph import DependencyGraphBuilder


def make_package(
    name: str = "requests",
    version: str = "2.31.0",
    ecosystem: str = "pypi",
) -> ExternalPackage:
    return ExternalPackage(name=name, version=version, ecosystem=ecosystem)


@pytest.fixture
def builder():
    return DependencyGraphBuilder(timeout=5)


class TestBuildDependencyGraph:
    async def test_empty_packages(self, builder):
        result = await builder.build_dependency_graph([], max_depth=3)
        assert result == []

    async def test_direct_deps_returned(self, builder):
        packages = [make_package(name="fastapi")]
        with patch.object(
            builder, "_resolve_package_dependencies", new_callable=AsyncMock
        ) as mock_resolve:
            mock_resolve.return_value = []
            result = await builder.build_dependency_graph(packages, max_depth=1)
        assert len(result) == 1
        assert result[0].name == "fastapi"

    async def test_failure_raises_runtime_error(self, builder):
        packages = [make_package()]
        with patch.object(
            builder, "analyze_transitive_dependencies", new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.side_effect = Exception("API failed")
            with pytest.raises(RuntimeError, match="Dependency graph building failed"):
                await builder.build_dependency_graph(packages)


class TestAnalyzeTransitiveDependencies:
    async def test_depth_limit_respected(self, builder):
        root = make_package(name="root")
        child = make_package(name="child")

        call_count = 0

        async def mock_resolve(pkg):
            nonlocal call_count
            call_count += 1
            if pkg.name == "root":
                return [child]
            return [make_package(name=f"deep-{call_count}")]

        with patch.object(builder, "_resolve_package_dependencies", side_effect=mock_resolve):
            result = await builder.analyze_transitive_dependencies([root], max_depth=2)

        # root (depth 0) -> child (depth 1) -> deep-X (depth 2 = max, stops)
        names = [p.name for p in result]
        assert "root" in names
        assert "child" in names

    async def test_no_infinite_recursion(self, builder):
        """Same package appearing as transitive dep should not loop."""
        root = make_package(name="root")
        child = make_package(name="child")

        async def mock_resolve(pkg):
            if pkg.name == "root":
                return [child]
            elif pkg.name == "child":
                return [make_package(name="root")]  # Circular
            return []

        with patch.object(builder, "_resolve_package_dependencies", side_effect=mock_resolve):
            result = await builder.analyze_transitive_dependencies([root], max_depth=10)

        names = [p.name for p in result]
        assert "root" in names
        assert "child" in names
        assert len(result) == 2  # No duplicate from circular

    async def test_transitive_dep_never_adds_a_second_copy_of_a_locked_name(self, builder):
        """Lock aiohttp 3.9.5 + yarl 1.9.4; aiohttp's metadata names yarl>=1.0.

        One yarl, at the locked version (main also kept one yarl, but the
        transitive 1.0 instead of the locked 1.9.4). The resolver is the live
        PyPI JSON API, so it is the one thing substituted here.
        """

        async def mock_resolve(pkg):
            return [make_package(name="yarl", version="1.0")] if pkg.name == "aiohttp" else []

        locked = [make_package("aiohttp", "3.9.5"), make_package("yarl", "1.9.4")]
        with patch.object(builder, "_resolve_package_dependencies", side_effect=mock_resolve):
            result = await builder.analyze_transitive_dependencies(locked, max_depth=3)

        assert [(p.name, p.version) for p in result] == [("aiohttp", "3.9.5"), ("yarl", "1.9.4")]

    async def test_two_locked_versions_of_one_name_are_both_kept(self, builder):
        """No resolver substitution: maven has no transitive resolver, so this is the
        real builder on real input (two guava versions on one classpath)."""
        locked = [
            make_package("com.google.guava:guava", "31.1-jre", "maven"),
            make_package("com.google.guava:guava", "32.0.0-jre", "maven"),
        ]
        result = await builder.analyze_transitive_dependencies(locked, max_depth=3)

        assert [p.version for p in result] == ["31.1-jre", "32.0.0-jre"]


class TestResolvePypiDependencies:
    async def test_mock_pypi_response(self, builder):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "requires_dist": [
                    "urllib3>=1.21.1",
                    "certifi>=2017.4.17",
                    "idna>=2.5 ; python_version >= '3.0'",
                ]
            }
        }

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            pkg = make_package(name="requests", ecosystem="pypi")
            deps = await builder._resolve_pypi_dependencies(pkg)

        names = [d.name for d in deps]
        assert "urllib3" in names
        assert "certifi" in names


class TestResolveNpmDependencies:
    async def test_mock_npm_response(self, builder):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "dist-tags": {"latest": "4.18.2"},
            "versions": {
                "4.18.2": {
                    "dependencies": {
                        "body-parser": "1.20.2",
                        "cookie": "0.5.0",
                    }
                }
            },
        }

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            pkg = make_package(name="express", version="*", ecosystem="npm")
            deps = await builder._resolve_npm_dependencies(pkg)

        names = [d.name for d in deps]
        assert "body-parser" in names
        assert "cookie" in names


class TestParsePypiRequirement:
    def test_version_specifier(self, builder):
        name, version = builder._parse_pypi_requirement("pkg>=1.0")
        assert name == "pkg"
        assert version == "1.0"

    def test_bare_name(self, builder):
        name, version = builder._parse_pypi_requirement("simple-pkg")
        assert name == "simple-pkg"
        assert version is None

    def test_extras_stripped(self, builder):
        name, version = builder._parse_pypi_requirement("package[extra1,extra2]>=2.0")
        assert name == "package"
        assert version == "2.0"

    def test_unparseable(self, builder):
        name, version = builder._parse_pypi_requirement("")
        assert name is None
        assert version is None


class TestBuildDependencyTree:
    def test_correct_dict_structure(self, builder):
        packages = [
            make_package(name="fastapi", version="0.115.0", ecosystem="pypi"),
            make_package(name="express", version="4.18.2", ecosystem="npm"),
        ]
        tree = builder.build_dependency_tree(packages)

        assert "fastapi" in tree
        assert tree["fastapi"]["version"] == "0.115.0"
        assert tree["fastapi"]["ecosystem"] == "pypi"
        assert "express" in tree
        assert tree["express"]["version"] == "4.18.2"

    def test_empty_packages(self, builder):
        tree = builder.build_dependency_tree([])
        assert tree == {}


class TestFindDependencyPaths:
    def test_finds_direct_path(self, builder):
        packages = [
            make_package(name="target"),
        ]
        paths = builder.find_dependency_paths(packages, "target")
        assert len(paths) >= 1
        assert any("target" in path for path in paths)

    def test_empty_when_not_found(self, builder):
        packages = [
            make_package(name="other"),
        ]
        paths = builder.find_dependency_paths(packages, "nonexistent")
        assert paths == []

    def test_empty_packages_returns_no_paths(self, builder):
        """Empty package list returns empty paths."""
        paths = builder.find_dependency_paths([], "target")
        assert paths == []


class TestResolvePackageDependencies:
    """Tests for _resolve_package_dependencies ecosystem dispatch."""

    async def test_pypi_ecosystem_dispatches(self, builder):
        """PyPI packages dispatch to _resolve_pypi_dependencies."""
        pkg = make_package(name="requests", ecosystem="pypi")
        with patch.object(
            builder, "_resolve_pypi_dependencies", new_callable=AsyncMock
        ) as mock_pypi:
            mock_pypi.return_value = [make_package(name="urllib3", ecosystem="pypi")]
            result = await builder._resolve_package_dependencies(pkg)
        assert len(result) == 1
        assert result[0].name == "urllib3"
        mock_pypi.assert_called_once_with(pkg)

    async def test_npm_ecosystem_dispatches(self, builder):
        """npm packages dispatch to _resolve_npm_dependencies."""
        pkg = make_package(name="express", ecosystem="npm")
        with patch.object(builder, "_resolve_npm_dependencies", new_callable=AsyncMock) as mock_npm:
            mock_npm.return_value = []
            result = await builder._resolve_package_dependencies(pkg)
        assert result == []
        mock_npm.assert_called_once_with(pkg)

    async def test_crates_ecosystem_dispatches(self, builder):
        """crates.io packages dispatch to _resolve_crates_dependencies."""
        pkg = make_package(name="serde", ecosystem="crates.io")
        with patch.object(
            builder, "_resolve_crates_dependencies", new_callable=AsyncMock
        ) as mock_crates:
            mock_crates.return_value = []
            result = await builder._resolve_package_dependencies(pkg)
        assert result == []
        mock_crates.assert_called_once_with(pkg)

    async def test_unsupported_ecosystem_returns_empty(self, builder):
        """Unsupported ecosystem returns empty list."""
        pkg = make_package(name="some-gem", ecosystem="rubygems")
        result = await builder._resolve_package_dependencies(pkg)
        assert result == []

    async def test_exception_returns_empty(self, builder):
        """Exception during resolution returns empty list."""
        pkg = make_package(name="bad-pkg", ecosystem="pypi")
        with patch.object(
            builder, "_resolve_pypi_dependencies", new_callable=AsyncMock
        ) as mock_pypi:
            mock_pypi.side_effect = Exception("API error")
            result = await builder._resolve_package_dependencies(pkg)
        assert result == []


class TestResolveCratesDependencies:
    """Tests for _resolve_crates_dependencies."""

    async def test_crates_success(self, builder):
        """Successfully resolves crates.io dependencies."""
        mock_crate_response = MagicMock()
        mock_crate_response.status_code = 200
        mock_crate_response.json.return_value = {"crate": {"newest_version": "1.0.0"}}

        mock_deps_response = MagicMock()
        mock_deps_response.status_code = 200
        mock_deps_response.json.return_value = {
            "dependencies": [
                {"crate_id": "serde_derive", "req": "^1.0", "kind": "normal"},
                {"crate_id": "proc-macro2", "req": "^1.0", "kind": "dev"},
            ]
        }

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=[mock_crate_response, mock_deps_response])
            mock_cls.return_value = mock_client

            pkg = make_package(name="serde", version="*", ecosystem="crates.io")
            deps = await builder._resolve_crates_dependencies(pkg)

        # Only normal deps, not dev deps
        assert len(deps) == 1
        assert deps[0].name == "serde_derive"

    async def test_crates_specific_version(self, builder):
        """Uses specific version instead of newest when provided."""
        mock_crate_response = MagicMock()
        mock_crate_response.status_code = 200
        mock_crate_response.json.return_value = {"crate": {"newest_version": "2.0.0"}}

        mock_deps_response = MagicMock()
        mock_deps_response.status_code = 200
        mock_deps_response.json.return_value = {"dependencies": []}

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=[mock_crate_response, mock_deps_response])
            mock_cls.return_value = mock_client

            pkg = make_package(name="serde", version="1.0.195", ecosystem="crates.io")
            deps = await builder._resolve_crates_dependencies(pkg)

        assert deps == []
        # Verify the deps URL used the specific version
        calls = mock_client.get.call_args_list
        assert "1.0.195" in calls[1][0][0]

    async def test_crates_api_failure(self, builder):
        """API failure returns empty list."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="nonexistent-crate", version="1.0.0", ecosystem="crates.io")
            deps = await builder._resolve_crates_dependencies(pkg)

        assert deps == []

    async def test_crates_no_version_available(self, builder):
        """If no version can be determined, returns empty."""
        mock_crate_response = MagicMock()
        mock_crate_response.status_code = 200
        mock_crate_response.json.return_value = {"crate": {"newest_version": ""}}

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_crate_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="empty-crate", version="*", ecosystem="crates.io")
            deps = await builder._resolve_crates_dependencies(pkg)

        assert deps == []

    async def test_crates_exception_returns_empty(self, builder):
        """Exception during crates resolution returns empty list."""
        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("network error"))
            mock_cls.return_value = mock_client

            pkg = make_package(name="error-crate", version="1.0.0", ecosystem="crates.io")
            deps = await builder._resolve_crates_dependencies(pkg)

        assert deps == []


class TestBuildDependencyTreeExtended:
    """Extended tests for build_dependency_tree."""

    def test_package_with_current_version_fallback(self, builder):
        """Uses current_version when version is None."""
        pkg = ExternalPackage(
            name="legacy-pkg",
            version=None,
            current_version="3.2.1",
            ecosystem="pypi",
        )
        tree = builder.build_dependency_tree([pkg])
        assert tree["legacy-pkg"]["version"] == "3.2.1"

    def test_package_with_no_version_at_all(self, builder):
        """Falls back to '*' when no version info available."""
        pkg = ExternalPackage(
            name="versionless",
            version=None,
            current_version=None,
            ecosystem="pypi",
        )
        tree = builder.build_dependency_tree([pkg])
        assert tree["versionless"]["version"] == "*"

    def test_tree_includes_description(self, builder):
        """Tree includes package description."""
        pkg = ExternalPackage(
            name="described-pkg",
            version="1.0.0",
            ecosystem="pypi",
            description="A useful package",
        )
        tree = builder.build_dependency_tree([pkg])
        assert tree["described-pkg"]["description"] == "A useful package"

    def test_tree_license_unknown_fallback(self, builder):
        """Tree shows 'Unknown' when license is None."""
        pkg = make_package(name="nolicense")
        tree = builder.build_dependency_tree([pkg])
        assert tree["nolicense"]["license"] == "Unknown"


class TestResolveNpmDependenciesExtended:
    """Extended tests for _resolve_npm_dependencies."""

    async def test_specific_version_used(self, builder):
        """When package has a specific version, it uses that version's deps."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "dist-tags": {"latest": "4.18.2"},
            "versions": {
                "4.17.0": {"dependencies": {"old-dep": "1.0.0"}},
                "4.18.2": {"dependencies": {"new-dep": "2.0.0"}},
            },
        }

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="express", version="4.17.0", ecosystem="npm")
            deps = await builder._resolve_npm_dependencies(pkg)

        names = [d.name for d in deps]
        assert "old-dep" in names
        assert "new-dep" not in names

    async def test_npm_api_failure_returns_empty(self, builder):
        """npm API failure returns empty deps."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="nonexistent", version="1.0.0", ecosystem="npm")
            deps = await builder._resolve_npm_dependencies(pkg)

        assert deps == []

    async def test_npm_exception_returns_empty(self, builder):
        """Exception during npm resolution returns empty."""
        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("connection failed"))
            mock_cls.return_value = mock_client

            pkg = make_package(name="error-pkg", version="1.0.0", ecosystem="npm")
            deps = await builder._resolve_npm_dependencies(pkg)

        assert deps == []

    async def test_npm_version_not_in_versions(self, builder):
        """If specific version not in versions dict, returns empty."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "dist-tags": {"latest": "4.18.2"},
            "versions": {"4.18.2": {"dependencies": {"dep": "1.0"}}},
        }

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="express", version="3.0.0", ecosystem="npm")
            deps = await builder._resolve_npm_dependencies(pkg)

        assert deps == []


class TestResolvePypiDependenciesExtended:
    """Extended tests for _resolve_pypi_dependencies."""

    async def test_pypi_api_failure(self, builder):
        """PyPI API failure returns empty list."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="nonexistent", ecosystem="pypi")
            deps = await builder._resolve_pypi_dependencies(pkg)

        assert deps == []

    async def test_pypi_exception_returns_empty(self, builder):
        """Exception during pypi resolution returns empty list."""
        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("timeout"))
            mock_cls.return_value = mock_client

            pkg = make_package(name="error-pkg", ecosystem="pypi")
            deps = await builder._resolve_pypi_dependencies(pkg)

        assert deps == []

    async def test_pypi_no_requires_dist(self, builder):
        """Package with no requires_dist returns empty deps."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"requires_dist": None}}

        with patch("services.dependency_graph.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            pkg = make_package(name="simple-pkg", ecosystem="pypi")
            deps = await builder._resolve_pypi_dependencies(pkg)

        assert deps == []


class TestAnalyzeTransitiveDependenciesExtended:
    """Extended tests for transitive dependency analysis."""

    async def test_transitive_dep_error_doesnt_crash(self, builder):
        """If resolving transitive deps fails, the package is still included."""
        root = make_package(name="root")

        async def mock_resolve(pkg):
            raise RuntimeError("resolution failed")

        with patch.object(builder, "_resolve_package_dependencies", side_effect=mock_resolve):
            result = await builder.analyze_transitive_dependencies([root], max_depth=3)

        assert len(result) == 1
        assert result[0].name == "root"

    async def test_deep_chain_respects_max_depth(self, builder):
        """Resolution chain stops at max_depth."""
        counter = {"n": 0}

        async def mock_resolve(pkg):
            counter["n"] += 1
            return [make_package(name=f"depth-{counter['n']}")]

        with patch.object(builder, "_resolve_package_dependencies", side_effect=mock_resolve):
            result = await builder.analyze_transitive_dependencies(
                [make_package(name="root")], max_depth=3
            )

        names = [p.name for p in result]
        assert "root" in names
        # Should have depth-1 and depth-2 but stop at depth 3
        assert "depth-1" in names
        assert "depth-2" in names


class TestBuildDependencyGraphExtended:
    """Extended tests for build_dependency_graph."""

    async def test_multiple_direct_deps(self, builder):
        """Multiple direct deps are all resolved."""
        pkgs = [
            make_package(name="a", ecosystem="pypi"),
            make_package(name="b", ecosystem="npm"),
        ]
        with patch.object(
            builder, "_resolve_package_dependencies", new_callable=AsyncMock
        ) as mock_resolve:
            mock_resolve.return_value = []
            result = await builder.build_dependency_graph(pkgs, max_depth=1)

        assert len(result) == 2
        names = {p.name for p in result}
        assert names == {"a", "b"}
