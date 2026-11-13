"""Tests for DependencyExtractor."""

import json
from pathlib import Path

import pytest

from services.dependency_extraction import DependencyExtractor


@pytest.fixture
def extractor():
    return DependencyExtractor()


class TestDependencyExtraction:
    def test_extract_from_requirements_txt(self, extractor, tmp_path):
        """Extract deps from requirements.txt with correct names, versions, and ecosystem."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("fastapi>=0.115.0\nuvicorn==0.35.0\npydantic\n")
        packages = extractor.extract_dependencies(tmp_path)

        names = [p.name for p in packages]
        assert "fastapi" in names
        assert "uvicorn" in names
        assert "pydantic" in names

        # Verify versions are correctly parsed
        fastapi_pkg = next(p for p in packages if p.name == "fastapi")
        assert fastapi_pkg.version == "0.115.0"
        assert fastapi_pkg.ecosystem == "pypi"

        uvicorn_pkg = next(p for p in packages if p.name == "uvicorn")
        assert uvicorn_pkg.version == "0.35.0"

        pydantic_pkg = next(p for p in packages if p.name == "pydantic")
        assert pydantic_pkg.version == "*"

    def test_extract_from_package_json(self, extractor, tmp_path):
        """Extract deps from package.json with correct ecosystems and clean versions."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            )
        )
        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

        # All npm packages must have npm ecosystem
        for pkg in packages:
            assert pkg.ecosystem == "npm"

        # Version prefix stripping: ^4.18.0 -> 4.18.0
        express_pkg = next(p for p in packages if p.name == "express")
        assert express_pkg.version == "4.18.0"

        # Exact version stays the same
        lodash_pkg = next(p for p in packages if p.name == "lodash")
        assert lodash_pkg.version == "4.17.21"

    def test_package_json_version_range_stripping(self, extractor, tmp_path):
        """Multi-character version prefixes like >= are fully stripped."""
        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(
            json.dumps(
                {
                    "dependencies": {
                        "a": ">=1.2.3",
                        "b": "~2.0.0",
                        "c": "<=3.0.0",
                    },
                }
            )
        )
        packages = extractor.extract_dependencies(tmp_path)

        a = next(p for p in packages if p.name == "a")
        assert a.version == "1.2.3", ">=1.2.3 should strip to 1.2.3"

        b = next(p for p in packages if p.name == "b")
        assert b.version == "2.0.0"

        c = next(p for p in packages if p.name == "c")
        assert c.version == "3.0.0"

    def test_deduplicate_packages(self, extractor):
        """Deduplication keeps the most specific version (== wins over *)."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(name="pkg", version="*"),
            ExternalPackage(name="pkg", version="==1.0.0"),
        ]
        result = extractor.deduplicate_packages(packages)
        assert len(result) == 1
        assert result[0].version == "==1.0.0"

    def test_deduplicate_case_insensitive(self, extractor):
        """Deduplication is case-insensitive on package names."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(name="FastAPI", version="*"),
            ExternalPackage(name="fastapi", version="==0.115.0"),
        ]
        result = extractor.deduplicate_packages(packages)
        assert len(result) == 1
        assert result[0].version == "==0.115.0"

    def test_empty_repo(self, extractor, tmp_path):
        """Empty directory returns empty list."""
        packages = extractor.extract_dependencies(tmp_path)
        assert packages == []

    def test_invalid_path(self, extractor):
        """Non-existent path raises ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            extractor.extract_dependencies(Path("/nonexistent"))

    def test_parse_pypi_requirement(self, extractor):
        """Parse various requirement formats correctly."""
        name, version = extractor.parse_pypi_requirement("package>=1.0.0")
        assert name == "package"
        assert version == "1.0.0"

        name, version = extractor.parse_pypi_requirement("simple-pkg")
        assert name == "simple-pkg"
        assert version is None

        name, version = extractor.parse_pypi_requirement("pkg==2.3.4")
        assert name == "pkg"
        assert version == "2.3.4"

    def test_clean_version_for_osv(self, extractor):
        """Clean version strings for OSV API compatibility."""
        assert extractor.clean_version_for_osv("==1.0.0") == "1.0.0"
        assert extractor.clean_version_for_osv(">=2.0.0") == "2.0.0"
        assert extractor.clean_version_for_osv("*") is None
        assert extractor.clean_version_for_osv("") is None
        assert extractor.clean_version_for_osv("~=3.1.0") == "3.1.0"
        assert extractor.clean_version_for_osv("!=4.0.0") == "4.0.0"
        # Invalid versions return None
        assert extractor.clean_version_for_osv("not-a-version") is None

    def test_requirements_with_comments(self, extractor, tmp_path):
        """Skip comments, blank lines, and -r directives in requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\n\nfastapi>=0.100.0\n-r other.txt\n")
        packages = extractor.extract_dependencies(tmp_path)
        assert len(packages) == 1
        assert packages[0].name == "fastapi"
        assert packages[0].ecosystem == "pypi"

    def test_parse_pyproject_toml(self, extractor, tmp_path):
        """Parse pyproject.toml dependencies with correct ecosystem."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\ndependencies = [\n    "fastapi>=0.115.0",\n    "uvicorn",\n]\n'
        )
        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "fastapi" in names

        fastapi_pkg = next(p for p in packages if p.name == "fastapi")
        assert fastapi_pkg.version == "0.115.0"
        assert fastapi_pkg.ecosystem == "pypi"

    def test_parse_uv_lock_resolved_versions_incl_transitive(self, extractor, tmp_path):
        """uv.lock yields RESOLVED concrete versions for the full tree, including
        transitive deps that never appear in pyproject (the issue-C regression:
        aiohttp/diffusers were missed because only pyproject was scanned)."""
        (tmp_path / "uv.lock").write_text(
            "version = 1\n\n"
            '[[package]]\nname = "course-service"\nversion = "0.1.0"\nsource = { editable = "." }\n\n'
            '[[package]]\nname = "aiohttp"\nversion = "3.14.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n\n'
            '[[package]]\nname = "diffusers"\nversion = "0.37.1"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )
        packages = extractor.extract_dependencies(tmp_path)
        by_name = {p.name: p for p in packages}
        # Transitive/resolved deps are present with CONCRETE versions.
        assert by_name["aiohttp"].version == "3.14.0"
        assert by_name["aiohttp"].ecosystem == "pypi"
        assert by_name["diffusers"].version == "0.37.1"

    def test_lockfile_preferred_over_pyproject(self, extractor, tmp_path):
        """When both uv.lock and pyproject exist, the lock wins for PyPI: resolved
        versions + transitive deps, and the constraint-only pyproject is skipped."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n    "fastapi>=0.115.0",\n]\n'
        )
        (tmp_path / "uv.lock").write_text(
            '[[package]]\nname = "fastapi"\nversion = "0.115.2"\n\n'
            '[[package]]\nname = "starlette"\nversion = "0.41.0"\n'
        )
        packages = extractor.extract_dependencies(tmp_path)
        by_name = {p.name: p for p in packages}
        # Resolved version from the lock, NOT the ">=0.115.0" constraint bound.
        assert by_name["fastapi"].version == "0.115.2"
        # Transitive dep only in the lock is included.
        assert "starlette" in by_name
        # The constraint-form "fastapi" was not also added as a separate entry.
        assert sum(1 for p in packages if p.name == "fastapi") == 1

    def test_parse_cargo_toml_dependencies_section(self, extractor, tmp_path):
        """Parse [dependencies] from Cargo.toml (not just [dev-dependencies])."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nserde = "1.0"\ntokio = "1.35"\n')
        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "serde" in names
        assert "tokio" in names

        serde_pkg = next(p for p in packages if p.name == "serde")
        assert serde_pkg.ecosystem == "crates.io"
        assert serde_pkg.version == "1.0"

    def test_parse_cargo_toml_dev_dependencies(self, extractor, tmp_path):
        """Parse [dev-dependencies] from Cargo.toml."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dev-dependencies]\ncriterion = "0.5"\n')
        packages = extractor.extract_dependencies(tmp_path)
        assert len(packages) == 1
        assert packages[0].name == "criterion"
        assert packages[0].ecosystem == "crates.io"

    def test_parse_cargo_toml_both_sections(self, extractor, tmp_path):
        """Parse both [dependencies] and [dev-dependencies] from Cargo.toml."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nserde = "1.0"\n\n[dev-dependencies]\ncriterion = "0.5"\n')
        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "serde" in names
        assert "criterion" in names

    def test_enrich_packages(self, extractor):
        """Enrich packages populates latest_version and license from external sources."""
        from unittest.mock import patch

        from models.package_manager_models import ExternalPackage

        packages = [ExternalPackage(name="fastapi", version="0.115.0", ecosystem="pypi")]
        with patch.object(extractor, "_get_latest_version", return_value="0.116.0"):
            with patch.object(extractor, "_get_license_info", return_value="MIT"):
                result = extractor.enrich_packages(packages)

        assert len(result) == 1
        assert result[0].name == "fastapi"
        assert result[0].version == "0.115.0"
        assert result[0].latest_version == "0.116.0"
        assert result[0].license == "MIT"
        assert result[0].ecosystem == "pypi"

    def test_get_latest_version_success(self, extractor):
        """Get latest version from PyPI returns correct version string."""
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"info": {"version": "0.116.0"}}
        with patch("services.dependency_extraction.httpx.get", return_value=mock_resp):
            result = extractor._get_latest_version("fastapi")
        assert result == "0.116.0"

    def test_get_latest_version_failure(self, extractor):
        """Get latest version returns None on HTTP error."""
        from unittest.mock import patch

        import httpx

        with patch("services.dependency_extraction.httpx.get", side_effect=httpx.HTTPError("fail")):
            result = extractor._get_latest_version("nonexistent")
        assert result is None

    def test_get_latest_version_non_200(self, extractor):
        """Get latest version returns None on non-200 status."""
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("services.dependency_extraction.httpx.get", return_value=mock_resp):
            result = extractor._get_latest_version("nonexistent")
        assert result is None

    def test_get_license_info_success(self, extractor):
        """Get license info from PyPI returns the license string."""
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "info": {
                "license": "MIT",
                "license_expression": None,
                "classifiers": [],
            }
        }
        with patch("services.dependency_extraction.httpx.get", return_value=mock_resp):
            result = extractor._get_license_info("fastapi")
        assert result == "MIT"

    def test_get_license_info_from_classifier(self, extractor):
        """License extracted from classifier when license field is empty."""
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "info": {
                "license": "",
                "license_expression": None,
                "classifiers": [
                    "License :: OSI Approved :: Apache Software License",
                ],
            }
        }
        with patch("services.dependency_extraction.httpx.get", return_value=mock_resp):
            result = extractor._get_license_info("some-pkg")
        assert result == "Apache Software License"

    def test_get_outdated_packages(self, extractor):
        """Detect outdated packages where current < latest."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(
                name="old-pkg",
                version="1.0.0",
                ecosystem="pypi",
                current_version="1.0.0",
                latest_version="2.0.0",
            ),
            ExternalPackage(
                name="current-pkg",
                version="2.0.0",
                ecosystem="pypi",
                current_version="2.0.0",
                latest_version="2.0.0",
            ),
        ]
        result = extractor.get_outdated_packages(packages)
        assert len(result) == 1
        assert result[0].name == "old-pkg"

    def test_get_outdated_packages_all_current(self, extractor):
        """All current returns empty list."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(
                name="pkg",
                version="1.0.0",
                ecosystem="pypi",
                current_version="1.0.0",
                latest_version="1.0.0",
            ),
        ]
        result = extractor.get_outdated_packages(packages)
        assert result == []

    def test_is_more_specific_version(self, extractor):
        """Version specificity: == beats *, * beats nothing."""
        assert extractor._is_more_specific_version("==1.0.0", "*") is True
        assert extractor._is_more_specific_version("*", "==1.0.0") is False
        assert extractor._is_more_specific_version("*", "*") is True
        assert extractor._is_more_specific_version(">=1.0", ">=2.0") is False
        # == always wins over non-==
        assert extractor._is_more_specific_version("==1.0.0", ">=1.0.0") is True
        assert extractor._is_more_specific_version(">=1.0.0", "==1.0.0") is False

    def test_get_vulnerable_packages_excludes_low(self, extractor):
        """Packages with low severity (case-insensitive) are excluded from vulnerable list."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(name="vuln", version="1.0", ecosystem="pypi", severity="HIGH"),
            ExternalPackage(name="safe", version="1.0", ecosystem="pypi"),
            ExternalPackage(name="low_lower", version="1.0", ecosystem="pypi", severity="low"),
            ExternalPackage(name="low_upper", version="1.0", ecosystem="pypi", severity="LOW"),
            ExternalPackage(name="low_mixed", version="1.0", ecosystem="pypi", severity="Low"),
        ]
        result = extractor.get_vulnerable_packages(packages)
        assert len(result) == 1
        assert result[0].name == "vuln"

    def test_get_vulnerable_packages_includes_all_non_low(self, extractor):
        """CRITICAL, HIGH, and MEDIUM severities are all included."""
        from models.package_manager_models import ExternalPackage

        packages = [
            ExternalPackage(name="crit", version="1.0", ecosystem="pypi", severity="CRITICAL"),
            ExternalPackage(name="high", version="1.0", ecosystem="pypi", severity="HIGH"),
            ExternalPackage(name="med", version="1.0", ecosystem="pypi", severity="MEDIUM"),
        ]
        result = extractor.get_vulnerable_packages(packages)
        assert len(result) == 3
        names = {p.name for p in result}
        assert names == {"crit", "high", "med"}

    def test_multiple_manifest_files_in_same_repo(self, extractor, tmp_path):
        """When both requirements.txt and package.json exist, both are parsed."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask>=2.0\n")

        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"react": "^18.0.0"}}))

        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "flask" in names
        assert "react" in names

        flask_pkg = next(p for p in packages if p.name == "flask")
        assert flask_pkg.ecosystem == "pypi"

        react_pkg = next(p for p in packages if p.name == "react")
        assert react_pkg.ecosystem == "npm"

    def test_requirements_subdirectory(self, extractor, tmp_path):
        """Requirements files in requirements/ subdirectory are also parsed."""
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "dev.txt").write_text("pytest>=7.0\n")
        (reqs_dir / "prod.txt").write_text("gunicorn>=21.0\n")

        packages = extractor.extract_dependencies(tmp_path)
        names = [p.name for p in packages]
        assert "pytest" in names
        assert "gunicorn" in names


class TestSpecifierPreservesTheOperator:
    """`version` could not tell a PIN from a RANGE, and that difference is load-bearing.

    MEASURED 2026-08-29. `parse_pypi_requirement` captured the comparison operator in
    group(2) and returned only group(3), so `fastmcp==3.4.7` and `fastmcp>=3.4.7` BOTH
    arrived as `"3.4.7"`. An AA gate asking "is every manifest already pinned AT the
    target?" therefore could not answer, and abstained on a live drive.

    The fix ADDS `specifier` rather than changing `version`, and that choice is the
    important part: `osv_scanner` puts `version` RAW into the OSV query payload with no
    cleaning, so an operator there returns zero vulnerabilities SILENTLY. A security scan
    that cannot fail is the one thing worse than the bug being fixed.
    """

    def test_parse_pypi_parts_returns_the_whole_constraint(self, extractor):
        assert extractor.parse_pypi_parts("fastmcp==3.4.7") == ("fastmcp", "==3.4.7", "3.4.7")
        assert extractor.parse_pypi_parts("fastmcp>=2.3.4") == ("fastmcp", ">=2.3.4", "2.3.4")
        assert extractor.parse_pypi_parts("fastmcp") == ("fastmcp", None, None)

    def test_a_multi_clause_constraint_is_not_truncated_at_the_comma(self, extractor):
        """⛔ THE REGRESSION THIS NEARLY SHIPPED.

        The old version group `[^\\s;,]+` stops dead at the first comma, so keeping the operator
        naively yields `">=2.13.0"` for `">=2.13.0,<3.0.0"` — the upper bound silently gone.

        That truncation was HARMLESS while nothing consumed it: `SpecifierSet("2.13.0")` raises
        InvalidSpecifier and `constraint_allows` falls back to permissive-True. A truncated but
        VALID specifier is worse than an invalid one — it parses, so a constraint the manifest
        never contained gets trusted. `>=2.13.0` admits 3.0.0; the real constraint refuses it.
        """
        name, spec, version = extractor.parse_pypi_parts("fastmcp>=2.13.0,<3.0.0")
        assert (name, spec, version) == ("fastmcp", ">=2.13.0,<3.0.0", "2.13.0")

        from services.dependency_upgrade import constraint_allows

        assert constraint_allows(spec, "3.0.0") is False, "the upper bound must still bite"
        assert constraint_allows(spec, "2.14.2") is True
        # And the truncated form — what a naive fix produces — would have been WRONG here:
        assert constraint_allows(">=2.13.0", "3.0.0") is True

    def test_extras_and_environment_markers_do_not_leak_into_the_specifier(self, extractor):
        assert extractor.parse_pypi_parts("fastmcp[cli]>=1.0") == ("fastmcp", ">=1.0", "1.0")
        assert extractor.parse_pypi_parts('fastmcp>=1.0 ; python_version<"3.9"') == (
            "fastmcp",
            ">=1.0",
            "1.0",
        )

    def test_a_non_constraint_reference_yields_no_specifier(self, extractor):
        """A git/URL ref is not a comparison; claiming one would be inventing a constraint."""
        assert extractor.parse_pypi_parts("fastmcp@git+https://example/x") == (
            "fastmcp",
            None,
            None,
        )

    def test_parse_pypi_requirement_contract_is_unchanged(self, extractor):
        """NEGATIVE CONTROL: the existing two-tuple caller contract must not move."""
        assert extractor.parse_pypi_requirement("fastmcp==3.4.7") == ("fastmcp", "3.4.7")
        assert extractor.parse_pypi_requirement("package>=1.0.0") == ("package", "1.0.0")

    def test_requirements_txt_carries_the_specifier(self, extractor, tmp_path):
        (tmp_path / "requirements.txt").write_text("fastmcp==3.4.7\nsse-starlette>=2.3.4\n")
        by_name = {p.name: p for p in extractor.extract_dependencies(tmp_path)}
        assert by_name["fastmcp"].specifier == "==3.4.7"
        assert by_name["sse-starlette"].specifier == ">=2.3.4"

    def test_pyproject_carries_the_specifier(self, extractor, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n  "fastmcp==3.4.7",\n  "httpx>=0.27.0",\n]\n'
        )
        by_name = {p.name: p for p in extractor.extract_dependencies(tmp_path)}
        assert by_name["fastmcp"].specifier == "==3.4.7"
        assert by_name["httpx"].specifier == ">=0.27.0"

    def test_version_stays_bare_so_the_osv_query_keeps_working(self, extractor, tmp_path):
        """THE SAFETY PROPERTY. osv_scanner sends `pkg.version` unmodified to OSV.

        If an operator ever leaks into `version`, OSV matches nothing and every package
        reports clean — a silent scan failure, not an error. This test is the guard.
        """
        (tmp_path / "requirements.txt").write_text("fastmcp==3.4.7\nhttpx>=0.27.0\n")
        pkgs = extractor.extract_dependencies(tmp_path)
        # ⛔ NON-VACUITY FLOOR. Without it this guard passes against a parser that returns [],
        # i.e. the one test protecting the silent-CVE-scan property goes green having examined
        # NOTHING. A guard that cannot fail is the defect it exists to catch.
        assert len(pkgs) >= 2, f"examined {len(pkgs)} packages; the guard checked nothing"
        assert {p.name for p in pkgs} == {"fastmcp", "httpx"}
        for p in pkgs:
            assert p.version is not None
            for op in ("=", ">", "<", "!", "~"):
                assert op not in p.version, f"{p.name} version {p.version!r} leaked an operator"

    def test_a_pin_and_a_range_at_the_same_version_are_now_distinguishable(
        self, extractor, tmp_path
    ):
        """The whole point. Both are version "3.4.7"; only `specifier` separates them."""
        (tmp_path / "requirements.txt").write_text("pinned==3.4.7\nranged>=3.4.7\n")
        by_name = {p.name: p for p in extractor.extract_dependencies(tmp_path)}
        assert by_name["pinned"].version == by_name["ranged"].version == "3.4.7"
        assert by_name["pinned"].specifier == "==3.4.7"
        assert by_name["ranged"].specifier == ">=3.4.7"

    def test_the_manifest_that_found_it_is_recorded(self, extractor, tmp_path):
        """`source` was never set by these two parsers, so a caller could not say WHICH
        manifest a constraint came from."""
        (tmp_path / "requirements.txt").write_text("fastmcp==3.4.7\n")
        pkgs = extractor.extract_dependencies(tmp_path)
        assert {p.source for p in pkgs if p.name == "fastmcp"} == {"requirements.txt"}

    def test_dedup_collapses_manifests_so_disagreement_is_invisible(self, extractor, tmp_path):
        """⚠️ A LIMITATION, pinned deliberately so nobody designs against the wrong model.

        `extract_dependencies` dedupes by NAME across all manifests, so exactly one entry
        survives. Two manifests that DISAGREE — the case that distinguishes a real alignment
        diff from a no-op — cannot be seen in this result at all.

        Answering "does every manifest already pin X at the target?" therefore requires the
        pre-dedup, per-manifest constraints, NOT this endpoint's `packages[]`. Asserting it
        from here is how a range that merely PERMITS the target gets read as a pin AT it.
        """
        (tmp_path / "requirements.txt").write_text("fastmcp>=2.3.4\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n  "fastmcp==3.4.7",\n]\n'
        )
        entries = [p for p in extractor.extract_dependencies(tmp_path) if p.name == "fastmcp"]
        assert len(entries) == 1, "if this ever returns 2, the limitation is gone — update the gate"
        # With the specifier-aware tiebreak the PIN wins over the range, which is at least the
        # more informative survivor. Before the fix the winner was whichever parsed first.
        assert entries[0].specifier == "==3.4.7"


class TestConstraintForUsesTheSpecifier:
    def test_constraint_for_prefers_the_specifier(self):
        """`_constraint_for` feeds SpecifierSet(); a bare "3.4.7" is not a PEP 440 specifier."""
        from models.package_manager_models import ExternalPackage
        from services.dependency_upgrade import _constraint_for

        pkgs = [ExternalPackage(name="fastmcp", version="3.4.7", specifier="==3.4.7")]
        assert _constraint_for("fastmcp", pkgs) == "==3.4.7"

    def test_a_pinned_package_now_refuses_an_out_of_range_cve_fix(self):
        """⚠️ A DISCLOSED BEHAVIOUR CHANGE, not a side effect.

        Before: `_constraint_for` returned the bare "3.4.7". `SpecifierSet("3.4.7")` raises
        InvalidSpecifier, and `constraint_allows` falls back to permissive-True — so a CVE fix at
        3.4.9 was reported as ALLOWED by a constraint that pins 3.4.7. That was a false green.

        After: the constraint is "==3.4.7", which genuinely does not admit 3.4.9, so the fix is
        routed to the needs-a-constraint-change path instead of being silently applied.

        This is more honest and it IS a routing change: manifest-pinned pypi packages with a CVE
        fixed outside their pin now land in `skipped_needs_major` under the default
        `allow_major=false`, where they previously flowed through. Recorded here so the change is
        asserted rather than discovered.
        """
        from models.package_manager_models import ExternalPackage
        from services.dependency_upgrade import _constraint_for, constraint_allows

        pinned = [ExternalPackage(name="fastmcp", version="3.4.7", specifier="==3.4.7")]
        c = _constraint_for("fastmcp", pinned)
        assert c == "==3.4.7"
        assert constraint_allows(c, "3.4.9") is False, "a pin must not admit a later version"
        assert constraint_allows(c, "3.4.7") is True
        # The OLD value, and why it was a false green: unparsable -> permissive.
        assert constraint_allows("3.4.7", "3.4.9") is True

    def test_constraint_for_falls_back_for_lockfile_packages(self):
        """Lockfile parsers emit resolved concretes with no constraint — keep the old answer."""
        from models.package_manager_models import ExternalPackage
        from services.dependency_upgrade import _constraint_for

        pkgs = [ExternalPackage(name="fastmcp", version="3.4.7")]
        assert _constraint_for("fastmcp", pkgs) == "3.4.7"


class TestLockfilePrecedenceHidesManifestConstraints:
    """⚠️ THE ENDPOINT IS A RESOLVED VIEW, NOT A CONSTRAINT VIEW. Design against this.

    `extract_dependencies` parses a manifest ONLY for an ecosystem no lockfile already
    covered. `uv.lock` covers `pypi`, so on any repo carrying one, `pyproject.toml` and
    `requirements.txt` are NEVER PARSED — every package arrives as a resolved concrete with
    `specifier=None`.

    MEASURED 2026-08-29: `nonagenticai/enterprise_mcp_server` ships `uv.lock`, `pyproject.toml`
    AND `requirements.txt`. An AA gate tried to ask "does every manifest already pin fastmcp at
    3.4.7?" through this endpoint and could not — not because of the discarded operator (fixed
    in this PR), but because the manifests were never read at all.

    Adding `specifier` is still right — it fixes `_constraint_for`, revives the dead dedup
    tiebreak, and works on repos WITHOUT a lockfile. But it does NOT make this endpoint able to
    answer a constraint question on a lockfile repo, and no field added here would.

    Answering that needs manifests parsed REGARDLESS of lockfile coverage, exposed separately
    from the resolved `packages[]` (which CVE scanning correctly wants resolved).
    """

    def test_a_lockfile_suppresses_the_manifest_parsers_entirely(self, extractor, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n  "fastmcp==3.4.7",\n]\n'
        )
        (tmp_path / "requirements.txt").write_text("fastmcp==3.4.7\n")
        (tmp_path / "uv.lock").write_text('[[package]]\nname = "fastmcp"\nversion = "3.4.7"\n')
        pkgs = extractor.extract_dependencies(tmp_path)
        fastmcp = [p for p in pkgs if p.name == "fastmcp"]
        assert fastmcp, "the lockfile package should still be found"
        # The constraint is absent because no manifest was read — NOT because it was stripped.
        assert all(p.specifier is None for p in fastmcp), (
            "a lockfile repo yields no manifest constraints; if this ever fails, the "
            "precedence changed and an AA gate could start reading real specifiers here"
        )
        assert all(p.source != "pyproject.toml" for p in fastmcp)

    def test_without_a_lockfile_the_manifest_constraint_does_come_through(
        self, extractor, tmp_path
    ):
        """The positive control: the suppression above is precedence, not a broken parser."""
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = [\n  "fastmcp==3.4.7",\n]\n'
        )
        pkgs = extractor.extract_dependencies(tmp_path)
        fastmcp = [p for p in pkgs if p.name == "fastmcp"]
        assert fastmcp and fastmcp[0].specifier == "==3.4.7"
        assert fastmcp[0].source == "pyproject.toml"


def _write_package_lock(path: Path, packages: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"": {"name": "root"}} | {
        f"node_modules/{name}": {"version": version} for name, version in packages.items()
    }
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": body}))


class TestLockfilesAtAnyDepth:
    """A subdirectory lockfile (shipped widget, e2e tooling) is scanned, not ignored."""

    def test_subdirectory_lockfiles_are_found_and_test_dirs_marked_dev(self, extractor, tmp_path):
        (tmp_path / "uv.lock").write_text('[[package]]\nname = "pyjwt"\nversion = "2.15.1"\n')
        _write_package_lock(tmp_path / "widget" / "package-lock.json", {"preact": "10.27.2"})
        _write_package_lock(tmp_path / "e2e" / "package-lock.json", {"playwright": "1.56.1"})

        by_name = {p.name: p for p in extractor.extract_dependencies(tmp_path)}

        assert set(by_name) == {"pyjwt", "preact", "playwright"}
        assert by_name["preact"].ecosystem == "npm"
        assert by_name["preact"].is_dev is False
        assert by_name["preact"].source == "widget/package-lock.json"
        assert by_name["playwright"].is_dev is True
        assert by_name["playwright"].source == "e2e/package-lock.json"
        assert by_name["pyjwt"].source == "uv.lock"

    def test_installed_trees_are_not_searched(self, extractor, tmp_path):
        _write_package_lock(
            tmp_path / "widget" / "node_modules" / "dep" / "package-lock.json", {"evil": "1.0.0"}
        )
        _write_package_lock(tmp_path / ".venv" / "package-lock.json", {"hidden": "1.0.0"})
        assert extractor.extract_dependencies(tmp_path) == []

    def test_a_runtime_occurrence_outranks_a_dev_one(self, extractor, tmp_path):
        _write_package_lock(tmp_path / "e2e" / "package-lock.json", {"ws": "8.18.0"})
        _write_package_lock(tmp_path / "widget" / "package-lock.json", {"ws": "8.18.0"})
        [pkg] = extractor.extract_dependencies(tmp_path)
        assert pkg.is_dev is False
        assert pkg.source == "widget/package-lock.json"

    def test_two_versions_in_two_lockfiles_are_both_kept(self, extractor, tmp_path):
        _write_package_lock(tmp_path / "a" / "package-lock.json", {"ws": "7.5.10"})
        _write_package_lock(tmp_path / "b" / "package-lock.json", {"ws": "8.18.0"})
        versions = sorted(p.version for p in extractor.extract_dependencies(tmp_path))
        assert versions == ["7.5.10", "8.18.0"]

    def test_a_subdirectory_lockfile_does_not_suppress_the_root_manifest(self, extractor, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
        _write_package_lock(tmp_path / "widget" / "package-lock.json", {"preact": "10.27.2"})
        names = {p.name for p in extractor.extract_dependencies(tmp_path)}
        assert names == {"lodash", "preact"}


class TestManifestRangesKeepTheirSpecifier:
    """package.json / Cargo.toml strip the operator from ``version``; the
    constraint as written must survive in ``specifier`` so a range is never
    mistaken for an exact pin (and version-scoped at OSV)."""

    def test_package_json(self, extractor, tmp_path):
        f = tmp_path / "package.json"
        f.write_text('{"dependencies": {"lodash": "^4.17.0", "left-pad": "1.3.0"}}')
        by_name = {p.name: p for p in extractor._parse_package_json(f)}
        assert (by_name["lodash"].version, by_name["lodash"].specifier) == ("4.17.0", "^4.17.0")
        assert by_name["left-pad"].specifier == "1.3.0"

    def test_cargo_toml(self, extractor, tmp_path):
        f = tmp_path / "Cargo.toml"
        f.write_text('[dependencies]\nserde = "1.0.190"\ntime = "=0.3.30"\n')
        by_name = {p.name: p for p in extractor._parse_cargo_toml(f)}
        assert by_name["serde"].specifier == "1.0.190"
        assert by_name["time"].specifier == "=0.3.30"
