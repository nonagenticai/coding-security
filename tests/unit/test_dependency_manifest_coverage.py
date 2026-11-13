"""Fail-closed coverage of the dependency scan's manifest / lockfile set.

MEASURED 2026-11-05 (coverage audit): the scanner FETCHED Go, Maven/Gradle,
Composer, Gemfile, NuGet, yarn and pnpm manifests, but the extractor parsed only
PyPI, crates.io and npm. Everything else yielded zero packages, the analyzer
reported an empty dependency report, and the result read as CLEAN — a repo whose
only dependencies live in a pom.xml scored "0 vulnerabilities" with
``scan_degraded: false``.

These tests pin the two halves of the fix:
* a manifest/lockfile that could not be read (no parser, malformed, or over the
  size cap) DEGRADES the report and NAMES itself in ``degraded_reasons``;
* the lockfile formats have real parsers, so their packages reach the scanner
  (where an ecosystem the baked OSV DB does not cover lands as "unchecked",
  which is honestly degraded rather than clean).
"""

import json

import pytest

from models.container_models import ContainerInfo, ContainerStatus
from services.dependency_analyzer import ArchitectureDependencyAnalyzer
from services.dependency_extraction import (
    MAX_MANIFEST_CHARS,
    DependencyExtractor,
)
from services.scan_runner import _materialize_codebase

# ---------------------------------------------------------------------------
# 1. Fail-closed: what the extractor cannot read must not read clean
# ---------------------------------------------------------------------------


async def test_manifest_only_repo_degrades_and_names_the_manifest(tmp_path):
    """A repo holding ONLY an unparsed manifest is not a clean repo."""
    (tmp_path / "pom.xml").write_text("<project><dependencies/></project>")
    (tmp_path / "build.gradle").write_text("dependencies { implementation 'x:y:1.0' }")

    report = await ArchitectureDependencyAnalyzer(enable_cache=False).analyze(tmp_path, "pom-only")

    # The old behaviour: 0 packages, 0 vulnerabilities, scan_degraded False.
    assert report.scan_degraded is True
    assert report.degraded_reasons, "a degraded report must say WHY"
    reason = report.degraded_reasons[0]
    assert "unparsed dependency manifests" in reason
    assert "pom.xml" in reason
    assert "build.gradle" in reason
    assert report.summary.total_packages == 0


async def test_size_skipped_lockfile_degrades_instead_of_reading_clean(tmp_path):
    """An oversized lockfile is skipped — and that skip is reported."""
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps({"packages": [{"name": "monolog/monolog", "version": "2.9.1"}]})
        + " " * (MAX_MANIFEST_CHARS + 1)
    )

    extractor = DependencyExtractor()
    assert extractor.extract_dependencies(tmp_path) == []
    assert any(
        "composer.lock" in item and "exceeds" in item for item in extractor.unparsed_manifests
    )

    report = await ArchitectureDependencyAnalyzer(enable_cache=False).analyze(tmp_path, "oversized")
    assert report.scan_degraded is True
    assert any("composer.lock" in reason for reason in report.degraded_reasons)


def test_a_manifest_covered_by_its_lockfile_is_not_unparsed(tmp_path):
    """go.mod beside a parsed go.sum is redundant, not a gap (positive control)."""
    (tmp_path / "go.mod").write_text("module example.com/m\n")
    (tmp_path / "go.sum").write_text("example.com/dep v1.2.3 h1:abc=\n")

    extractor = DependencyExtractor()
    packages = extractor.extract_dependencies(tmp_path)

    assert [(p.name, p.version) for p in packages] == [("example.com/dep", "v1.2.3")]
    assert extractor.unparsed_manifests == []


def test_a_manifest_without_its_lockfile_is_unparsed(tmp_path):
    """go.mod WITHOUT go.sum cannot be resolved without running a build."""
    (tmp_path / "go.mod").write_text("module example.com/m\n")
    extractor = DependencyExtractor()
    assert extractor.extract_dependencies(tmp_path) == []
    assert extractor.unparsed_manifests == ["go.mod"]


def test_unparsed_manifests_are_reset_between_runs(tmp_path):
    """A reused extractor must not carry a previous repo's gaps forward."""
    (tmp_path / "pom.xml").write_text("<project/>")
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "package.json").write_text('{"dependencies": {"lodash": "4.17.21"}}')

    extractor = DependencyExtractor()
    extractor.extract_dependencies(tmp_path)
    assert extractor.unparsed_manifests == ["pom.xml"]
    extractor.extract_dependencies(clean)
    assert extractor.unparsed_manifests == []


async def test_without_unparsed_tracking_the_same_fixture_reads_clean(tmp_path, monkeypatch):
    """NEGATIVE CONTROL: this reproduces the PRE-FIX behaviour on the same input.

    With the unparsed tracking disabled (the state of the old extractor), the
    pom.xml-only repo yields 0 packages and is NOT degraded — so the degrade
    test above cannot be passing for some unrelated reason.
    """
    (tmp_path / "pom.xml").write_text("<project/>")
    monkeypatch.setattr(DependencyExtractor, "_UNPARSED_MANIFESTS", ())

    report = await ArchitectureDependencyAnalyzer(enable_cache=False).analyze(tmp_path, "pom-only")

    assert report.summary.total_packages == 0
    assert report.scan_degraded is False


# ---------------------------------------------------------------------------
# 1b. An EMPTY lockfile is not coverage — it must not hide a real manifest
# ---------------------------------------------------------------------------


def test_header_only_yarn_lock_does_not_suppress_package_json(tmp_path):
    """REGRESSION: a yarn.lock with no entries marked npm covered, hid the real
    package.json, and the repo scanned as 0 packages / clean."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n\n")

    extractor = DependencyExtractor()
    packages = extractor.extract_dependencies(tmp_path)

    assert [(p.name, p.version) for p in packages] == [("lodash", "4.17.21")]
    assert extractor.unparsed_manifests == []


def test_workspace_only_yarn_lock_does_not_suppress_package_json(tmp_path):
    """Same regression via berry: a workspace-only entry resolves to no package."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"preact": "10.27.2"}}))
    (tmp_path / "yarn.lock").write_text(
        '__metadata:\n  version: 8\n\n"my-app@workspace:.":\n  version: 0.0.0-use.local\n'
    )

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    assert [(p.name, p.version) for p in packages] == [("preact", "10.27.2")]


# ---------------------------------------------------------------------------
# 1c. Manifests are read at ANY depth (they were only read at the repo root)
# ---------------------------------------------------------------------------


def test_nested_requirements_are_read(tmp_path):
    """A repo whose deps live only in backend/requirements.txt is not empty."""
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "requirements.txt").write_text("fastapi==0.115.0\n")

    extractor = DependencyExtractor()
    packages = extractor.extract_dependencies(tmp_path)

    assert [(p.name, p.version) for p in packages] == [("fastapi", "0.115.0")]
    assert extractor.unparsed_manifests == []


def test_nested_package_json_is_read(tmp_path):
    """A frontend/package.json-only repo is not empty."""
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.2.0"}})
    )

    extractor = DependencyExtractor()
    packages = extractor.extract_dependencies(tmp_path)

    assert [(p.name, p.version) for p in packages] == [("react", "18.2.0")]
    assert extractor.unparsed_manifests == []


def test_a_nested_lockfile_covers_only_its_own_directory(tmp_path):
    """frontend/package-lock.json resolves frontend/package.json, not the root one."""
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.0"}}))
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.2.0"}})
    )
    (tmp_path / "frontend" / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/react": {"version": "18.2.0", "dev": False}}})
    )

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    by_name = {p.name: p for p in packages}

    assert by_name["react"].version == "18.2.0"
    assert by_name["react"].source == "frontend/package-lock.json"
    assert by_name["express"].version == "4.18.0"  # the ROOT manifest still parsed


def test_a_nested_manifest_under_a_test_dir_is_dev(tmp_path):
    """The any-depth walk marks test tooling as dev, like the lockfile walk."""
    (tmp_path / "e2e").mkdir()
    (tmp_path / "e2e" / "package.json").write_text(
        json.dumps({"dependencies": {"playwright": "1.56.1"}})
    )

    [package] = DependencyExtractor().extract_dependencies(tmp_path)
    assert (package.name, package.is_dev) == ("playwright", True)


# ---------------------------------------------------------------------------
# 1d. A manifest must never duplicate a package a lockfile RESOLVED
# ---------------------------------------------------------------------------


def test_a_root_lockfile_wins_over_a_nested_manifest_duplicate(tmp_path):
    """REGRESSION: react 18.3.1 (lock) + ^18.2.0 (nested manifest) => ONE row.

    The manifest row carries a RANGE, so the lookup treats it as unpinned and
    reports every advisory for the name — a phantom CVE on a version that is
    not installed.
    """
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/react": {"version": "18.3.1"}}})
    )
    app = tmp_path / "packages" / "app"
    app.mkdir(parents=True)
    (app / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.2.0"}}))

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    react = [p for p in packages if p.name == "react"]

    assert len(react) == 1, f"phantom duplicate rows: {[(p.name, p.version) for p in react]}"
    assert react[0].version == "18.3.1"
    assert react[0].specifier is None  # the RESOLVED row, not the constraint


async def test_a_phantom_manifest_row_cannot_report_a_cve(tmp_path, monkeypatch):
    """End-to-end: the fixture OSV DB affects <18.3.0; the phantom 18.2.0 row
    (unpinned range => "report everything") would raise a CVE for a version that
    is not installed. With one resolved row there is nothing to report."""
    record = {
        "id": "GHSA-phantom-row-test",
        "summary": "affects react < 18.3.0",
        "details": "",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "react"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "18.3.0"}]}
                ],
            }
        ],
        "references": [],
        "published": "",
        "modified": "",
    }
    db = tmp_path / "osv-db"
    (db / "npm").mkdir(parents=True)
    (db / "npm" / "react.json").write_text(json.dumps([record]))
    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(db))

    repo = tmp_path / "repo"
    app = repo / "packages" / "app"
    app.mkdir(parents=True)
    (repo / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/react": {"version": "18.3.1"}}})
    )
    (app / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.2.0"}}))

    report = await ArchitectureDependencyAnalyzer(enable_cache=False).analyze(repo, "app")

    assert [p.version for p in report.packages if p.name == "react"] == ["18.3.1"]
    assert report.vulnerabilities == [], "a phantom unpinned row reported a CVE"
    assert report.scan_degraded is False

    # NON-VACUITY: the fixture DB DOES report for the exact phantom row the old
    # merge emitted (range specifier => unpinned => "report everything"), so the
    # zero above is the merge's doing, not an inert fixture.
    from models.package_manager_models import ExternalPackage
    from services.dependency_visualization import DependencyVulnerabilityScanner

    phantom = ExternalPackage(name="react", version="18.2.0", specifier="^18.2.0", ecosystem="npm")
    scanner = DependencyVulnerabilityScanner(timeout=5, enable_cache=False)
    assert await scanner.scan_vulnerabilities([phantom]), "fixture DB is not discriminating"


def test_a_cargo_workspace_manifest_cannot_duplicate_a_locked_crate(tmp_path):
    """Root Cargo.lock serde 1.0.190 + crates/x `serde = "1"` => ONE serde."""
    (tmp_path / "Cargo.lock").write_text(
        "[[package]]\n"
        'name = "serde"\n'
        'version = "1.0.190"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        "[[package]]\n"
        'name = "my-workspace"\n'
        'version = "0.1.0"\n'
    )
    member = tmp_path / "crates" / "x"
    member.mkdir(parents=True)
    (member / "Cargo.toml").write_text('[dependencies]\nserde = "1"\n')

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    serde = [p for p in packages if p.name == "serde"]

    assert len(serde) == 1, f"phantom duplicate rows: {[(p.name, p.version) for p in serde]}"
    assert serde[0].version == "1.0.190"


def test_a_nested_requirements_cannot_duplicate_a_locked_package(tmp_path):
    """Root uv.lock fastapi 0.115.2 + backend/requirements.txt >=0.100.0 => ONE."""
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "fastapi"\nversion = "0.115.2"\n')
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "requirements.txt").write_text("fastapi>=0.100.0\n")

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    fastapi = [p for p in packages if p.name == "fastapi"]

    assert len(fastapi) == 1, f"phantom duplicate rows: {[(p.name, p.version) for p in fastapi]}"
    assert fastapi[0].version == "0.115.2"


def test_the_duplicate_check_uses_the_lookup_normalisation(tmp_path):
    """`zope.interface` (lock) and `zope-interface` (manifest) are ONE package."""
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "zope.interface"\nversion = "6.0"\n')
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "requirements.txt").write_text("zope-interface>=5.0\n")

    packages = DependencyExtractor().extract_dependencies(tmp_path)
    assert len(packages) == 1
    assert (packages[0].name, packages[0].version) == ("zope.interface", "6.0")


def test_a_manifest_package_no_lockfile_resolved_is_still_added(tmp_path):
    """POSITIVE CONTROL: only names a lockfile RESOLVED are skipped."""
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/react": {"version": "18.3.1"}}})
    )
    app = tmp_path / "packages" / "app"
    app.mkdir(parents=True)
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18.2.0", "left-pad": "1.3.0"}})
    )

    by_name = {p.name: p for p in DependencyExtractor().extract_dependencies(tmp_path)}

    assert by_name["react"].version == "18.3.1"
    assert by_name["left-pad"].version == "1.3.0"  # manifest-only name survives


# ---------------------------------------------------------------------------
# 2. The lockfile formats parse (resolved name/version, existing ecosystems)
# ---------------------------------------------------------------------------


def _extract(tmp_path, filename, content):
    (tmp_path / filename).write_text(content)
    return {
        (p.name, p.version, p.ecosystem)
        for p in DependencyExtractor().extract_dependencies(tmp_path)
    }


def test_go_sum(tmp_path):
    content = (
        "github.com/foo/bar v1.2.3 h1:abc=\n"
        "github.com/foo/bar v1.2.3/go.mod h1:def=\n"
        "gopkg.in/yaml.v3 v3.0.1 h1:xyz=\n"
        "github.com/baz/qux v2.0.0+incompatible h1:qqq=\n"
    )
    assert _extract(tmp_path, "go.sum", content) == {
        ("github.com/foo/bar", "v1.2.3", "go"),
        ("gopkg.in/yaml.v3", "v3.0.1", "go"),
        ("github.com/baz/qux", "v2.0.0+incompatible", "go"),
    }


def test_yarn_lock_v1(tmp_path):
    content = (
        "# yarn lockfile v1\n\n"
        '"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n'
        '  version "7.12.11"\n'
        '  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.11.tgz"\n\n'
        "lodash@^4.17.20, lodash@^4.17.21:\n"
        '  version "4.17.21"\n'
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
    )
    assert _extract(tmp_path, "yarn.lock", content) == {
        ("@babel/code-frame", "7.12.11", "npm"),
        ("lodash", "4.17.21", "npm"),
    }


def test_yarn_lock_berry_excludes_workspaces_and_nested_version_deps(tmp_path):
    content = (
        "__metadata:\n"
        "  version: 8\n"
        "  cacheKey: 10c0\n\n"
        '"lodash@npm:^4.17.21":\n'
        "  version: 4.17.21\n"
        '  resolution: "lodash@npm:4.17.21"\n\n'
        '"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":\n'
        "  version: 1.1.0\n"
        '  resolution: "@scope/pkg@npm:1.1.0"\n'
        "  dependencies:\n"
        "    version: ^9.0.0\n\n"
        '"my-app@workspace:.":\n'
        "  version: 0.0.0-use.local\n"
    )
    assert _extract(tmp_path, "yarn.lock", content) == {
        ("lodash", "4.17.21", "npm"),
        ("@scope/pkg", "1.1.0", "npm"),
    }


def test_pnpm_lock(tmp_path):
    content = (
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  lodash@4.17.21:\n"
        "    resolution: {integrity: sha512-abc}\n"
        "  '@scope/pkg@1.2.3(peer@2.0.0)':\n"
        "    resolution: {integrity: sha512-def}\n"
        "    dev: true\n"
    )
    assert _extract(tmp_path, "pnpm-lock.yaml", content) == {
        ("lodash", "4.17.21", "npm"),
        ("@scope/pkg", "1.2.3", "npm"),
    }


def test_pnpm_lock_v5_key_shape(tmp_path):
    content = (
        "lockfileVersion: 5.4\n"
        "packages:\n"
        "  /lodash/4.17.21:\n"
        "    resolution: {integrity: sha512-abc}\n"
        "  /@scope/pkg/1.2.3_peer@2.0.0:\n"
        "    resolution: {integrity: sha512-def}\n"
    )
    assert _extract(tmp_path, "pnpm-lock.yaml", content) == {
        ("lodash", "4.17.21", "npm"),
        ("@scope/pkg", "1.2.3", "npm"),
    }


def test_composer_lock(tmp_path):
    content = json.dumps(
        {
            "packages": [{"name": "monolog/monolog", "version": "2.9.1"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.6.0"}],
        }
    )
    assert _extract(tmp_path, "composer.lock", content) == {
        ("monolog/monolog", "2.9.1", "packagist"),
        ("phpunit/phpunit", "9.6.0", "packagist"),
    }


def test_gemfile_lock_only_reads_gem_specs_and_strips_platform(tmp_path):
    content = (
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    actioncable (7.1.3)\n"
        "      actionpack (= 7.1.3)\n"
        "    nokogiri (1.16.2-x86_64-linux)\n\n"
        "PATH\n"
        "  remote: .\n"
        "  specs:\n"
        "    myapp (0.1.0)\n\n"
        "DEPENDENCIES\n"
        "  actioncable (~> 7.1)\n"
    )
    assert _extract(tmp_path, "Gemfile.lock", content) == {
        ("actioncable", "7.1.3", "rubygems"),
        ("nokogiri", "1.16.2", "rubygems"),
    }


def test_packages_lock_json_skips_project_refs(tmp_path):
    content = json.dumps(
        {
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
                    "MyApp": {"type": "Project", "resolved": "1.0.0"},
                }
            },
        }
    )
    assert _extract(tmp_path, "packages.lock.json", content) == {
        ("Newtonsoft.Json", "13.0.3", "nuget"),
    }


def test_nuget_packages_config(tmp_path):
    content = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<packages>\n"
        '  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />\n'
        "  <package id='Serilog' version='2.12.0' />\n"
        "</packages>\n"
    )
    assert _extract(tmp_path, "packages.config", content) == {
        ("Newtonsoft.Json", "13.0.3", "nuget"),
        ("Serilog", "2.12.0", "nuget"),
    }


# ---------------------------------------------------------------------------
# 3. A parsed but UNCOVERED ecosystem is degraded by the lookup, not clean
# ---------------------------------------------------------------------------


async def test_go_packages_from_go_sum_land_as_unchecked_degraded(tmp_path, monkeypatch):
    """The baked OSV DB has PyPI+crates.io+npm only — a Go repo must not read clean."""
    db = tmp_path / "osv-db"
    (db / "PyPI").mkdir(parents=True)
    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(db))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.sum").write_text("github.com/gin-gonic/gin v1.9.1 h1:abc=\n")

    report = await ArchitectureDependencyAnalyzer(enable_cache=False).analyze(repo, "go-repo")

    assert report.summary.total_packages == 1
    assert report.scan_degraded is True
    joined = " ".join(report.degraded_reasons)
    assert "vulnerability lookup incomplete" in joined
    # The EXACT reason, not the two-letter ecosystem id (which also occurs in
    # package names): names the uncovered ecosystem and an unchecked package.
    assert "no offline OSV DB for ecosystem 'go'" in joined
    assert "github.com/gin-gonic/gin" in joined


# ---------------------------------------------------------------------------
# 4. A size-skipped DEPENDENCY MANIFEST degrades the container fetch
# ---------------------------------------------------------------------------


def _remote_container():
    """A ContainerInfo whose codebase_path is NOT a local dir → triggers a fetch."""
    return ContainerInfo(
        container_name="victim",
        api_endpoint="http://localhost:8080",
        codebase_path="/workspace",
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _reader_client(find_stdout, payload):
    """A fake coding-containers whose bulk read returns *payload* as JSON stdout."""

    class _Resp:
        status_code = 200
        content = b"{}"

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    class _Client:
        is_closed = False

        async def aclose(self):
            return None

        async def request(self, _method, _url, **kwargs):
            return await self.post(_url, **kwargs)

        async def post(self, _url, **kwargs):
            cmd = kwargs["json"]["command"]
            if cmd[0] == "find":
                return _Resp({"stdout": find_stdout})
            return _Resp({"stdout": json.dumps(payload)})

    return _Client()


@pytest.mark.asyncio
async def test_skipped_dependency_manifest_degrades_the_fetch(monkeypatch):
    """A lockfile the container could not hand over means the scan saw less."""
    client = _reader_client(
        "/workspace/go.sum\n/workspace/app.py\n",
        {"files": {"/workspace/app.py": "x = 1"}, "skipped": ["/workspace/go.sum"]},
    )
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)

    result = await _materialize_codebase(_remote_container(), "victim", "tenant-1")
    try:
        assert result.incomplete is True
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_skipped_source_file_is_still_a_documented_size_bound(monkeypatch):
    """NEGATIVE CONTROL: an oversized non-manifest file is not a coverage gap."""
    client = _reader_client(
        "/workspace/app.py\n/workspace/huge.bin\n",
        {"files": {"/workspace/app.py": "x = 1"}, "skipped": ["/workspace/huge.bin"]},
    )
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)

    result = await _materialize_codebase(_remote_container(), "victim", "tenant-1")
    try:
        assert result.incomplete is False
    finally:
        if result.temp_dir:
            import shutil

            shutil.rmtree(result.temp_dir, ignore_errors=True)
