"""Dependency Extraction and Parsing Module.

Handles dependency discovery, parsing, and basic processing including
deduplication and version normalization.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path

import httpx
import yaml
from packaging.version import InvalidVersion, Version

from models.package_manager_models import ExternalPackage, normalize_package_name

logger = logging.getLogger(__name__)

# uv.lock / poetry.lock are TOML with one ``[[package]]`` block per dependency;
# ``name`` is always immediately followed by ``version``. This pairs the two so we
# read the RESOLVED concrete version (mirrors the same pattern in
# ``services/package_upgrade/strategies.py``). Cargo.lock is parsed as TOML by
# :func:`cargo_lock_packages` instead, because only a package's ``source`` tells a
# crates.io crate from a workspace/path/git crate of the same name; this pairing is
# its fallback for a Cargo.lock that is not valid TOML.
_LOCK_NAME_VERSION_RE = re.compile(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')


CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)


#: Largest manifest / lockfile parsed (a real Cargo.lock / uv.lock is < 1 MiB).
MAX_MANIFEST_CHARS = 4 * 1024 * 1024
#: ``[extras]`` of a PEP 508 requirement. The body excludes ``[`` so a run of unclosed
#: ``[`` fails in O(1) at each one; the previous ``\[.*?\]`` rescanned the rest of the
#: line from every ``[`` (quadratic on ``[`` x N).
EXTRAS_RE = re.compile(r"\[[^\[\]\n]*+\]")


def load_bounded_toml(content: str, what: str) -> dict:
    """``tomllib.loads`` of a tenant-supplied manifest under a size cap.

    Raises ``ValueError`` (naming *what*) for anything that is not a parseable
    TOML document within :data:`MAX_MANIFEST_CHARS` (a nesting too deep for
    tomllib's recursive parser is its ``RecursionError``, reported the same way).
    """
    if len(content) > MAX_MANIFEST_CHARS:
        raise ValueError(f"{what} exceeds {MAX_MANIFEST_CHARS} characters")
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ValueError(f"{what} is not valid TOML: {exc}") from exc


def read_bounded_text(filepath: Path, what: str) -> str:
    """``read_text`` of a tenant-supplied manifest under :data:`MAX_MANIFEST_CHARS`.

    Raises ``ValueError`` (naming *what*) when the decoded text is over the cap,
    so an oversized lockfile is REPORTED like any other unparseable one instead
    of silently shrinking the scanned package set while the scan reads clean.
    """
    text = filepath.read_text(encoding="utf-8")
    if len(text) > MAX_MANIFEST_CHARS:
        raise ValueError(f"{what} exceeds {MAX_MANIFEST_CHARS} characters")
    return text


def _short_error(exc: Exception, limit: int = 160) -> str:
    """One-line, bounded rendering of a parse failure for the degraded report."""
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= limit else text[: limit - 3] + "..."


def cargo_lock_packages(content: str, what: str = "Cargo.lock") -> list[dict]:
    """The ``[[package]]`` tables of a Cargo.lock text, shape-checked.

    Raises ``ValueError`` on a lockfile that is not TOML, exceeds the size
    cap, or whose ``package`` is not an array of tables (callers record
    it like the other parse failures). Entries without a string ``name`` and
    ``version`` are dropped.
    """
    data = load_bounded_toml(content, what)
    packages = data.get("package", [])
    if not isinstance(packages, list):
        raise ValueError(f"{what} 'package' is not an array of tables")
    return [
        pkg
        for pkg in packages
        if isinstance(pkg, dict)
        and isinstance(pkg.get("name"), str)
        and isinstance(pkg.get("version"), str)
        and pkg["name"]
        and pkg["version"]
    ]


def cargo_lock_registry_packages(content: str) -> list[tuple[str, str]]:
    """``(name, version)`` of every crates.io package in a Cargo.lock text.

    Raises ``ValueError`` like :func:`cargo_lock_packages`.
    """
    return [
        (pkg["name"], pkg["version"])
        for pkg in cargo_lock_packages(content)
        if pkg.get("source") in CRATES_IO_SOURCES
    ]


#: Directories never searched for lockfiles: installed/vendored trees, not the
#: repo's own dependency declarations (mirrors the remote ``find`` exclusions in
#: ``services.scan_runner.fetch_manifests_to_tempdir``).
_LOCKFILE_SKIP_DIRS = frozenset(
    {"node_modules", ".venv", "venv", "vendor", "__pycache__", "site-packages"}
)

#: A lockfile under a directory with one of these names resolves TEST tooling
#: (e2e runners, browser drivers), so its packages are marked ``is_dev``.
_TEST_DIR_NAMES = frozenset({"e2e", "tests", "test", "spec", "cypress", "playwright"})

#: A ``requirements/`` directory holds PyPI constraint files of any base name
#: (``requirements/base.txt``), which the ``requirements*.txt`` pattern misses.
_REQUIREMENTS_SUBDIR = "requirements"


def _walk_files(repo: Path) -> Iterator[Path]:
    """Every file under ``repo``, pruning installed/hidden trees.

    Prunes :data:`_LOCKFILE_SKIP_DIRS` and hidden directories, so an installed
    ``node_modules``/``.venv`` tree is never descended into.
    """
    for dirpath, dirnames, files in os.walk(repo):
        dirnames[:] = [
            d for d in dirnames if d not in _LOCKFILE_SKIP_DIRS and not d.startswith(".")
        ]
        for name in files:
            yield Path(dirpath) / name


def find_lockfiles(repo: Path, filenames: set[str]) -> list[Path]:
    """Every file named in ``filenames`` under ``repo``, at any depth, sorted."""
    return sorted(path for path in _walk_files(repo) if path.name in filenames)


def find_manifest_files(repo: Path, patterns: set[str]) -> list[Path]:
    """Every file whose NAME matches one of ``patterns`` under ``repo``, sorted.

    ``patterns`` are shell globs (``*.csproj``) as well as exact names, so the
    manifests with no parser of their own are found by the same walk the
    lockfiles use.
    """
    return sorted(
        path
        for path in _walk_files(repo)
        if any(fnmatch.fnmatchcase(path.name, pattern) for pattern in patterns)
    )


class DependencyExtractor:
    """Handles dependency extraction and parsing from various package managers."""

    # Lockfiles give RESOLVED concrete versions for the FULL dependency tree,
    # including transitive deps. They are strongly preferred over manifests
    # (pyproject/requirements), whose entries are version CONSTRAINTS and omit
    # transitive deps entirely — so a real CVE in a transitive or loosely-pinned
    # package (e.g. aiohttp pulled in transitively, or a commented/optional dep)
    # is invisible to a manifest-only scan. One lockfile per ecosystem makes the
    # manifest redundant, so we skip the manifest for any ecosystem a lockfile
    # already covered.
    _LOCKFILE_PARSERS: tuple[tuple[str, str, str], ...] = (
        ("uv.lock", "_parse_uv_or_poetry_lock", "pypi"),
        ("poetry.lock", "_parse_uv_or_poetry_lock", "pypi"),
        ("Pipfile.lock", "_parse_pipfile_lock", "pypi"),
        ("package-lock.json", "_parse_package_lock_json", "npm"),
        ("yarn.lock", "_parse_yarn_lock", "npm"),
        ("pnpm-lock.yaml", "_parse_pnpm_lock", "npm"),
        ("Cargo.lock", "_parse_cargo_lock", "crates.io"),
        ("go.sum", "_parse_go_sum", "go"),
        ("composer.lock", "_parse_composer_lock", "packagist"),
        ("Gemfile.lock", "_parse_gemfile_lock", "rubygems"),
        ("packages.lock.json", "_parse_nuget_lock", "nuget"),
        ("packages.config", "_parse_nuget_packages_config", "nuget"),
    )
    _MANIFEST_PARSERS: tuple[tuple[str, str, str], ...] = (
        ("requirements*.txt", "_parse_requirements_txt", "pypi"),
        ("pyproject.toml", "_parse_pyproject_toml", "pypi"),
        ("package.json", "_parse_package_json", "npm"),
        ("Cargo.toml", "_parse_cargo_toml", "crates.io"),
    )
    #: Manifests this extractor has NO parser for. Resolving them needs a build
    #: (Maven/Gradle), the ecosystem's package manager (composer/go/gem/NuGet),
    #: or they are a constraint-only view of a lockfile read at RESOLVED
    #: versions. They must never be ignored: a repo whose dependencies live only
    #: in one of these produced "0 packages / 0 vulnerabilities" and read as
    #: CLEAN. Each is reported (``unparsed_manifests``) so the caller can mark
    #: the scan degraded instead of passing a repo it never checked.
    #: A manifest in a directory that ALSO holds a parsed lockfile of the same
    #: ecosystem is redundant, not unparsed (see ``_LOCKFILE_PARSERS``).
    _UNPARSED_MANIFESTS: tuple[tuple[str, str], ...] = (
        ("pom.xml", "maven"),
        ("build.gradle", "maven"),
        ("build.gradle.kts", "maven"),
        ("go.mod", "go"),
        ("Gemfile", "rubygems"),
        ("composer.json", "packagist"),
        ("Pipfile", "pypi"),
        ("*.csproj", "nuget"),
    )

    def __init__(self) -> None:
        """Initialize the dependency extractor."""
        #: Manifests the LAST ``extract_dependencies`` could not resolve, as
        #: ``<path>`` or ``<path> (<why>)``. Empty means every manifest found
        #: was parsed. Reset per call, so a reuse never reports a stale gap.
        self.unparsed_manifests: list[str] = []
        logger.info("DependencyExtractor initialized")

    def extract_dependencies(self, repo: Path) -> list[ExternalPackage]:
        """Extract dependencies from a repository path.

        Prefers lockfiles (resolved versions + transitive deps) over manifests
        (constraints, direct-only). BOTH are read at ANY depth (a shipped
        ``widget/package-lock.json`` is as installed as the root ``uv.lock``);
        those under a test directory (``e2e/``, ``tests/`` ...) are marked
        ``is_dev``. A manifest is skipped only where a lockfile in the SAME
        directory RESOLVED packages for its ecosystem.

        Every manifest/lockfile the extractor could NOT read (no parser for the
        format, malformed content, over the size cap) is recorded in
        ``unparsed_manifests``. An empty package list therefore never means
        "nothing to check" on its own — the caller must read that list before
        treating a scan as clean.
        """
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo}")

        logger.info("Starting dependency extraction for repository at: %s", repo)
        packages: list[ExternalPackage] = []
        self.unparsed_manifests = []
        # Lockfile packages are RESOLVED: one entry per (ecosystem, name, version),
        # so a lock that resolves two versions of one name (smallvec 0.6.14 and
        # 1.6.0) keeps both — each is installed and each is scanned.
        resolved: dict[tuple[str, str, str], ExternalPackage] = {}
        # (directory, ecosystem) pairs a PARSED lockfile RESOLVED packages for,
        # so a manifest beside it is redundant rather than unparsed.
        covered_dirs: set[tuple[str, str]] = set()

        # 1. Lockfiles first — authoritative, resolved, full tree, any depth.
        lockfile_parsers = {name: (parser, eco) for name, parser, eco in self._LOCKFILE_PARSERS}
        for filepath in find_lockfiles(repo, set(lockfile_parsers)):
            parser_name, ecosystem = lockfile_parsers[filepath.name]
            rel = filepath.relative_to(repo)
            test_dir = any(part.lower() in _TEST_DIR_NAMES for part in rel.parent.parts)
            try:
                parsed = getattr(self, parser_name)(filepath)
            except (OSError, ValueError, RuntimeError) as e:
                # A lockfile we fetched but cannot read is a COVERAGE GAP, not a
                # clean scan: its packages were never checked. Report it.
                logger.warning("Failed to parse lockfile %s: %s", rel, e)
                self.unparsed_manifests.append(f"{rel.as_posix()} ({_short_error(e)})")
                continue
            if parsed:
                # ONLY a lockfile that RESOLVED something covers its ecosystem.
                # An empty one (a header-only yarn.lock, a workspace-only berry
                # lock) must not suppress a real package.json beside it: that
                # suppressed the manifest, yielded 0 packages and read CLEAN —
                # the fail-open this scan exists to prevent.
                covered_dirs.add((rel.parent.as_posix(), ecosystem))
            for pkg in parsed:
                update: dict[str, object] = {"source": pkg.source or rel.as_posix()}
                if test_dir:
                    update["is_dev"] = True
                pkg = pkg.model_copy(update=update)
                key = (ecosystem, pkg.name.lower(), pkg.version or "")
                existing = resolved.get(key)
                # Same resolved package in two lockfiles: a runtime occurrence
                # outranks a dev-only one.
                if existing is None or (existing.is_dev and not pkg.is_dev):
                    resolved[key] = pkg
            logger.info("Found %d resolved packages in lockfile %s", len(parsed), rel)

        # 2. Manifests at ANY depth (mirroring the lockfile walk), constraint-
        #    based, and only where no lockfile in the SAME directory resolved
        #    that ecosystem. Reading the repo ROOT only was a fail-open: a
        #    monorepo whose dependencies live in backend/requirements.txt or
        #    frontend/package.json reported 0 packages and read as CLEAN.
        manifest_patterns = {pattern for pattern, _p, _e in self._MANIFEST_PARSERS} | {"*.txt"}
        for filepath in find_manifest_files(repo, manifest_patterns):
            rel = filepath.relative_to(repo)
            matched = self._manifest_parser(filepath.name)
            if matched is None:
                # ``requirements/*.txt`` (any depth): the extractor's original
                # PyPI layout; every other ``*.txt`` is unrelated.
                if filepath.suffix != ".txt" or filepath.parent.name != _REQUIREMENTS_SUBDIR:
                    continue
                matched = ("_parse_requirements_txt", "pypi")
            parser_name, ecosystem = matched
            if (rel.parent.as_posix(), ecosystem) in covered_dirs:
                continue
            test_dir = any(part.lower() in _TEST_DIR_NAMES for part in rel.parent.parts)
            try:
                parsed = getattr(self, parser_name)(filepath)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Failed to parse %s: %s", rel, e)
                self.unparsed_manifests.append(f"{rel.as_posix()} ({_short_error(e)})")
                continue
            if test_dir:
                parsed = [pkg.model_copy(update={"is_dev": True}) for pkg in parsed]
            packages.extend(parsed)
            logger.info("Found %d packages in %s", len(parsed), rel)

        # 3. Manifests with no parser of their own — recorded, never guessed.
        unparsed_patterns = {pattern for pattern, _eco in self._UNPARSED_MANIFESTS}
        for filepath in find_manifest_files(repo, unparsed_patterns):
            rel = filepath.relative_to(repo)
            ecosystem = self._unparsed_manifest_ecosystem(filepath.name)
            if ecosystem is None or (rel.parent.as_posix(), ecosystem) in covered_dirs:
                continue
            logger.warning("No parser for dependency manifest %s", rel)
            self.unparsed_manifests.append(rel.as_posix())

        # Sorted + deduped: the report line must name the SAME gaps every run.
        self.unparsed_manifests = sorted(dict.fromkeys(self.unparsed_manifests))

        if not packages and not resolved:
            logger.warning("No dependencies found in repository at %s", repo)
            return []

        # A manifest must NEVER add a second row for a package a lockfile
        # already RESOLVED for the same (ecosystem, normalised name). Manifests
        # DO share an ecosystem with a lockfile now that both are read at any
        # depth: a root ``package-lock.json`` resolving react 18.3.1 plus
        # ``packages/app/package.json`` declaring ``"react": "^18.2.0"`` used to
        # emit a PHANTOM react 18.2.0. That row carries a RANGE, so the lookup
        # treats it as unpinned and reports every advisory for the name — a CVE
        # for a version that is not installed. Only a name no lockfile resolved
        # may come from a manifest (keeping its unpinned semantics).
        resolved_names = {
            ((pkg.ecosystem or "").lower(), normalize_package_name(pkg.name))
            for pkg in resolved.values()
        }
        manifest_only = [
            pkg
            for pkg in packages
            if ((pkg.ecosystem or "").lower(), normalize_package_name(pkg.name))
            not in resolved_names
        ]
        unique_packages = list(resolved.values()) + self.deduplicate_packages(manifest_only)
        logger.info("Found %d unique packages after deduplication", len(unique_packages))
        return unique_packages

    @classmethod
    def _unparsed_manifest_ecosystem(cls, name: str) -> str | None:
        """The ecosystem of a manifest this extractor has no parser for."""
        for pattern, ecosystem in cls._UNPARSED_MANIFESTS:
            if fnmatch.fnmatchcase(name, pattern):
                return ecosystem
        return None

    @classmethod
    def _manifest_parser(cls, name: str) -> tuple[str, str] | None:
        """``(parser method, ecosystem)`` for a manifest filename, if one exists."""
        for pattern, parser_name, ecosystem in cls._MANIFEST_PARSERS:
            if fnmatch.fnmatchcase(name, pattern):
                return parser_name, ecosystem
        return None

    # --- Lockfile parsers (RESOLVED concrete versions, full tree) ---

    def _parse_uv_or_poetry_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse uv.lock / poetry.lock — concrete versions for every resolved
        package (direct AND transitive)."""
        content = filepath.read_text(encoding="utf-8")
        return [
            ExternalPackage(name=name, version=version, ecosystem="pypi")
            for name, version in _LOCK_NAME_VERSION_RE.findall(content)
        ]

    def _parse_cargo_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse Cargo.lock — concrete versions for the full crates.io tree.

        Only ``[[package]]`` entries whose ``source`` is the crates.io registry are
        crates.io packages. Workspace members and path deps carry no ``source`` and
        git deps a ``git+`` one; looking those up in the crates.io advisory DB
        would report a local crate that happens to share a published crate's name
        (``time``, ``log`` ...) as that crate's CVEs.

        A lockfile that is not TOML (merge-conflict markers, a truncated file) is
        still read, with the name/version pairing used before the TOML parse:
        scanning it with local crates included beats reporting no packages, which
        reads as a clean repo.
        """
        content = filepath.read_text(encoding="utf-8")
        try:
            pairs = cargo_lock_registry_packages(content)
        except ValueError as exc:
            logger.warning(
                "Cargo.lock %s is not TOML (%s); reading name/version pairs", filepath, exc
            )
            pairs = _LOCK_NAME_VERSION_RE.findall(content)
        return [
            ExternalPackage(name=name, version=version, ecosystem="crates.io")
            for name, version in pairs
        ]

    def _parse_pipfile_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse Pipfile.lock (JSON) — resolved versions in default + develop."""
        packages: list[ExternalPackage] = []
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for name, meta in (data.get(section) or {}).items():
                version = (meta.get("version") or "").lstrip("=") if isinstance(meta, dict) else ""
                if name:
                    packages.append(
                        ExternalPackage(
                            name=name,
                            version=version or "*",
                            ecosystem="pypi",
                            is_dev=section == "develop",
                        )
                    )
        return packages

    def _parse_package_lock_json(self, filepath: Path) -> list[ExternalPackage]:
        """Parse package-lock.json (npm v2/v3) — resolved versions, full tree."""
        packages: list[ExternalPackage] = []
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        # npm v2/v3: "packages" keyed by install path ("" = root, skip it).
        pkgs = data.get("packages")
        if isinstance(pkgs, dict):
            for path, meta in pkgs.items():
                if not path or not isinstance(meta, dict):
                    continue
                name = meta.get("name") or path.split("node_modules/")[-1]
                version = meta.get("version")
                if name and version:
                    packages.append(
                        ExternalPackage(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            is_dev=bool(meta.get("dev")),
                        )
                    )
            return packages
        # npm v1 fallback: flat "dependencies".
        for name, meta in (data.get("dependencies") or {}).items():
            version = meta.get("version") if isinstance(meta, dict) else None
            if name and version:
                packages.append(ExternalPackage(name=name, version=version, ecosystem="npm"))
        return packages

    # --- Remaining ecosystems' lockfiles ---

    #: ``version "1.2.3"`` (yarn v1) / ``version: 1.2.3`` (yarn berry).
    _YARN_VERSION_RE = re.compile(r'^version:?\s+"?([^"\s]+)"?\s*$')
    #: Descriptors that resolve to something other than a registry package.
    _YARN_NON_REGISTRY = ("workspace:", "patch:", "file:", "link:", "portal:")

    @classmethod
    def _yarn_descriptor_name(cls, descriptor: str) -> str | None:
        """Package name of a yarn descriptor (``name@range`` / ``@scope/name@range``)."""
        descriptor = descriptor.strip().strip("\"'")
        if not descriptor or descriptor.startswith("__"):
            return None
        if any(marker in descriptor for marker in cls._YARN_NON_REGISTRY):
            return None
        # A scoped name starts with '@', so its version separator is the SECOND '@'.
        index = descriptor.find("@", 1 if descriptor.startswith("@") else 0)
        return descriptor[:index] if index > 0 else None

    def _parse_yarn_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse yarn.lock — v1 (``version "x"``) and berry (``version: x``).

        An entry header is a non-indented list of descriptors ending in ':';
        ``version`` sits at exactly two spaces under it. A dependency block
        nested deeper (a package literally named ``version``) is not an entry
        version, hence the indent check.
        """
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        name: str | None = None
        have_version = False
        for raw in read_bounded_text(filepath, "yarn.lock").splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if indent == 0:
                header = raw.strip()
                if header.endswith(":"):
                    header = header[:-1]
                name, have_version = None, False
                for descriptor in header.split(","):
                    name = self._yarn_descriptor_name(descriptor)
                    if name:
                        break
                continue
            if name is None or have_version or indent != 2:
                continue
            match = self._YARN_VERSION_RE.match(raw.strip())
            if not match:
                continue
            have_version = True
            version = match.group(1)
            if (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append(ExternalPackage(name=name, version=version, ecosystem="npm"))
        return packages

    #: pnpm v6+/v9 key: ``/lodash@4.17.21`` or ``@scope/pkg@1.0.0(peer@2.0.0)``.
    _PNPM_KEY_RE = re.compile(r"^/?(?P<name>@[^/@]+/[^/@]+|[^/@]+)@(?P<version>[^()]+)(?:\(.*\))?$")
    #: pnpm v5 key: ``/lodash/4.17.21`` or ``/@scope/pkg/1.0.0_peer@2.0.0``.
    _PNPM_KEY_V5_RE = re.compile(r"^/(?P<name>@[^/]+/[^/]+|[^/]+)/(?P<version>[^_]+)(?:_.*)?$")

    @classmethod
    def _pnpm_key(cls, key: str) -> tuple[str, str] | None:
        """``(name, version)`` of a pnpm ``packages`` key (peer suffix stripped)."""
        for pattern in (cls._PNPM_KEY_RE, cls._PNPM_KEY_V5_RE):
            match = pattern.match(key)
            if match:
                return match.group("name"), match.group("version")
        return None

    def _parse_pnpm_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse pnpm-lock.yaml — the resolved ``packages`` map (all versions)."""
        try:
            data = yaml.safe_load(read_bounded_text(filepath, "pnpm-lock.yaml"))
        except yaml.YAMLError as exc:
            raise ValueError(f"pnpm-lock.yaml is not valid YAML: {exc}") from exc
        except RecursionError as exc:
            raise ValueError("pnpm-lock.yaml is nested too deeply to parse") from exc
        if not isinstance(data, dict):
            raise ValueError("pnpm-lock.yaml is not a YAML mapping")
        # v9 also emits a 'snapshots' map; 'packages' is present in every version
        # we support, with 'snapshots' used only as a fallback.
        entries = data.get("packages")
        if not isinstance(entries, dict):
            entries = data.get("snapshots")
        if not isinstance(entries, dict):
            raise ValueError("pnpm-lock.yaml has no 'packages' mapping")
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        for key, meta in entries.items():
            if not isinstance(key, str):
                continue
            parsed = self._pnpm_key(key)
            if parsed is None:
                continue
            name, version = parsed
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append(
                ExternalPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_dev=bool(isinstance(meta, dict) and meta.get("dev")),
                )
            )
        return packages

    def _parse_go_sum(self, filepath: Path) -> list[ExternalPackage]:
        """Parse go.sum — every module/version the build resolved.

        A line is ``<module> <version> <h1:hash>``; the ``<version>/go.mod``
        companion carries only the go.mod checksum and is skipped. go.sum is a
        SUPERSET of go.mod's direct requirements (all transitive modules at
        their resolved versions), so it is the Go lockfile.
        """
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        for line in read_bounded_text(filepath, "go.sum").splitlines():
            parts = line.split()
            if len(parts) != 3 or not parts[2].startswith("h1:"):
                continue
            module, version = parts[0], parts[1]
            if not module or not version.startswith("v") or version.endswith("/go.mod"):
                continue
            if (module, version) in seen:
                continue
            seen.add((module, version))
            packages.append(ExternalPackage(name=module, version=version, ecosystem="go"))
        return packages

    def _parse_composer_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse composer.lock (JSON) — resolved ``packages`` + ``packages-dev``."""
        data = json.loads(read_bounded_text(filepath, "composer.lock"))
        packages: list[ExternalPackage] = []
        for section in ("packages", "packages-dev"):
            entries = data.get(section) or []
            if not isinstance(entries, list):
                raise ValueError(f"composer.lock '{section}' is not an array")
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name, version = entry.get("name"), entry.get("version")
                if not (isinstance(name, str) and name and isinstance(version, str) and version):
                    continue
                packages.append(
                    ExternalPackage(
                        name=name,
                        version=version,
                        ecosystem="packagist",
                        is_dev=section == "packages-dev",
                    )
                )
        return packages

    #: One resolved spec line of a Bundler ``GEM`` section: ``    rack (2.2.8)``.
    _GEMFILE_SPEC_RE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$")
    #: Platform suffix Bundler appends to a precompiled gem version
    #: (``nokogiri (1.16.2-x86_64-linux)``); NOT part of the gem's version.
    _RUBY_PLATFORM_SUFFIX_RE = re.compile(
        r"-(?:java|jruby|rbx|"
        r"(?:x86_64|x86|x64|arm64|aarch64|arm|universal|powerpc|sparc|mswin32|mswin64|mingw32"
        r"|mingw-ucrt)-[a-z0-9_-]+)\Z"
    )

    def _parse_gemfile_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse Gemfile.lock — resolved gems of every ``GEM`` section.

        Only ``GEM`` specs are rubygems packages; ``PATH``/``GIT`` specs are
        local or git checkouts of the repo itself and must not inherit a
        published gem's advisories.
        """
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        section = ""
        for raw in read_bounded_text(filepath, "Gemfile.lock").splitlines():
            if not raw.strip():
                continue
            if not raw[0].isspace():
                section = raw.strip()
                continue
            if section != "GEM":
                continue
            match = self._GEMFILE_SPEC_RE.match(raw)
            if not match:
                continue
            name = match.group(1)
            version = self._RUBY_PLATFORM_SUFFIX_RE.sub("", match.group(2).strip())
            if not version or (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append(ExternalPackage(name=name, version=version, ecosystem="rubygems"))
        return packages

    def _parse_nuget_lock(self, filepath: Path) -> list[ExternalPackage]:
        """Parse packages.lock.json — the ``resolved`` version per target framework.

        ``type: Project`` entries are the repo's own projects, not NuGet
        packages: looking one up would report a local assembly's name as a
        published package's CVEs.
        """
        data = json.loads(read_bounded_text(filepath, "packages.lock.json"))
        dependencies = data.get("dependencies")
        if not isinstance(dependencies, dict):
            raise ValueError("packages.lock.json has no 'dependencies' mapping")
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        for target in dependencies.values():
            if not isinstance(target, dict):
                continue
            for name, meta in target.items():
                if not isinstance(meta, dict):
                    continue
                kind = meta.get("type")
                if isinstance(kind, str) and kind.lower() == "project":
                    continue
                version = meta.get("resolved")
                if not (isinstance(name, str) and name and isinstance(version, str) and version):
                    continue
                if (name, version) in seen:
                    continue
                seen.add((name, version))
                packages.append(ExternalPackage(name=name, version=version, ecosystem="nuget"))
        return packages

    #: A packages.config ``<package ...>`` start tag, with its flat attributes.
    _PACKAGES_CONFIG_TAG_RE = re.compile(r"<package\b([^>]*)>", re.IGNORECASE)
    _XML_ATTR_RE = re.compile(r"""\b(id|version)\s*=\s*("[^"]*"|'[^']*')""", re.IGNORECASE)

    def _parse_nuget_packages_config(self, filepath: Path) -> list[ExternalPackage]:
        """Parse packages.config (a flat ``<package id= version= />`` list).

        Read with a tag/attribute scan rather than an XML parser on purpose:
        the file is tenant content and has no nesting to honour, while an XML
        parser would put entity expansion on the scan path (ElementTree is
        flagged B314 for exactly that reason).
        """
        content = read_bounded_text(filepath, "packages.config")
        if "<packages" not in content.lower():
            raise ValueError("packages.config has no <packages> root element")
        packages: list[ExternalPackage] = []
        seen: set[tuple[str, str]] = set()
        for tag in self._PACKAGES_CONFIG_TAG_RE.finditer(content):
            attrs = {
                match.group(1).lower(): match.group(2)[1:-1]
                for match in self._XML_ATTR_RE.finditer(tag.group(1))
            }
            name, version = attrs.get("id", "").strip(), attrs.get("version", "").strip()
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append(ExternalPackage(name=name, version=version, ecosystem="nuget"))
        return packages

    def deduplicate_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Remove duplicate packages, keeping the most specific version.

        ⚠️ ONE ENTRY PER PACKAGE NAME SURVIVES, across ALL manifests. A caller therefore
        cannot ask "does every manifest that mentions X already pin it at the target?" from
        this result — the disagreeing manifest has been collapsed away. That question needs
        the per-manifest constraints (see `source` + `specifier` on the pre-dedup list), and
        answering it from the deduped list is how a range that merely PERMITS the target gets
        mistaken for a pin AT it.
        """
        package_map: dict[str, ExternalPackage] = {}

        for package in packages:
            name = package.name.lower()
            if name not in package_map:
                package_map[name] = package
            else:
                existing = package_map[name]
                # Compare the SPECIFIER, not the bare version. `_is_more_specific_version`
                # decides on `"==" in version` — and the manifest parsers strip the operator,
                # so that test could never be true and the tiebreak was dead code: the
                # first-parsed manifest simply won. With `specifier` it does what it says.
                if self._is_more_specific_version(
                    package.specifier or package.version or package.current_version or "*",
                    existing.specifier or existing.version or existing.current_version or "*",
                ):
                    package_map[name] = package

        return list(package_map.values())

    def _is_more_specific_version(self, version1: str, version2: str) -> bool:
        """Check if version1 is more specific than version2."""
        if "==" in version2 and "==" not in version1:
            return False
        if "==" in version1 and "==" not in version2:
            return True
        if version2 == "*":
            return True
        if version1 == "*":
            return False
        return False

    def enrich_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Enrich packages with latest version and license information."""
        enriched = []
        for package in packages:
            enriched_package = ExternalPackage(
                name=package.name,
                version=package.version or package.current_version or "*",
                license=self._get_license_info(package.name) or "Unknown",
                ecosystem=package.ecosystem,
                description=package.description,
                current_version=package.current_version,
                latest_version=self._get_latest_version(package.name),
                severity=package.severity,
            )
            enriched.append(enriched_package)
        return enriched

    def _get_latest_version(self, package_name: str) -> str | None:
        """Get the latest version of a package from PyPI."""
        try:
            response = httpx.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                version = data.get("info", {}).get("version")
                return version if isinstance(version, str) else None
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return None

    def _get_license_info(self, package_name: str) -> str | None:
        """Get license information for a package."""
        try:
            response = httpx.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                info = data.get("info", {})
                license_info = info.get("license") or info.get("license_expression") or ""
                classifiers = info.get("classifiers", [])
                for classifier in classifiers:
                    if classifier.startswith("License ::"):
                        license_from_classifier = classifier.split("::")[-1].strip()
                        if license_from_classifier and license_from_classifier != "OSI Approved":
                            return str(license_from_classifier)
                return license_info if license_info else None
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return None

    # A requirement is `name` + the WHOLE constraint, not name + one clause. The old regex
    # ended the version at `[^\s;,]+`, which stops dead at the first comma — see parse_pypi_parts.
    _PYPI_NAME_REST_RE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*(.*)$")

    def parse_pypi_parts(self, requirement: str) -> tuple[str | None, str | None, str | None]:
        r"""Split a PyPI requirement into ``(name, specifier, version)``.

        ``specifier`` is the constraint AS WRITTEN and COMPLETE — ``">=2.13.0,<3.0.0"``, not just
        its first clause. ``version`` is the bare first version, operator-free.

        ⛔ WHY THE WHOLE CONSTRAINT, NOT ONE CLAUSE (measured 2026-08-29). The operator used to be
        captured and discarded, so `==3.4.7` and `>=3.4.7` were indistinguishable. The obvious fix
        — keep group(2) and group(3) — reintroduces the bug one level down, because the version
        group `[^\s;,]+` TERMINATES AT THE COMMA:

            "fastmcp>=2.13.0,<3.0.0"  ->  ">=2.13.0"          the upper bound is GONE

        That truncation was harmless while nothing consumed it: `SpecifierSet("2.13.0")` raises
        InvalidSpecifier and `constraint_allows` falls back to permissive-True. Feeding it a
        truncated but VALID specifier is worse than feeding it an invalid one — it parses, so a
        constraint the manifest never contained gets TRUSTED, and `>=2.13.0` admits 3.0.0 where the
        real constraint refuses it. Making dead code reachable is a behaviour change.

        ``version`` deliberately stays operator-free: ``osv_scanner`` puts it raw into the OSV
        query payload, where an operator returns zero vulnerabilities silently.
        """
        requirement = EXTRAS_RE.sub("", requirement or "")
        # Drop the environment marker: `foo>=1.0 ; python_version < "3.9"` constrains nothing here.
        requirement = requirement.split(";", 1)[0].strip()
        match = self._PYPI_NAME_REST_RE.match(requirement)
        if not match:
            return None, None, None
        name = match.group(1)
        rest = (match.group(2) or "").replace(" ", "")
        if not rest:
            return name, None, None
        # Anything that is not a comparison is not a constraint we can read (a URL, an @ ref).
        if not re.match(r"^[><=!~]", rest):
            return name, None, None
        first = re.match(r"^[><=!~]+\s*([^\s,;]+)", rest)
        return name, rest, (first.group(1) if first else None)

    def parse_pypi_requirement(self, requirement: str) -> tuple[str | None, str | None]:
        """Parse a PyPI requirement string to extract name and version.

        Contract unchanged: the version is returned WITHOUT its operator. Use
        ``parse_pypi_parts`` when the operator matters.
        """
        name, _specifier, version = self.parse_pypi_parts(requirement)
        return name, version

    def clean_version_for_osv(self, version: str) -> str | None:
        """Clean version string for OSV API compatibility."""
        version = version.replace("==", "").replace(">=", "").replace("<=", "")
        version = version.replace("~=", "").replace("!=", "").replace(">", "").replace("<", "")
        version = version.strip()
        if version == "*" or not version:
            return None
        try:
            Version(version)
            return version
        except InvalidVersion:
            return None

    def get_outdated_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Get packages whose ``latest_version`` is greater than the current one.

        Compared as PEP 440 versions, never as strings. A package whose current
        version is not a concrete version (``*``, a range, unparseable) cannot be
        judged and is skipped.
        """
        outdated = []
        for package in packages:
            if not package.latest_version:
                continue
            current_raw = package.current_version or package.version or "*"
            current = self.clean_version_for_osv(current_raw)
            if not current:
                continue
            try:
                if Version(current) < Version(package.latest_version):
                    outdated.append(package)
            except InvalidVersion:
                logger.warning(
                    "outdated: unparseable version for %s (current=%r latest=%r)",
                    package.name,
                    current_raw,
                    package.latest_version,
                )
        return outdated

    def get_vulnerable_packages(self, packages: list[ExternalPackage]) -> list[ExternalPackage]:
        """Get packages with known vulnerabilities."""
        return [pkg for pkg in packages if pkg.severity and pkg.severity.lower() != "low"]

    # --- Direct parsers (no plugin architecture) ---

    def _parse_requirements_txt(self, filepath: Path) -> list[ExternalPackage]:
        """Parse requirements.txt file."""
        packages = []
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                name, specifier, version = self.parse_pypi_parts(line)
                if name:
                    packages.append(
                        ExternalPackage(
                            name=name,
                            version=version or "*",
                            specifier=specifier,
                            source=filepath.name,
                            ecosystem="pypi",
                        )
                    )
        return packages

    def _parse_pyproject_toml(self, filepath: Path) -> list[ExternalPackage]:
        """Parse pyproject.toml dependencies section."""
        packages = []
        content = filepath.read_text(encoding="utf-8")

        # Extract [project.dependencies] section
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[project]":
                continue
            if stripped.startswith("dependencies") and "=" in stripped:
                in_deps = True
                # Handle inline array start
                if "[" in stripped:
                    continue
                continue
            if in_deps:
                if stripped == "]":
                    in_deps = False
                    continue
                # Parse dependency string like "fastapi>=0.115.0"
                dep = stripped.strip('", ')
                if dep:
                    name, specifier, version = self.parse_pypi_parts(dep)
                    if name:
                        packages.append(
                            ExternalPackage(
                                name=name,
                                version=version or "*",
                                specifier=specifier,
                                source=filepath.name,
                                ecosystem="pypi",
                            )
                        )

        return packages

    def _parse_package_json(self, filepath: Path) -> list[ExternalPackage]:
        """Parse package.json dependencies."""
        packages = []
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)

        for deps_key in ("dependencies", "devDependencies"):
            deps = data.get(deps_key, {})
            for name, version in deps.items():
                clean_version = re.sub(r"^[\^~>=<]+", "", version).split()[0]
                packages.append(
                    ExternalPackage(
                        name=name,
                        version=clean_version,
                        # As written: "^4.17.0" is a range, "4.17.0" a pin.
                        specifier=version,
                        ecosystem="npm",
                        is_dev=deps_key == "devDependencies",
                    )
                )
        return packages

    def _parse_cargo_toml(self, filepath: Path) -> list[ExternalPackage]:
        """Parse Cargo.toml dependencies."""
        packages = []
        content = filepath.read_text(encoding="utf-8")
        in_deps = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "[dependencies]" or stripped == "[dev-dependencies]":
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in stripped:
                parts = stripped.split("=", 1)
                name = parts[0].strip()
                version = parts[1].strip().strip('"').strip("'")
                if name:
                    packages.append(
                        ExternalPackage(
                            name=name,
                            version=version or "*",
                            # As written: a bare Cargo version is a caret range.
                            specifier=version or None,
                            ecosystem="crates.io",
                        )
                    )

        return packages
