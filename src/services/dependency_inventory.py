"""Direct + resolved dependencies of one repo checkout, per ecosystem (PyPI, crates.io).

Pure parsing over a local copy of the repo's manifests (the route fetches them
with the same manifest fetch the dependency scan uses). Sources:

* PyPI direct: ``pyproject.toml`` ``[project].dependencies`` (+ optional
  dependencies), ``[dependency-groups]`` and ``[tool.uv].dev-dependencies``
  (dev), ``requirements*.txt`` (``requirements-dev``/``-test`` = dev).
* PyPI resolved: ``uv.lock`` / ``poetry.lock`` registry packages (the project
  itself and path/git/url sources are not PyPI packages and are excluded).
* crates.io direct: ``Cargo.toml`` ``[dependencies]``, ``[dev-dependencies]`` /
  ``[build-dependencies]`` (dev), ``[workspace.dependencies]``,
  ``[target.*.*dependencies]``. Path/git deps are listed with their specifier.
* crates.io resolved: ``Cargo.lock`` crates.io-registry packages (workspace
  members and path/git crates are not registry packages and are excluded).

``direct`` on a resolved entry is decided per VERSION, not per name: a PyPI
version is direct when it satisfies a manifest requirement of that name; a
crate version is direct when one of the repo's own crates in ``Cargo.lock``
(no ``source``) depends on exactly that version. A lockfile resolving two
versions of one name therefore marks only the one the manifest asked for.

Every manifest is tenant content: a file that is too large, not TOML (incl.
nested too deep for tomllib), or has a section of the wrong type is reported in ``errors``
(``<file>: ...``) and skipped; it never fails the other files or the route.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from models.dependency_inventory_models import DependencyEntry, EcosystemDependencies
from services import dependency_extraction as _extraction
from services.dependency_extraction import (
    CRATES_IO_SOURCES,
    cargo_lock_packages,
    load_bounded_toml,
)

_SKIP_PARTS = {"node_modules", "__pycache__", "venv", "target"}
#: PEP 503 name separators; also splits a requirements file stem into tokens.
_SEPARATORS_RE = re.compile(r"[-_.]+")
#: requirements-<token>.txt names whose deps are dev-only (whole tokens, so
#: requirements-docker.txt is NOT dev).
_DEV_REQUIREMENT_TOKENS = {"dev", "test", "tests", "testing", "lint", "docs", "doc", "ci"}


class ManifestError(ValueError):
    """A manifest/lockfile section does not have the type its format defines."""


def _norm_pypi(name: str) -> str:
    return _SEPARATORS_RE.sub("-", name.strip().lower())


def _norm_crate(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        parts = path.relative_to(root).parts
        if any(p.startswith(".") or p in _SKIP_PARTS for p in parts[:-1]):
            continue
        if path.is_file():
            out.append(path)
    return out


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _load(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"unreadable ({exc})") from exc
    return load_bounded_toml(content, "file")


def _table(container: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    """``container[key]`` when it is a table; {} when absent; ManifestError otherwise."""
    value = container.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ManifestError(f"{where} is not a table")
    return value


def _array(container: dict[str, Any], key: str, where: str) -> list[Any]:
    """``container[key]`` when it is an array; [] when absent; ManifestError otherwise."""
    value = container.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ManifestError(f"{where} is not an array")
    return value


def _pypi_req(raw: Any, source: str, dev: bool, where: str) -> DependencyEntry | None:
    if not isinstance(raw, str):
        raise ManifestError(f"{where} holds a non-string requirement")
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        return None
    spec = str(req.specifier) or None
    if req.url:
        spec = f"@ {req.url}"
    return DependencyEntry(name=req.name, specifier=spec, direct=True, dev=dev, source_file=source)


def _pyproject_direct(path: Path, source: str) -> list[DependencyEntry]:
    data = _load(path)
    out: list[DependencyEntry] = []

    def add(reqs: list[Any], dev: bool, where: str) -> None:
        for raw in reqs:
            if entry := _pypi_req(raw, source, dev, where):
                out.append(entry)

    project = _table(data, "project", "[project]")
    add(_array(project, "dependencies", "[project].dependencies"), False, "[project].dependencies")
    extras = _table(project, "optional-dependencies", "[project.optional-dependencies]")
    for extra in extras:
        where = f"[project.optional-dependencies].{extra}"
        add(_array(extras, extra, where), False, where)
    groups = _table(data, "dependency-groups", "[dependency-groups]")
    for group in groups:
        where = f"[dependency-groups].{group}"
        # {include-group = "..."} tables are references, not requirements.
        add([r for r in _array(groups, group, where) if not isinstance(r, dict)], True, where)
    uv = _table(_table(data, "tool", "[tool]"), "uv", "[tool.uv]")
    where = "[tool.uv].dev-dependencies"
    add(_array(uv, "dev-dependencies", where), True, where)
    return out


def _requirements_direct(path: Path, source: str) -> list[DependencyEntry]:
    tokens = set(_SEPARATORS_RE.split(path.stem.lower()))
    dev = bool(tokens & _DEV_REQUIREMENT_TOKENS)
    out: list[DependencyEntry] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > _extraction.MAX_MANIFEST_CHARS:
        raise ManifestError(f"exceeds {_extraction.MAX_MANIFEST_CHARS} characters")
    for line in text.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        if entry := _pypi_req(line, source, dev, "requirement"):
            out.append(entry)
    return out


def _pypi_lock(path: Path) -> list[tuple[str, str]]:
    data = _load(path)
    out: list[tuple[str, str]] = []
    for pkg in _array(data, "package", "[[package]]"):
        if not isinstance(pkg, dict):
            raise ManifestError("[[package]] holds a non-table entry")
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
            continue
        # Only registry packages are PyPI packages (same rule as Cargo.lock): uv
        # marks them `source = { registry = ... }`; poetry omits `source` for PyPI
        # and uses type "legacy" for another index. The project itself, path,
        # git and url sources are not, and must not inherit a PyPI name's CVEs.
        src = pkg.get("source")
        if src is not None and not (
            isinstance(src, dict) and ("registry" in src or src.get("type") == "legacy")
        ):
            continue
        out.append((name, version))
    return out


def _cargo_dep_spec(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if value.get("workspace") is True:
            return "workspace = true"
        for key in ("version", "path", "git"):
            if isinstance(value.get(key), str) and value[key]:
                return f"{key} = {value[key]}" if key != "version" else value[key]
    return None


_CARGO_DEP_TABLES = (
    ("dependencies", False),
    ("dev-dependencies", True),
    ("build-dependencies", True),
)


def _cargo_direct(path: Path, source: str) -> tuple[list[DependencyEntry], str | None]:
    """Direct deps declared by one Cargo.toml, and its ``[package].name`` (if any)."""
    data = _load(path)
    tables: list[tuple[dict[str, Any], bool, str]] = [
        (_table(data, key, f"[{key}]"), dev, f"[{key}]") for key, dev in _CARGO_DEP_TABLES
    ]
    workspace = _table(data, "workspace", "[workspace]")
    tables.append(
        (_table(workspace, "dependencies", "[workspace.dependencies]"), False, "[workspace]")
    )
    targets = _table(data, "target", "[target]")
    for cfg in targets:
        target = _table(targets, cfg, f"[target.{cfg}]")
        for key, dev in _CARGO_DEP_TABLES:
            where = f"[target.{cfg}.{key}]"
            tables.append((_table(target, key, where), dev, where))
    out: list[DependencyEntry] = []
    for table, dev, where in tables:
        for key, value in table.items():
            if not isinstance(value, str | dict):
                raise ManifestError(f"{where}.{key} is neither a version string nor a table")
            renamed = value.get("package") if isinstance(value, dict) else None
            name = renamed if isinstance(renamed, str) and renamed else key
            out.append(
                DependencyEntry(
                    name=name,
                    specifier=_cargo_dep_spec(value),
                    direct=True,
                    dev=dev,
                    source_file=source,
                )
            )
    package_name = _table(data, "package", "[package]").get("name")
    return out, package_name if isinstance(package_name, str) else None


def _cargo_lock(
    content: str, members: set[str]
) -> tuple[list[tuple[str, str]], set[tuple[str, str]]]:
    """``(registry packages, direct (name, version) edges)`` of one Cargo.lock.

    The direct edges are the ``dependencies`` of the repo's own crates (lock
    packages without ``source`` whose name is a ``[package].name`` of the repo;
    every source-less package when the repo declares none). An edge naming no
    version (``"serde"``) means the lock resolves that name once. A lock listing
    none of the repo's crates has no edges: nothing in it is marked direct.
    """
    packages = cargo_lock_packages(content, "file")
    registry = [(p["name"], p["version"]) for p in packages if p.get("source") in CRATES_IO_SOURCES]
    versions: dict[str, list[str]] = {}
    for name, version in registry:
        versions.setdefault(_norm_crate(name), []).append(version)
    local = [p for p in packages if "source" not in p]
    if members:
        local = [p for p in local if _norm_crate(p["name"]) in members]
    edges: set[tuple[str, str]] = set()
    for pkg in local:
        deps = pkg.get("dependencies", [])
        if not isinstance(deps, list):
            raise ManifestError(f"[[package]] {pkg['name']} dependencies is not an array")
        for dep in deps:
            if not isinstance(dep, str) or not dep.split():
                raise ManifestError(f"[[package]] {pkg['name']} holds a malformed dependency")
            parts = dep.split()
            name = _norm_crate(parts[0])
            if len(parts) > 1:
                edges.add((name, parts[1]))
            elif len(versions.get(name, [])) == 1:
                edges.add((name, versions[name][0]))
    return registry, edges


def _pypi_spec_matches(specifier: str | None, version: str) -> bool:
    """Whether *version* satisfies a manifest requirement's specifier.

    No specifier, a URL requirement, or a specifier/version packaging cannot
    read all match: the name is then the only evidence there is.
    """
    if not specifier or specifier.startswith("@"):
        return True
    try:
        return SpecifierSet(specifier).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return True


def _parse_file(errors: list[str], source: str, parse: Callable[[], Any], default: Any) -> Any:
    """Run one file's parser; any failure is that file's error entry, never the route's."""
    try:
        return parse()
    except (OSError, ValueError) as exc:  # tenant content: one bad file must not sink the rest
        errors.append(f"{source}: {exc or type(exc).__name__}")
        return default


def build_inventory(
    root: Path, ecosystems: set[str] | set[Literal["pypi", "crates.io"]]
) -> tuple[list[EcosystemDependencies], list[str]]:
    """Per-ecosystem direct + resolved lists for the repo copy at *root*."""
    errors: list[str] = []
    files = _files(root)
    result: list[EcosystemDependencies] = []

    if "pypi" in ecosystems:
        eco = EcosystemDependencies(ecosystem="pypi")
        resolved: list[tuple[str, str, str]] = []
        for path in files:
            source = _rel(root, path)
            if path.name == "pyproject.toml":
                eco.manifest_files.append(source)
                eco.direct.extend(
                    _parse_file(errors, source, lambda: _pyproject_direct(path, source), [])
                )
            elif (
                path.name.startswith("requirements")
                and path.suffix == ".txt"
                or (path.suffix == ".txt" and path.parent.name == "requirements")
            ):
                eco.manifest_files.append(source)
                eco.direct.extend(
                    _parse_file(errors, source, lambda: _requirements_direct(path, source), [])
                )
            elif path.name in ("uv.lock", "poetry.lock"):
                eco.lock_files.append(source)
                pkgs = _parse_file(errors, source, lambda: _pypi_lock(path), [])
                resolved.extend((n, v, source) for n, v in pkgs)
        declared: dict[str, list[DependencyEntry]] = {}
        for entry in eco.direct:
            declared.setdefault(_norm_pypi(entry.name), []).append(entry)
        seen: set[tuple[str, str]] = set()
        for name, version, source in resolved:
            key = (_norm_pypi(name), version)
            if key in seen:
                continue
            seen.add(key)
            matching = [
                e for e in declared.get(key[0], []) if _pypi_spec_matches(e.specifier, version)
            ]
            eco.resolved.append(
                DependencyEntry(
                    name=name,
                    version=version,
                    purl=f"pkg:pypi/{key[0]}@{version}",
                    direct=bool(matching),
                    dev=bool(matching) and all(e.dev for e in matching),
                    source_file=source,
                )
            )
        if eco.manifest_files or eco.lock_files:
            result.append(eco)

    if "crates.io" in ecosystems:
        eco = EcosystemDependencies(ecosystem="crates.io")
        members: set[str] = set()
        locks: list[tuple[Path, str]] = []
        for path in files:
            source = _rel(root, path)
            if path.name == "Cargo.toml":
                eco.manifest_files.append(source)
                direct, member = _parse_file(
                    errors, source, lambda: _cargo_direct(path, source), ([], None)
                )
                eco.direct.extend(direct)
                if member:
                    members.add(_norm_crate(member))
            elif path.name == "Cargo.lock":
                eco.lock_files.append(source)
                locks.append((path, source))
        resolved_c: list[tuple[str, str, str]] = []
        edges: set[tuple[str, str]] = set()
        for path, source in locks:
            pkgs, lock_edges = _parse_file(
                errors,
                source,
                lambda: _cargo_lock(path.read_text(encoding="utf-8"), members),
                ([], set()),
            )
            resolved_c.extend((n, v, source) for n, v in pkgs)
            edges |= lock_edges
        dev = _merge_dev(eco.direct, _norm_crate)
        seen_c: set[tuple[str, str]] = set()
        for name, version, source in resolved_c:
            key = (_norm_crate(name), version)
            if key in seen_c:
                continue
            seen_c.add(key)
            direct = key in edges
            eco.resolved.append(
                DependencyEntry(
                    name=name,
                    version=version,
                    purl=f"pkg:cargo/{name}@{version}",
                    direct=direct,
                    dev=direct and dev.get(key[0], False),
                    source_file=source,
                )
            )
        if eco.manifest_files or eco.lock_files:
            result.append(eco)

    return result, errors


def _merge_dev(entries: list[DependencyEntry], norm: Callable[[str], str]) -> dict[str, bool]:
    """name -> dev flag across all manifests (a dep that is a runtime dep anywhere is not dev)."""
    dev: dict[str, bool] = {}
    for entry in entries:
        key = norm(entry.name)
        dev[key] = dev.get(key, True) and entry.dev
    return dev
