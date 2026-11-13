"""Direct PyPI dependencies of one repo -> the Rust crates that replace them.

The map is the versioned data file ``data/pypi_to_crates.toml`` (shipped in the
image with ``src/``), read once. Only DIRECT dependencies are mapped: a port
replaces what the code imports, not what its dependencies pull in. A name the
file does not list is reported as ``unmapped``, never guessed.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from models.dependency_inventory_models import (
    CrateMapping,
    EcosystemDependencies,
    RustCrateMap,
)
from services.dependency_inventory import _merge_dev, _norm_pypi

MAP_PATH = Path(__file__).resolve().parents[1] / "data" / "pypi_to_crates.toml"


@dataclass(frozen=True)
class CrateEntry:
    crates: tuple[str, ...]
    tools: tuple[str, ...]
    note: str | None


@dataclass(frozen=True)
class CrateMapData:
    version: str
    packages: dict[str, CrateEntry]


def parse_crate_map(text: str) -> CrateMapData:
    """Parse and validate the map file's content; ValueError on any violation."""
    data = tomllib.loads(text)
    version = data.get("map_version")
    if not isinstance(version, str) or not version:
        raise ValueError("map_version missing")
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("[packages] missing")
    out: dict[str, CrateEntry] = {}
    for key, value in packages.items():
        if key != _norm_pypi(key):
            raise ValueError(f"packages.{key}: key is not PEP 503-normalised")
        if not isinstance(value, dict) or set(value) - {"crates", "tools", "note"}:
            raise ValueError(f"packages.{key}: only `crates`, `tools` and `note` are allowed")
        crates, tools, note = value.get("crates"), value.get("tools", []), value.get("note")
        for field, names in (("crates", crates), ("tools", tools)):
            if not isinstance(names, list) or not all(isinstance(c, str) and c for c in names):
                raise ValueError(f"packages.{key}.{field} is not a list of crate names")
        if note is not None and not (isinstance(note, str) and note):
            raise ValueError(f"packages.{key}.note is not a non-empty string")
        if not crates and not tools and note is None:
            raise ValueError(f"packages.{key}: empty crates and tools needs a note")
        out[key] = CrateEntry(tuple(crates), tuple(tools), note)
    return CrateMapData(version, out)


@cache
def load_crate_map() -> CrateMapData:
    return parse_crate_map(MAP_PATH.read_text(encoding="utf-8"))


def rust_crate_map(ecosystems: list[EcosystemDependencies]) -> RustCrateMap | None:
    """The crate map of the repo's direct PyPI deps; None without a PyPI ecosystem."""
    pypi = next((e for e in ecosystems if e.ecosystem == "pypi"), None)
    if pypi is None:
        return None
    crate_map = load_crate_map()
    dev = _merge_dev(pypi.direct, _norm_pypi)
    locked: dict[str, set[str]] = {}
    for entry in pypi.resolved:
        if entry.direct and entry.version:
            locked.setdefault(_norm_pypi(entry.name), set()).add(entry.version)
    result = RustCrateMap(map_version=crate_map.version)
    for name in sorted(dev):
        known = crate_map.packages.get(name)
        if known is None:
            result.unmapped.append(name)
            continue
        versions = locked.get(name, set())
        result.mapped.append(
            CrateMapping(
                pypi=name,
                version=next(iter(versions)) if len(versions) == 1 else None,
                dev=dev[name],
                crates=list(known.crates),
                tools=list(known.tools),
                note=known.note,
            )
        )
    return result
