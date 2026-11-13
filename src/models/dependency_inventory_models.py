"""Per-repo dependency inventory (direct + resolved) for a workspace — SBOM-shaped.

Served by ``POST /api/security/sbom/{container_name}/dependencies``. Each entry
carries a purl and the offline-OSV advisory ids for its resolved version, so the
list is a security view, not a build-tool view.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from models.common import BaseResponse


class DependencyEntry(BaseModel):
    """One package of one ecosystem in one repo."""

    name: str
    version: str | None = Field(
        None, description="Resolved version (from the lockfile); null for a direct-only entry"
    )
    specifier: str | None = Field(
        None, description="Requirement as declared in the manifest (direct deps only)"
    )
    purl: str | None = Field(None, description="pkg:pypi/... or pkg:cargo/... (resolved only)")
    direct: bool = Field(..., description="Declared in a manifest of this repo")
    dev: bool = Field(False, description="Declared only as a dev/test/build dependency")
    source_file: str = Field(..., description="Manifest or lockfile, relative to the repo root")
    advisories: list[str] = Field(
        default_factory=list,
        description="Offline-OSV advisory ids affecting the resolved version",
    )
    advisories_checked: bool = Field(
        False,
        description=(
            "True only when the resolved version was looked up in the offline OSV DB. "
            "False = UNCHECKED (no lockfile version, or no DB for the ecosystem) - never "
            "read an empty advisories list on an unchecked entry as clean."
        ),
    )


class EcosystemDependencies(BaseModel):
    ecosystem: Literal["pypi", "crates.io"]
    manifest_files: list[str] = Field(default_factory=list)
    lock_files: list[str] = Field(default_factory=list)
    direct: list[DependencyEntry] = Field(
        default_factory=list, description="Dependencies declared in the manifests"
    )
    resolved: list[DependencyEntry] = Field(
        default_factory=list,
        description="Every package pinned by the lockfiles (direct + transitive), registry only",
    )


class CrateMapping(BaseModel):
    """One direct PyPI dependency and the Rust crate(s) that replace it."""

    pypi: str = Field(..., description="PEP 503-normalised PyPI name")
    version: str | None = Field(
        None,
        description=(
            "Locked version of the direct dependency; null when no lockfile pins exactly "
            "one version of it"
        ),
    )
    dev: bool = Field(False, description="Declared only as a dev/test/build dependency")
    crates: list[str] = Field(
        ...,
        description=(
            "crates.io names to add as [dependencies] / [dev-dependencies]; empty = "
            "nothing to add (std, language feature or toolchain), see note"
        ),
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Binaries installed with `cargo install` (never a Cargo.toml dependency)",
    )
    note: str | None = Field(None, description="Caveat or the std/toolchain replacement")


class RustCrateMap(BaseModel):
    """Direct PyPI dependencies of one repo mapped to Rust crates (py2rust planning).

    Facts from the versioned map file only; nothing is guessed.
    """

    map_version: str = Field(..., description="Version of the PyPI->crates map file")
    mapped: list[CrateMapping] = Field(default_factory=list)
    unmapped: list[str] = Field(
        default_factory=list,
        description="Direct PyPI dependencies (normalised) the map has no entry for",
    )


class RepoDependencies(BaseModel):
    repo: str = Field(..., description="'primary' or '.repos/<name>'")
    ecosystems: list[EcosystemDependencies] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    rust_crate_map: RustCrateMap | None = Field(
        None,
        description=(
            "Rust crates replacing each DIRECT PyPI dependency (transitive ones are not "
            "ported); null when the repo has no PyPI ecosystem"
        ),
    )


class WorkspaceDependencies(BaseModel):
    container_name: str
    generated_at: datetime
    repos: list[RepoDependencies] = Field(default_factory=list)
    advisory_lookup_errors: list[str] = Field(
        default_factory=list,
        description="Advisory-DB lookup failures (missing DB/ecosystem, unreadable record)",
    )
    repo_listing_error: str | None = Field(
        None,
        description=(
            "Set when the workspace's .repos/ listing failed or was truncated: only the "
            "primary repo is listed and the answer is incomplete"
        ),
    )
    incomplete: bool = Field(
        False,
        description=(
            "A manifest fetch dropped files, a repo could not be read, or the .repos/ "
            "listing failed"
        ),
    )


class WorkspaceDependenciesResponse(BaseResponse):
    result: WorkspaceDependencies
