"""``POST /sbom/{container_name}/dependencies`` — per-repo direct + resolved dependencies.

The SBOM (``/sbom/{container_name}``) lists RESOLVED packages of one repo with
purls; it cannot say which are direct and does not span the workspace's repos.
This route answers "what does each repo depend on": for the primary repo and
every source checkout under ``.repos/`` it returns, per ecosystem (PyPI,
crates.io), the manifest-declared direct dependencies and the lockfile-resolved
set with purls and the offline-OSV advisory ids of each resolved version.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from coding_client.clients import CodingWorkspacesClient, ServiceError
from fastapi import APIRouter, Depends, HTTPException, Query

from auth.tenant import require_tenant
from clients.outbound import sibling_headers
from config.settings import get_settings
from models.common import ResponseStatus
from models.container_models import ContainerInfo
from models.dependency_inventory_models import (
    EcosystemDependencies,
    RepoDependencies,
    WorkspaceDependencies,
    WorkspaceDependenciesResponse,
)
from models.errors import Error404Response, Error500Response
from models.package_manager_models import ExternalPackage
from models.responses import internal_error
from models.security_api_models import Ecosystem
from models.workspace_repos import (
    PRIMARY_REPO,
    REPOS_DIR,
    normalize_repo,
    repo_root,
)
from services.dependency_analyzer import attach_vulnerabilities
from services.dependency_inventory import build_inventory
from services.dependency_visualization import DependencyVulnerabilityScanner
from services.rust_crate_map import load_crate_map, rust_crate_map
from services.scan_runner import fetch_manifests_to_tempdir
from utils.container_validation import validate_and_get_container_for_tenant

logger = logging.getLogger(__name__)

router = APIRouter()

# Read + validate the map at import: an image without (or with a broken)
# data/pypi_to_crates.toml then fails to start, so the CI image smoke catches
# it instead of the route 500ing in prod.
load_crate_map()

_REPO_QUERY_DESCRIPTION = (
    "Which repository to list. Omitted = EVERY repo of the workspace: 'primary' "
    "(the workspace root, .repos/ excluded) plus each '.repos/<name>' source "
    "checkout. 'primary' or '.repos/<name>' (or the bare '<name>') = only that one."
)
_ECOSYSTEM_DESCRIPTION = (
    "auto = PyPI and crates.io, whichever have manifests; pypi / crates.io = only that ecosystem."
)


class RepoListingError(RuntimeError):
    """The workspace's ``.repos/`` listing did not complete (exec error, truncation)."""


def _local_codebase(workspace: ContainerInfo) -> bool:
    return os.path.isdir(workspace.codebase_path)


async def _secondary_repos(
    workspace: ContainerInfo, container_name: str, tenant_id: str
) -> list[str]:
    """Canonical ``.repos/<name>`` selectors present in the workspace.

    Remotely this is ``find <root> -mindepth 2 -maxdepth 2 -type d -path
    '<root>/.repos/*'`` and its STDOUT is the answer: find's exit status is
    ignored (it is 1 when ``.repos/`` is absent or any unrelated dir is
    unreadable, while the listing it printed is still complete). An exec error,
    a malformed response or output truncated by the exec budget raises
    :class:`RepoListingError`: answering from a partial listing would silently
    drop repos from the inventory.
    """
    names: list[str] = []
    if _local_codebase(workspace):
        base = Path(workspace.codebase_path) / REPOS_DIR
        if base.is_dir():
            names = sorted(p.name for p in base.iterdir() if p.is_dir())
    else:
        root = get_settings().workspace_root.rstrip("/")
        client = CodingWorkspacesClient(
            base_url=get_settings().containers_service_url, timeout=60.0
        )
        try:
            payload = await client.exec(
                container_name,
                headers=sibling_headers(
                    tenant_id, operation=f"containers exec ls-repos {container_name}"
                ),
                command=[
                    "find",
                    root,
                    "-mindepth",
                    "2",
                    "-maxdepth",
                    "2",
                    "-type",
                    "d",
                    "-path",
                    f"{root}/{REPOS_DIR}/*",
                ],
            )
        except ServiceError as exc:
            raise RepoListingError(f"could not list {REPOS_DIR}/ (HTTP {exc.status_code})") from exc
        finally:
            await client.close()
        if not isinstance(payload, dict):
            raise RepoListingError(f"could not list {REPOS_DIR}/: malformed exec response")
        if payload.get("truncated"):
            raise RepoListingError(f"listing {REPOS_DIR}/ was truncated by the exec budget")
        stdout = payload.get("stdout") or ""
        names = sorted(
            line.strip().rstrip("/").rsplit("/", 1)[-1]
            for line in stdout.splitlines()
            if line.strip()
        )
    out: list[str] = []
    for name in names:
        try:
            out.append(normalize_repo(name))
        except ValueError:
            logger.warning("skipping unsafe %s entry %r", REPOS_DIR, name)
    return out


@asynccontextmanager
async def _repo_manifests(
    workspace: ContainerInfo, container_name: str, tenant_id: str, repo: str
) -> AsyncGenerator[tuple[Path, bool]]:
    """Yield ``(local dir holding the repo's manifests, fetch_incomplete)``."""
    if _local_codebase(workspace):
        yield Path(repo_root(workspace.codebase_path, repo)), False
        return
    temp_dir, incomplete = await fetch_manifests_to_tempdir(
        container_name, repo_root(get_settings().workspace_root, repo), tenant_id
    )
    try:
        yield temp_dir, incomplete
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def _attach_advisories(eco: EcosystemDependencies, db_dir: str) -> list[str]:
    """Fill ``advisories`` / ``advisories_checked`` of every resolved entry; return lookup errors.

    The same offline-OSV lookup the dependency scan runs (``scan_vulnerabilities``
    + ``attach_vulnerabilities``), so each record lands on the version it affects.
    Any lookup error (no DB for the ecosystem, an unreadable record) leaves the
    whole ecosystem UNCHECKED: never read as clean.
    """
    scanner = DependencyVulnerabilityScanner(offline_db_dir=db_dir, enable_cache=False)
    packages = [
        ExternalPackage(name=e.name, version=e.version, ecosystem=eco.ecosystem)
        for e in eco.resolved
    ]
    await scanner.scan_vulnerabilities(packages)
    if scanner.lookup_errors:
        return list(scanner.lookup_errors)
    enriched = attach_vulnerabilities(packages, scanner.package_vulnerabilities)
    for entry, package in zip(eco.resolved, enriched, strict=True):
        entry.advisories = sorted({v.id for v in package.vulnerabilities or []})
        entry.advisories_checked = True
    return []


async def _list_repo(
    workspace: ContainerInfo,
    container_name: str,
    tenant_id: str,
    name: str,
    ecosystems: set[Literal["pypi", "crates.io"]],
) -> tuple[RepoDependencies, bool, list[str]]:
    """One repo's inventory: ``(entry, incomplete, advisory lookup errors)``.

    Manifest parsing runs in a worker thread, never on the event loop.
    """
    entry = RepoDependencies(repo=name)
    incomplete = False
    advisory_errors: list[str] = []
    try:
        async with _repo_manifests(workspace, container_name, tenant_id, name) as (path, partial):
            entry.ecosystems, entry.errors = await asyncio.to_thread(
                build_inventory, path, ecosystems
            )
            entry.rust_crate_map = rust_crate_map(entry.ecosystems)
            if partial:
                incomplete = True
                entry.errors.append("manifest fetch was incomplete")
    except RuntimeError as exc:
        incomplete = True
        entry.errors.append(f"manifest fetch failed: {exc}")
    db_dir = get_settings().osv_offline_db_dir
    for eco in entry.ecosystems:
        if eco.resolved:
            for error in await _attach_advisories(eco, db_dir):
                if error not in advisory_errors:
                    advisory_errors.append(error)
    return entry, incomplete, advisory_errors


@router.post(
    "/sbom/{container_name}/dependencies",
    response_model=WorkspaceDependenciesResponse,
    operation_id="list_workspace_dependencies",
    summary="Per-repo direct + resolved dependencies (PyPI, crates.io)",
    description=(
        "For each repo of the workspace (primary + every .repos/<name> source "
        "checkout, or the one named by `repo`): per ecosystem, the manifest files, "
        "the direct dependencies as declared (name, specifier, dev) and the "
        "lockfile-resolved packages (name, version, purl, direct, dev) with the "
        "offline-OSV advisory ids of each resolved version. PyPI from pyproject.toml "
        "/ requirements*.txt / uv.lock / poetry.lock; crates from Cargo.toml / "
        "Cargo.lock. `advisories_checked=false` means UNCHECKED, not clean. "
        "`rust_crate_map` maps each DIRECT PyPI dependency to the Rust crates that "
        "replace it, plus `tools` installed with `cargo install` (versioned map, "
        "`unmapped` = no entry, never guessed)."
    ),
    responses={
        404: {"model": Error404Response, "description": "Workspace or repo not found"},
        500: {"model": Error500Response, "description": "Listing failed"},
    },
)
async def list_workspace_dependencies(
    container_name: str,
    repo: Annotated[str | None, Query(description=_REPO_QUERY_DESCRIPTION)] = None,
    ecosystem: Annotated[Ecosystem, Query(description=_ECOSYSTEM_DESCRIPTION)] = "auto",
    tenant_id: str = Depends(require_tenant),
) -> WorkspaceDependenciesResponse:
    try:
        selected = normalize_repo(repo) if repo is not None else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    ecosystems: set[Literal["pypi", "crates.io"]] = (
        {"pypi", "crates.io"} if ecosystem == "auto" else {ecosystem}
    )

    # Tenant gate FIRST: nothing runs for a name that is not the caller's.
    workspace = await validate_and_get_container_for_tenant(container_name, tenant_id)
    try:
        try:
            secondary = await _secondary_repos(workspace, container_name, tenant_id)
        except RepoListingError as exc:
            if selected not in (None, PRIMARY_REPO):
                # The selected checkout cannot be confirmed to exist.
                raise internal_error(str(exc)) from exc
            # Primary-only answers stay correct; an all-repos answer is partial
            # and says so (degraded) instead of omitting repos silently.
            secondary = []
            listing_error = str(exc)
        else:
            listing_error = None
        if selected is None:
            repos = [PRIMARY_REPO, *secondary]
        elif selected == PRIMARY_REPO or selected in secondary:
            repos = [selected]
        else:
            raise HTTPException(
                status_code=404,
                detail=f"repo '{selected}' not found in workspace '{container_name}'",
            )
        result = WorkspaceDependencies(
            container_name=container_name, generated_at=datetime.now(UTC)
        )
        if listing_error and selected is None:
            result.incomplete = True
            result.repo_listing_error = listing_error
        for name in repos:
            entry, incomplete, lookup_errors = await _list_repo(
                workspace, container_name, tenant_id, name, ecosystems
            )
            result.incomplete = result.incomplete or incomplete
            result.advisory_lookup_errors.extend(
                e for e in lookup_errors if e not in result.advisory_lookup_errors
            )
            result.repos.append(entry)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("dependency listing failed for %s", container_name)
        raise internal_error(f"Dependency listing failed: {exc}") from exc

    degraded = (
        result.incomplete
        or bool(result.advisory_lookup_errors)
        or any(r.errors for r in result.repos)
    )
    total = sum(len(e.resolved) for r in result.repos for e in r.ecosystems)
    return WorkspaceDependenciesResponse(
        status=ResponseStatus.DEGRADED if degraded else ResponseStatus.SUCCESS,
        message=(
            f"{len(result.repos)} repo(s), {total} resolved package(s)"
            + (
                " — DEGRADED: see errors / advisory_lookup_errors / repo_listing_error"
                if degraded
                else ""
            )
        ),
        result=result,
    )
