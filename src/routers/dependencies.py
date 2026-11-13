"""Dependencies API endpoints for analyzing project dependencies.

Provides endpoints for analyzing dependencies, security vulnerabilities,
license compliance, and generating dependency reports.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException

from app_factory import get_redis
from auth.tenant import require_tenant
from clients.containers_client import ContainersClient, ContainersClientError
from clients.github_client import GithubClient
from config.settings import get_settings
from models.architecture_models import DependencyRiskReport, mark_degraded
from models.errors import (
    Error400Response,
    Error404Response,
    Error500Response,
    ValidationErrorResponse,
)
from models.package_manager_models import ExternalPackage
from models.responses import (
    bad_request,
    internal_error,
    not_found,
    service_unavailable,
)
from models.upgrade_models import (
    AddDependenciesRequest,
    RemoveDependenciesRequest,
    ReplaceDependenciesRequest,
    UpgradeCvesRequest,
    UpgradeMajorRequest,
    UpgradeRequest,
    UpgradeResponse,
)
from services import scan_queue
from services.dependency_analyzer import ArchitectureDependencyAnalyzer
from services.dependency_upgrade import (
    execute_add,
    execute_cross_major_upgrade,
    execute_cve_upgrade,
    execute_in_range_upgrade,
    execute_remove,
    execute_replace,
)

# ``resolve_repo_path`` / ``ResolvedRepo`` live in ``services.scan_runner`` so the
# durable-scan worker imports them without a router→app_factory cycle. They are
# re-imported here so the synchronous GET endpoints (and callers that patch
# ``routers.dependencies.resolve_repo_path``) keep working unchanged.
from services.scan_runner import ResolvedRepo, resolve_repo_path  # noqa: F401
from services.scan_task_store import (
    AsyncScanTaskRecord,
    ScanTaskAccessDenied,
    ScanTaskStore,
    ScanTaskStoreUnavailable,
)
from services.workspace_latest_versions import (
    LatestLookupError,
    apply_latest_versions,
    fetch_latest_in_workspace,
)
from utils.container_validation import validate_and_get_container_for_tenant

logger = logging.getLogger(__name__)

router = APIRouter()


def get_dependency_analyzer():
    """Dependency to get the dependency analyzer."""
    return ArchitectureDependencyAnalyzer()


@router.get(
    "/{container_name}",
    response_model=DependencyRiskReport,
    operation_id="get_container_dependencies",
    summary="Get container dependency analysis",
    description="""
    Get comprehensive dependency analysis report for a container.

    Analyzes all dependencies within the container including:
    - External package dependencies
    - Security vulnerabilities
    - Outdated packages
    - License compliance
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
    },
)
async def get_dependencies(
    container_name: str,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    """Get dependency analysis report for a container."""
    try:
        async with resolve_repo_path(container_name, tenant_id) as repo:
            if not repo.path.exists():
                raise not_found("Container codebase path", f"{container_name} at {repo.path}")

            report = await analyzer.analyze(repo.path, container_name)
            # OR, never overwrite: analyze() already flags its own degradations.
            if repo.incomplete:
                mark_degraded(report, "dependency-manifest fetch was incomplete")
            return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get dependencies for container %s: %s", container_name, e)
        raise internal_error(f"Failed to get dependencies: {str(e)}") from e


@router.get(
    "/{container_name}/outdated",
    response_model=list[ExternalPackage],
    operation_id="list_outdated_packages",
    summary="Get outdated packages in container",
    description="""
    Get packages that have newer versions available within the container.

    Returns a list of packages with:
    - Current version
    - Latest available version
    - Update recommendations

    For uv projects (uv.lock) latest versions are resolved inside the workspace
    (`uv tree --outdated`), for direct dependencies. Returns 503 when that lookup
    fails, rather than an empty list that would read as "up to date".
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
        503: {
            "model": Error500Response,
            "description": "Workspace latest-version lookup failed",
        },
    },
)
async def get_outdated_packages(
    container_name: str,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    """Get packages that have newer versions available in the container."""
    try:
        async with resolve_repo_path(container_name, tenant_id) as repo:
            if not repo.path.exists():
                raise not_found("Container codebase path", f"{container_name} at {repo.path}")

            report = await analyzer.analyze(repo.path, container_name)
            packages = report.packages
            if (repo.path / "uv.lock").is_file():
                # The pod has no internet egress: ask uv INSIDE the workspace.
                try:
                    latest = await fetch_latest_in_workspace(
                        _build_clients()[0], container_name=container_name, tenant_id=tenant_id
                    )
                except LatestLookupError as exc:
                    # Fail loud: [] would read as "everything is up to date".
                    raise service_unavailable(
                        f"Latest-version lookup in the workspace failed: {exc}"
                    ) from exc
                packages = apply_latest_versions(packages, latest)
            return analyzer.get_outdated_packages(packages)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get outdated packages for container %s: %s", container_name, e)
        raise internal_error(f"Failed to get outdated packages: {str(e)}") from e


@router.get(
    "/{container_name}/vulnerable",
    response_model=list[ExternalPackage],
    operation_id="list_vulnerable_packages",
    summary="Get vulnerable packages in container",
    description="""
    Get packages with known security vulnerabilities within the container.

    Each returned package carries, from the OSV scan:
    - `severity`: the highest severity among its known vulnerabilities (LOW-only packages
      are excluded)
    - `vulnerability_ids`: the advisory ids (OSV / CVE / GHSA)
    - `vulnerabilities`: `[{id, severity, fixed_versions}]`, one per advisory, each with
      its OWN fixed versions (empty = no known fix)
    - `fixed_versions`: the union of those fixes, or null when any advisory has no fix

    Returns 503 when any OSV lookup failed, rather than an incomplete list that would
    read as "nothing vulnerable".
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
        503: {
            "model": Error500Response,
            "description": "Vulnerability (OSV) lookup failed; the result would be incomplete",
        },
    },
)
async def get_vulnerable_packages(
    container_name: str,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    """Get packages with known security vulnerabilities in the container."""
    try:
        async with resolve_repo_path(container_name, tenant_id) as repo:
            if not repo.path.exists():
                raise not_found("Container codebase path", f"{container_name} at {repo.path}")

            report = await analyzer.analyze(repo.path, container_name)
            lookup_errors = analyzer.vulnerability_lookup_errors
            if lookup_errors:
                # Fail loud: a partial OSV lookup would otherwise return [] (or a
                # short list) that reads exactly like "nothing is vulnerable".
                raise service_unavailable(
                    f"Vulnerability lookup failed for {len(lookup_errors)} "
                    f"package(s)/batch(es); result would be incomplete: "
                    f"{'; '.join(lookup_errors[:3])}"
                )
            vulnerable = analyzer.get_vulnerable_packages(report.packages)

            return vulnerable

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get vulnerable packages for container %s: %s", container_name, e)
        raise internal_error(f"Failed to get vulnerable packages: {str(e)}") from e


@router.get(
    "/{container_name}/report",
    response_model=DependencyRiskReport,
    operation_id="get_dependency_report",
    summary="Get container dependency report",
    description="""
    Alias for GET /{container_name} to match frontend expectations.

    Get comprehensive dependency analysis report for a container including:
    - External package dependencies with versions and ecosystems
    - Security vulnerabilities with CVE information
    - Outdated packages
    - License compliance information
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
    },
)
async def get_dependency_report(
    container_name: str,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    """Get dependency analysis report for a container (frontend-compatible endpoint)."""
    return await get_dependencies(container_name, analyzer, tenant_id)


@router.post(
    "/{container_name}/scan",
    response_model=DependencyRiskReport,
    operation_id="scan_container_dependencies",
    summary="Trigger dependency scan",
    description="""
    Trigger a new dependency scan for the container.

    This endpoint forces a fresh analysis of dependencies, bypassing any cache.
    Use this when you want to ensure the most up-to-date dependency information.

    Returns the same comprehensive report as GET /{container_name}/report including:
    - External package dependencies
    - Security vulnerabilities
    - Outdated packages
    - License compliance
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
    },
)
async def trigger_dependency_scan(
    container_name: str,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    """Trigger a new dependency scan for a container."""
    try:
        async with resolve_repo_path(container_name, tenant_id) as repo:
            if not repo.path.exists():
                raise not_found("Container codebase path", f"{container_name} at {repo.path}")

            # Force fresh analysis: drop cached vulnerability lookups so this
            # genuinely re-queries instead of returning a stale grade (the
            # docstring promise of "bypassing any cache").
            analyzer.clear_vulnerability_cache()
            logger.info("Triggering dependency scan for container: %s", container_name)
            report = await analyzer.analyze(repo.path, container_name)
            # OR, never overwrite: analyze() already flags its own degradations.
            if repo.incomplete:
                mark_degraded(report, "dependency-manifest fetch was incomplete")

            logger.info(
                "Dependency scan completed for container %s: %d packages, %d vulnerabilities",
                container_name,
                len(report.packages),
                len(report.vulnerabilities),
            )

            return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to trigger dependency scan for container %s: %s", container_name, e)
        raise internal_error(f"Failed to trigger dependency scan: {str(e)}") from e


@router.post(
    "/{container_name}/scan/async",
    operation_id="scan_container_dependencies_async",
    summary="Async Dependency Scan (task_id + poll)",
    description="""
    **Submit a dependency scan as a background task and poll for the result.**

    Additive companion to ``POST /{container_name}/scan``: instead of blocking
    the request for the whole scan (which can outrun the upstream gateway budget
    on a large repo with many manifests / transitive CVE lookups), this enqueues
    the scan in a background task under a wider wall-clock budget and returns a
    ``task_id`` immediately. Poll ``GET /scan/results/{task_id}`` for
    ``queued`` / ``running`` / ``completed`` / ``failed`` status and the final
    ``DependencyRiskReport``.

    Requires the Redis results store to be online (returns 503 if not).
    """,
    responses={
        200: {"description": "Scan task accepted; poll /scan/results/{task_id}"},
        404: {"model": Error404Response, "description": "Container not found"},
        503: {
            "model": Error500Response,
            "description": "Async scan unavailable - results store offline",
        },
    },
)
async def scan_container_dependencies_async(
    container_name: str,
    tenant_id: str = Depends(require_tenant),
) -> dict:
    """Submit an async (task_id + poll) dependency scan for a container.

    The scan is executed by the durable Redis-Streams worker (see
    ``services.scan_worker``): this endpoint stamps a ``queued`` record and
    enqueues a job, then returns immediately. The worker builds a fresh
    ``ArchitectureDependencyAnalyzer`` per job (empty cache = genuinely fresh
    scan), so no explicit cache-clear is needed here.
    """
    # Validate container up-front so a bad name fails fast with 404 before we
    # allocate a task_id or enqueue work.
    await validate_and_get_container_for_tenant(container_name, tenant_id)

    # The async model persists status + result in Redis for the poll endpoint.
    # Evaluate get_redis at call time (not as a default arg) so it stays
    # patchable in tests and the store re-reads it on every write.
    settings = get_settings()
    store = ScanTaskStore(
        key_prefix="dependency_scan_task:",
        ttl_seconds=settings.security_scan_task_ttl_seconds,
        redis_getter=get_redis,
        stale_after_seconds=settings.security_scan_stale_after_seconds,
    )
    budget = settings.dependency_scan_async_budget_seconds

    task_id = str(uuid.uuid4())

    # Store 'queued' synchronously BEFORE returning so an immediate poll sees it.
    # If the store is offline there is nowhere to write the result, so the poll
    # could never observe completion — fail loud (503) instead of silently
    # dropping the scan into a void.
    queued = AsyncScanTaskRecord(
        task_id=task_id,
        status="queued",
        tenant_id=tenant_id,
        extra={"container_name": container_name},
    )
    try:
        await store.store(queued, required=True)
    except ScanTaskStoreUnavailable:
        raise HTTPException(
            status_code=503,
            detail="async dependency scan unavailable: results store offline",
        )

    # Enqueue the durable job (dependency jobs carry no request body).
    await scan_queue.enqueue(
        get_redis(),
        settings,
        task_id=task_id,
        tenant_id=tenant_id,
        container_name=container_name,
        kind="dependency",
        budget_seconds=budget,
        scan_request="",
    )
    return {"task_id": task_id, "container_name": container_name, "status": "queued"}


@router.get(
    "/scan/results/{task_id}",
    operation_id="get_dependency_scan_results",
    summary="Poll Async Dependency Scan Result",
    description="""
    **Retrieve the result of an async dependency scan by task_id.**

    Returns the stored record (``queued`` / ``running`` / ``completed`` /
    ``failed``) written by ``POST /{container_name}/scan/async``. If the task is
    unknown (still running before the first store, or expired past the 24h TTL),
    returns ``status: pending``. Records are tenant-scoped: a task belonging to
    another tenant returns 404.
    """,
    responses={
        200: {"description": "Task status / result (or pending if unknown)"},
        404: {"model": Error404Response, "description": "Task not found for this tenant"},
    },
)
async def get_dependency_scan_results(
    task_id: str,
    tenant_id: str = Depends(require_tenant),
) -> dict:
    """Poll for an async dependency scan result by task_id."""
    settings = get_settings()
    store = ScanTaskStore(
        key_prefix="dependency_scan_task:",
        ttl_seconds=settings.security_scan_task_ttl_seconds,
        redis_getter=get_redis,
        stale_after_seconds=settings.security_scan_stale_after_seconds,
    )
    try:
        record = await store.load(task_id, tenant_id)
    except ScanTaskAccessDenied:
        raise HTTPException(status_code=404, detail="Task not found")

    if record is None:
        return {
            "task_id": task_id,
            "status": "pending",
            "message": "Dependency scan is still running or results have expired (24h TTL).",
        }
    return record


def _build_clients() -> tuple[ContainersClient, GithubClient | None]:
    """Build the per-request httpx wrappers, reading URLs from settings.

    ``GithubClient`` is None when the URL isn't configured — the upgrade
    routes will surface a 400 if a caller asks for commit/open_pr without it.
    """
    from config.settings import get_settings

    s = get_settings()
    containers_client = ContainersClient(s.containers_service_url)
    github_client: GithubClient | None = None
    if s.github_service_url:
        github_client = GithubClient(s.github_service_url)
    return containers_client, github_client


@router.post(
    "/{container_name}/upgrade",
    response_model=UpgradeResponse,
    operation_id="upgrade_in_range_packages",
    summary="Upgrade packages within their current manifest constraint",
    description="""
    Bump one or more packages to the latest version permitted by the
    constraint already declared in the manifest. Touches the lockfile only.

    Companion endpoint: ``POST /{container_name}/upgrade-major`` rewrites
    the constraint AND bumps the lockfile (use that when the new release
    crosses the existing upper bound — e.g. ``fastmcp>=2.13.0,<3.0.0`` →
    ``3.0.0``).

    The package manager is auto-detected from the manifests in
    ``project_path`` unless explicitly provided. Supports all 18 managers
    in ``LanguagePackageManager`` (uv, pip, poetry, pipenv, conda,
    npm, yarn, pnpm, bun, cargo, maven, gradle, gem/bundler, go, composer,
    nuget, dotnet).

    Optional ``commit=true`` posts the resulting diff via coding-github's
    ``/api/repositories/apply-changes``; ``open_pr=true`` additionally opens a PR.
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
    },
)
async def upgrade_in_range_packages(
    container_name: str,
    body: UpgradeRequest,
    tenant_id: str = Depends(require_tenant),
):
    if body.commit and not body.branch_name:
        raise bad_request("branch_name is required when commit=true")
    if body.open_pr and not body.commit:
        raise bad_request("open_pr=true requires commit=true")

    containers_client, github_client = _build_clients()
    try:
        return await execute_in_range_upgrade(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        # 400-class errors from coding-containers (bad manager etc.) propagate
        # as 400; transport / 5xx land as 502.
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error("upgrade failed: container=%s err=%s", container_name, exc, exc_info=True)
        raise internal_error(f"Upgrade failed: {exc}") from exc


@router.post(
    "/{container_name}/upgrade-major",
    response_model=UpgradeResponse,
    operation_id="upgrade_cross_major_packages",
    summary="Rewrite the manifest constraint and upgrade across a major version",
    description="""
    Cross-major package upgrade. For each package: rewrite the version
    constraint in the manifest (``pyproject.toml`` / ``package.json`` /
    ``Cargo.toml`` / …) AND bump the lockfile.

    Use this when an in-range upgrade can't reach the new version because the
    existing manifest constraint forbids it. Example: ``pyproject.toml`` pins
    ``fastmcp>=2.13.0,<3.0.0`` and the latest is ``3.0.0`` — only this route
    can deliver the bump.

    The package manager is auto-detected from manifests in ``project_path``
    unless explicitly provided. Constraint derivation defaults to a SemVer-
    style upper bound (``>={target},<{major+1}.0.0``); pass ``new_constraint``
    to override.
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {
            "model": ValidationErrorResponse,
            "description": "Validation error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error",
        },
    },
)
async def upgrade_cross_major_packages(
    container_name: str,
    body: UpgradeMajorRequest,
    tenant_id: str = Depends(require_tenant),
):
    if body.commit and not body.branch_name:
        raise bad_request("branch_name is required when commit=true")
    if body.open_pr and not body.commit:
        raise bad_request("open_pr=true requires commit=true")

    containers_client, github_client = _build_clients()
    try:
        return await execute_cross_major_upgrade(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error(
            "upgrade-major failed: container=%s err=%s",
            container_name,
            exc,
            exc_info=True,
        )
        raise internal_error(f"Upgrade-major failed: {exc}") from exc


def _validate_commit_opts(body) -> None:  # noqa: ANN001  (body is one of the request models)
    if body.commit and not body.branch_name:
        raise bad_request("branch_name is required when commit=true")
    if body.open_pr and not body.commit:
        raise bad_request("open_pr=true requires commit=true")


@router.post(
    "/{container_name}/upgrade-cves",
    response_model=UpgradeResponse,
    operation_id="upgrade_cves",
    summary="Upgrade every dependency with a CVE at or above the chosen severity",
    description="""
    CVE-driven dependency upgrade. Reads the analyzer's vulnerability report,
    filters by ``min_severity`` / ``cve_ids`` / ``packages``, picks the
    minimum version that clears every CVE per package, and dispatches the
    right verb (in-range or cross-major).

    ``allow_major`` is True by default — typical security policy is "take the
    bump even if it crosses a major" because the alternative is staying
    vulnerable. Set False to refuse cross-major fixes and have them surface
    as ``PackageResult.success=False`` for manual review.
    """,
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {"model": ValidationErrorResponse, "description": "Validation error"},
        500: {"model": Error500Response, "description": "Internal server error"},
    },
)
async def upgrade_cves(
    container_name: str,
    body: UpgradeCvesRequest,
    analyzer: ArchitectureDependencyAnalyzer = Depends(get_dependency_analyzer),
    tenant_id: str = Depends(require_tenant),
):
    _validate_commit_opts(body)
    containers_client, github_client = _build_clients()
    try:
        return await execute_cve_upgrade(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
            analyzer=analyzer,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error("upgrade-cves failed: container=%s err=%s", container_name, exc, exc_info=True)
        raise internal_error(f"upgrade-cves failed: {exc}") from exc


@router.post(
    "/{container_name}/add",
    response_model=UpgradeResponse,
    operation_id="add_dependencies",
    summary="Add new dependencies to the manifest",
    description=(
        "Append new dependencies via the manager's native ``add`` verb (or via "
        "in-process manifest edit for pip / conda / maven / gradle / bundler). "
        "Companion routes: ``/remove`` and ``/replace`` for the inverse and the "
        "atomic-swap case respectively."
    ),
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {"model": ValidationErrorResponse, "description": "Validation error"},
        500: {"model": Error500Response, "description": "Internal server error"},
    },
)
async def add_dependencies(
    container_name: str,
    body: AddDependenciesRequest,
    tenant_id: str = Depends(require_tenant),
):
    _validate_commit_opts(body)
    containers_client, github_client = _build_clients()
    try:
        return await execute_add(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error("add failed: container=%s err=%s", container_name, exc, exc_info=True)
        raise internal_error(f"add failed: {exc}") from exc


@router.post(
    "/{container_name}/remove",
    response_model=UpgradeResponse,
    operation_id="remove_dependencies",
    summary="Remove dependencies from the manifest",
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {"model": ValidationErrorResponse, "description": "Validation error"},
        500: {"model": Error500Response, "description": "Internal server error"},
    },
)
async def remove_dependencies(
    container_name: str,
    body: RemoveDependenciesRequest,
    tenant_id: str = Depends(require_tenant),
):
    _validate_commit_opts(body)
    containers_client, github_client = _build_clients()
    try:
        return await execute_remove(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error("remove failed: container=%s err=%s", container_name, exc, exc_info=True)
        raise internal_error(f"remove failed: {exc}") from exc


@router.post(
    "/{container_name}/replace",
    response_model=UpgradeResponse,
    operation_id="replace_dependencies",
    summary="Atomically replace one dependency with another (e.g. asyncpg → psycopg)",
    description=(
        "Single-commit remove + add for one or more replacements. If the remove "
        "step succeeds and the add step fails (resolver conflict, missing "
        "registry), the orchestrator surfaces a non-zero ``exit_code`` and "
        "refuses to commit so no half-migration ships. When ``open_pr=true``, "
        "the PR body is appended with a list of source files that still import "
        "the OLD package name — best-effort grep based on the manager's "
        "ecosystem, never blocks the operation."
    ),
    responses={
        400: {"model": Error400Response, "description": "Bad request"},
        404: {"model": Error404Response, "description": "Container not found"},
        422: {"model": ValidationErrorResponse, "description": "Validation error"},
        500: {"model": Error500Response, "description": "Internal server error"},
    },
)
async def replace_dependencies(
    container_name: str,
    body: ReplaceDependenciesRequest,
    tenant_id: str = Depends(require_tenant),
):
    _validate_commit_opts(body)
    containers_client, github_client = _build_clients()
    try:
        return await execute_replace(
            container_name=container_name,
            tenant_id=tenant_id,
            body=body,
            containers_client=containers_client,
            github_client=github_client,
        )
    except HTTPException:
        raise
    except ContainersClientError as exc:
        if exc.status_code and exc.status_code < 500:
            raise bad_request(str(exc)) from exc
        raise internal_error(f"Upstream coding-containers error: {exc}") from exc
    except ValueError as exc:
        raise bad_request(str(exc)) from exc
    except Exception as exc:
        logger.error("replace failed: container=%s err=%s", container_name, exc, exc_info=True)
        raise internal_error(f"replace failed: {exc}") from exc
