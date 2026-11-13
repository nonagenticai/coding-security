"""Container-image scanning + SBOM endpoints.

Covers ``/scan/{container_name}/image`` (Trivy/Grype),
``/sbom/{container_name}`` (Syft), and
``/sbom/{container_name}/vulnerabilities`` (Syft + Grype) — the image-level
surface that complements the source-code scanners in ``container_scan``.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from auth.tenant import require_tenant
from models.common import ResponseStatus
from models.container_models import ContainerInfo
from models.errors import Error404Response, Error500Response
from models.responses import internal_error
from models.security_api_models import ImageScanResponse, SBOMResponse
from models.workspace_repos import PRIMARY_REPO, REPO_FIELD_DESCRIPTION, normalize_repo
from services.scan_runner import _materialize_codebase
from services.scanner_errors import ScannerExecutionError
from services.syft_scanner import SBOMFormat
from utils.container_validation import validate_and_get_container_for_tenant

logger = logging.getLogger(__name__)

router = APIRouter()

_WORKSPACE_IS_NOT_AN_IMAGE = (
    "'{name}' is a workspace, not an image: no image '{ref}' is built for it. "
    "Use POST /api/security/sbom/{name}/vulnerabilities for dependency "
    "vulnerabilities and POST /api/security/scan/{name} for source vulnerabilities."
)


async def _tenant_workspace(container_name: str, tenant_id: str) -> ContainerInfo:
    """The caller's workspace named ``container_name``; 404 for anything else.

    Resolved BEFORE any tool runs. These endpoints used to treat a name the
    tenant registry did not know as a registry IMAGE name and ran
    trivy/grype/syft on ``registry/<name>:<tag>`` — so any licensed caller
    could inventory and vulnerability-scan any image in the registry,
    including other tenants' and the platform's own. An unknown name and
    another tenant's workspace are the same 404 (no enumeration).
    """
    return await validate_and_get_container_for_tenant(container_name, tenant_id)


_MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
    }
)
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", "vendor"})
_MAX_MANIFESTS = 20


def _find_dependency_manifests(root: Path) -> list[str]:
    """Relative paths of dependency manifests under ``root`` (bounded, sorted)."""
    found: list[str] = []
    if not root.is_dir():
        return found
    stack = [root]
    while stack and len(found) < _MAX_MANIFESTS:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.name in _MANIFEST_NAMES or (
                entry.name.startswith("requirements") and entry.suffix == ".txt"
            ):
                found.append(str(entry.relative_to(root)))
    return sorted(found)[:_MAX_MANIFESTS]


@dataclass
class _SbomSource:
    """What syft catalogs: ``dir:<materialized workspace>``."""

    ref: str  # passed to syft
    label: str  # reported as image_ref
    errors: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)  # dependency manifests present


def _repo_param(repo: str | None) -> str:
    """Canonical repo selector, or 422 for a value that could escape .repos/."""
    try:
        return normalize_repo(repo)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@asynccontextmanager
async def _sbom_source(
    workspace: ContainerInfo, container_name: str, tenant_id: str, repo: str = PRIMARY_REPO
) -> AsyncGenerator[_SbomSource]:
    """Yield the (tenant-validated) workspace repo, materialized with the same
    fetch as /scan, as the SBOM source; the tempdir is removed on exit."""
    materialized = await _materialize_codebase(workspace, container_name, tenant_id, repo)
    try:
        label = f"workspace:{container_name}"
        if repo != PRIMARY_REPO:
            label += f"/{repo}"
        source = _SbomSource(ref=f"dir:{workspace.codebase_path}", label=label)
        if materialized.incomplete:
            source.errors.append("workspace fetch was incomplete; the SBOM may miss packages")
        source.manifests = await asyncio.to_thread(
            _find_dependency_manifests, Path(workspace.codebase_path)
        )
        yield source
    finally:
        if materialized.temp_dir:
            shutil.rmtree(materialized.temp_dir, ignore_errors=True)


@router.post(
    "/scan/{container_name}/image",
    response_model=ImageScanResponse,
    operation_id="scan_container_image",
    summary="Container Image Vulnerability Scan",
    description="Scan a container's Docker image for OS and library vulnerabilities using Trivy or Grype.",
    responses={
        200: {"model": ImageScanResponse, "description": "Image scan completed"},
        404: {"model": Error404Response, "description": "Container not found"},
        500: {"model": Error500Response, "description": "Image scan failed"},
    },
)
async def scan_container_image(
    container_name: str,
    tag: str = "latest",
    tenant_id: str = Depends(require_tenant),
) -> ImageScanResponse:
    """Scan a container's Docker image for vulnerabilities.

    Only the caller's own workspace is addressable (404 otherwise). A workspace
    has no built image, so the answer is "not computed" with the reason and
    the endpoints that do cover it — never a scan of an arbitrary registry ref.
    """
    from datetime import UTC, datetime

    from config.settings import get_settings
    from models.image_scan_models import ImageScanResult

    await _tenant_workspace(container_name, tenant_id)
    image_ref = f"{get_settings().docker_registry_url}/{container_name}:{tag}"
    reason = _WORKSPACE_IS_NOT_AN_IMAGE.format(name=container_name, ref=image_ref)
    return ImageScanResponse(
        status=ResponseStatus.DEGRADED,
        message=f"Image scan NOT COMPUTED: {reason}",
        result=ImageScanResult(
            container_name=container_name,
            image_ref=image_ref,
            scanner="none",
            scan_timestamp=datetime.now(UTC),
            scan_duration_seconds=0,
            total_vulnerabilities=0,
            errors=[reason],
        ),
    )


@router.post(
    "/sbom/{container_name}",
    response_model=SBOMResponse,
    operation_id="generate_sbom",
    summary="Generate Container SBOM",
    description="Generate a Software Bill of Materials for a container's Docker image using Syft.",
    responses={
        200: {"model": SBOMResponse, "description": "SBOM generated"},
        500: {"model": Error500Response, "description": "SBOM generation failed"},
    },
)
async def generate_container_sbom(
    container_name: str,
    # Allowlisted (422 otherwise): the value reaches `syft -o`, where
    # `fmt=/path` would write a file on the pod.
    sbom_format: SBOMFormat = "cyclonedx-json",
    tag: str = "latest",
    repo: Annotated[str | None, Query(description=REPO_FIELD_DESCRIPTION)] = None,
    tenant_id: str = Depends(require_tenant),
) -> SBOMResponse:
    """Generate an SBOM for the caller's workspace from its source tree.

    Lockfiles of every ecosystem syft catalogs are included: uv.lock /
    requirements (pkg:pypi) and Cargo.lock (pkg:cargo) side by side, each
    package with its ``ecosystem``.
    """
    from config.settings import get_settings
    from services.syft_scanner import SyftScanner

    selected = _repo_param(repo)
    # Tenant gate FIRST: nothing runs for a name that is not the caller's.
    workspace = await _tenant_workspace(container_name, tenant_id)
    try:
        settings = get_settings()

        # Off-thread: SyftScanner.__init__ runs a blocking --version probe.
        syft = await asyncio.to_thread(SyftScanner)
        async with _sbom_source(workspace, container_name, tenant_id, selected) as source:
            result = await syft.generate_sbom(
                source.ref,
                container_name=container_name,
                sbom_format=sbom_format,
                timeout=settings.syft_scan_timeout,
            )
        result.image_ref = source.label
        result.repo = selected
        result.errors.extend(source.errors)
        if result.total_packages == 0 and source.manifests and not result.errors:
            # A uv.lock-blind Syft (< 1.29) answers 0 packages for a repo full of
            # dependencies; that must not read as a genuinely empty SBOM.
            result.errors.append(
                "SBOM found 0 packages although dependency manifests are present: "
                + ", ".join(source.manifests[:5])
            )

        # SyftScanner reports its own failures on `result.errors` and returns a
        # zero-package SBOMResult — which is byte-identical to a genuinely empty
        # image unless the envelope status says otherwise.
        return SBOMResponse(
            status=ResponseStatus.DEGRADED if result.errors else ResponseStatus.SUCCESS,
            message=(
                f"SBOM generation DEGRADED for workspace {container_name}: "
                f"results are partial/incomplete — {result.total_packages} packages found "
                f"({len(result.errors)} error(s)): {'; '.join(result.errors[:2])}"
                if result.errors
                else f"SBOM generated for workspace {container_name}: "
                f"{result.total_packages} packages found"
            ),
            result=result,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"SBOM generation failed for container '{container_name}': {e}")
        raise internal_error(f"SBOM generation failed: {str(e)}")


@router.post(
    "/sbom/{container_name}/vulnerabilities",
    response_model=ImageScanResponse,
    operation_id="scan_sbom_vulnerabilities",
    summary="Scan SBOM for Vulnerabilities",
    description="Generate SBOM with Syft, then scan it with Grype for vulnerabilities.",
    responses={
        200: {"model": ImageScanResponse, "description": "SBOM vulnerability scan completed"},
        500: {"model": Error500Response, "description": "SBOM vulnerability scan failed"},
    },
)
async def scan_sbom_vulnerabilities(
    container_name: str,
    tag: str = "latest",
    repo: Annotated[str | None, Query(description=REPO_FIELD_DESCRIPTION)] = None,
    tenant_id: str = Depends(require_tenant),
) -> ImageScanResponse:
    """Generate SBOM and scan it for vulnerabilities."""
    import tempfile
    from datetime import UTC, datetime

    from config.settings import get_settings
    from models.image_scan_models import ImageScanResult
    from services.grype_scanner import GrypeScanner
    from services.syft_scanner import SyftScanner

    selected = _repo_param(repo)
    # Tenant gate FIRST: nothing runs for a name that is not the caller's.
    workspace = await _tenant_workspace(container_name, tenant_id)
    try:
        settings = get_settings()
        image_ref = f"workspace:{container_name}"
        start_time = datetime.now(UTC)
        errors: list[str] = []
        # Bound BEFORE the scan: on the ScannerExecutionError path below the
        # assignment never happens, and every downstream use would raise
        # NameError — turning the intended degraded result into an opaque 500.
        vulns: list = []

        # Off-thread: both scanners run blocking --version probes in __init__.
        syft = await asyncio.to_thread(SyftScanner)
        grype = await asyncio.to_thread(GrypeScanner)

        if not syft.is_syft_available():
            errors.append("Syft not available for SBOM generation")
            result = ImageScanResult(
                container_name=container_name,
                image_ref=image_ref,
                scanner="grype",
                scan_timestamp=datetime.now(UTC),
                scan_duration_seconds=0,
                total_vulnerabilities=0,
                errors=errors,
            )
            return ImageScanResponse(
                status=ResponseStatus.DEGRADED,
                message="SBOM vulnerability scan DEGRADED: Syft not available, no SBOM was generated",
                result=result,
            )

        if not grype.is_grype_available():
            errors.append("Grype not available for SBOM scanning")
            result = ImageScanResult(
                container_name=container_name,
                image_ref=image_ref,
                scanner="grype",
                scan_timestamp=datetime.now(UTC),
                scan_duration_seconds=0,
                total_vulnerabilities=0,
                errors=errors,
            )
            return ImageScanResponse(
                status=ResponseStatus.DEGRADED,
                message="SBOM vulnerability scan DEGRADED: Grype not available, SBOM was not scanned",
                result=result,
            )

        # Generate SBOM (workspace: from its materialized source tree)
        async with _sbom_source(workspace, container_name, tenant_id, selected) as source:
            sbom_result = await syft.generate_sbom(
                source.ref,
                container_name=container_name,
                timeout=settings.syft_scan_timeout,
            )
        image_ref = source.label
        errors.extend(source.errors)
        errors.extend(sbom_result.errors)

        if not sbom_result.raw_sbom:
            errors.append("SBOM generation produced no output")
            result = ImageScanResult(
                container_name=container_name,
                image_ref=image_ref,
                scanner="grype",
                scan_timestamp=datetime.now(UTC),
                scan_duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                total_vulnerabilities=0,
                errors=errors,
            )
            return ImageScanResponse(
                status=ResponseStatus.DEGRADED,
                message="SBOM vulnerability scan DEGRADED: SBOM generation produced no output",
                result=result,
            )

        # Write SBOM to temp file and scan with Grype
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(sbom_result.raw_sbom)
            sbom_path = f.name

        try:
            vulns = await grype.scan_sbom(sbom_path, timeout=settings.grype_scan_timeout)
        except ScannerExecutionError as e:
            # Scanner ran but errored — return a degraded result, not a clean one.
            errors.append(f"grype SBOM scan errored: {e}")
        finally:
            Path(sbom_path).unlink(missing_ok=True)

        duration = (datetime.now(UTC) - start_time).total_seconds()

        by_severity: dict[str, int] = {}
        for v in vulns:
            sev = v.severity.upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        result = ImageScanResult(
            container_name=container_name,
            image_ref=image_ref,
            scanner="grype",
            scan_timestamp=datetime.now(UTC),
            scan_duration_seconds=duration,
            total_vulnerabilities=len(vulns),
            by_severity=by_severity,
            vulnerabilities=vulns,
            errors=errors,
        )

        return ImageScanResponse(
            status=ResponseStatus.DEGRADED if errors else ResponseStatus.SUCCESS,
            message=(
                f"SBOM vulnerability scan DEGRADED for workspace {container_name}: "
                f"results are partial/incomplete — {len(vulns)} vulnerabilities found "
                f"({len(errors)} scanner error(s))"
                if errors
                else f"SBOM vulnerability scan completed for workspace {container_name}: "
                f"{len(vulns)} vulnerabilities found"
            ),
            result=result,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"SBOM vulnerability scan failed for container '{container_name}': {e}")
        raise internal_error(f"SBOM vulnerability scan failed: {str(e)}")
