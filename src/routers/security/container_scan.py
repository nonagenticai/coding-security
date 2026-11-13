"""Container-scoped security scan + report endpoints.

Covers ``/scan/{container_name}``, ``/scan/{container_name}/quick`` and
``/report/{container_name}`` — the source-code scanning surface that operates
on a registered container's codebase (local or remote).
"""

from __future__ import annotations

import logging
import shutil
import uuid

from fastapi import APIRouter, Depends, HTTPException

from app_factory import get_redis
from auth.tenant import require_tenant
from config.settings import get_settings
from models.errors import (
    Error400Response,
    Error404Response,
    Error500Response,
)
from models.responses import bad_request, internal_error
from models.security_api_models import (
    ContainerSecurityReportResponse,
    ContainerSecurityScanRequest,
    ContainerSecurityScanResponse,
)
from services import scan_queue
from services.scan_runner import _materialize_codebase, _run_scan_bounded
from services.scan_task_store import (
    AsyncScanTaskRecord,
    ScanTaskAccessDenied,
    ScanTaskStore,
    ScanTaskStoreUnavailable,
)
from services.security_scan_service import get_security_scan_service
from utils.container_validation import validate_and_get_container_for_tenant

logger = logging.getLogger(__name__)

router = APIRouter()

# The scan-execution helpers (_materialize_codebase / _run_scan_bounded) live in
# ``services.scan_runner`` so the durable Redis-Streams worker can import them
# without pulling this router (which does a module-level ``from app_factory
# import get_redis``) into an import cycle. They are re-imported above so the
# synchronous endpoints below keep calling them unchanged.


@router.post(
    "/scan/{container_name}",
    response_model=ContainerSecurityScanResponse,
    operation_id="scan_container_security",
    summary="Container Security Scan",
    description="""
    **Perform comprehensive security scan on an entire container.**

    Scans all files within a container for security vulnerabilities including:
    - SQL injection vulnerabilities
    - Cross-site scripting (XSS) issues
    - Command injection flaws
    - Hardcoded credentials and secrets
    - Weak cryptographic implementations
    - Buffer overflow vulnerabilities
    - Authentication and authorization flaws
    - Input validation weaknesses

    Returns detailed scan results with vulnerability counts, severity distribution,
    risk scores, and file-level analysis.
    """,
    responses={
        200: {
            "model": ContainerSecurityScanResponse,
            "description": "Security scan completed successfully",
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid scan parameters",
        },
        404: {
            "model": Error404Response,
            "description": "Container not found",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - security scan failed",
        },
    },
)
async def scan_container_security(
    container_name: str,
    scan_request: ContainerSecurityScanRequest,
    tenant_id: str = Depends(require_tenant),
) -> ContainerSecurityScanResponse:
    """Perform comprehensive security scan on a container."""
    try:
        # Validate container exists
        container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

        # Use path parameter as source of truth; validate if body also provides it
        if (
            scan_request.container_name is not None
            and scan_request.container_name != container_name
        ):
            raise bad_request(
                f"Container name mismatch: path parameter '{container_name}' "
                f"does not match request body '{scan_request.container_name}'"
            )
        scan_request.container_name = container_name

        # Get security scan service
        scan_service = get_security_scan_service()

        # If codebase is remote (K8s container), fetch files to temp dir first.
        materialized = await _materialize_codebase(
            container_info, container_name, tenant_id, scan_request.repo
        )

        try:
            # Perform security scan under an overall deadline.
            scan_result = await _run_scan_bounded(
                scan_service,
                container_info,
                scan_request,
                container_name,
                # Known before the scan runs — the grades must fail closed on it,
                # not be patched after they were computed.
                force_degraded=materialized.incomplete,
            )
            if materialized.incomplete:
                # Fetched fewer files than the repo holds → the scan saw an
                # unknown-incomplete slice; a grade on partial coverage is not
                # trustworthy, so fail honest (degraded).
                scan_result.scan_degraded = True
                scan_result.degraded_reasons.append("codebase fetch was incomplete")
        finally:
            # Clean up temp dir if we created one
            if materialized.temp_dir:
                shutil.rmtree(materialized.temp_dir, ignore_errors=True)

        logger.info(
            f"Security scan {'DEGRADED' if scan_result.scan_degraded else 'completed'} "
            f"for container '{container_name}': "
            f"{scan_result.total_vulnerabilities} vulnerabilities found"
        )

        # Derive the envelope status from scan_degraded. A timed-out / partial /
        # incomplete-coverage scan must NOT report top-level status="success": a
        # consumer keying only on `status` would otherwise read a degraded,
        # possibly-truncated scan as a clean pass.
        return ContainerSecurityScanResponse(
            status="degraded" if scan_result.scan_degraded else "success",
            message=(
                f"Security scan DEGRADED for container '{container_name}': "
                f"results are partial/incomplete — found "
                f"{scan_result.total_vulnerabilities} vulnerabilities "
                f"in {scan_result.total_files_scanned} files scanned so far"
                if scan_result.scan_degraded
                else f"Security scan completed for container '{container_name}': "
                f"found {scan_result.total_vulnerabilities} vulnerabilities "
                f"in {scan_result.total_files_scanned} files"
            ),
            result=scan_result,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Security scan failed for container '{container_name}': {e}")
        raise internal_error(f"Security scan failed: {str(e)}")


@router.post(
    "/scan/{container_name}/async",
    operation_id="scan_container_security_async",
    summary="Async Container Security Scan (task_id + poll)",
    description="""
    **Submit a container security scan as a background task and poll for the result.**

    Additive companion to ``POST /scan/{container_name}``: instead of blocking
    the request for the whole scan (which fails degraded once the sync path hits
    the ~75s upstream gateway budget), this enqueues the scan in a background
    task under a wider wall-clock budget and returns a ``task_id`` immediately.
    Poll ``GET /scan/results/{task_id}`` for ``queued`` / ``running`` /
    ``completed`` / ``failed`` status and the final ``SecurityScanResult``.

    Requires the Redis results store to be online (returns 503 if not).
    """,
    responses={
        200: {"description": "Scan task accepted; poll /scan/results/{task_id}"},
        400: {"model": Error400Response, "description": "Bad request - invalid scan parameters"},
        404: {"model": Error404Response, "description": "Container not found"},
        503: {
            "model": Error500Response,
            "description": "Async scan unavailable - results store offline",
        },
    },
)
async def scan_container_security_async(
    container_name: str,
    scan_request: ContainerSecurityScanRequest,
    tenant_id: str = Depends(require_tenant),
) -> dict:
    """Submit an async (task_id + poll) security scan for a container.

    The scan is executed by the durable Redis-Streams worker (see
    ``services.scan_worker``): this endpoint stamps a ``queued`` record and
    enqueues a job, then returns immediately. Concurrency is bounded by the
    worker's read-loop count and the job survives a worker crash (reclaimed from
    the consumer-group PEL) — neither held for the previous in-process
    ``BackgroundTasks`` execution.
    """
    # Validate container up-front so a bad name fails fast with 404 before we
    # allocate a task_id or enqueue work.
    await validate_and_get_container_for_tenant(container_name, tenant_id)

    # Use path parameter as source of truth; validate if body also provides it.
    if scan_request.container_name is not None and scan_request.container_name != container_name:
        raise bad_request(
            f"Container name mismatch: path parameter '{container_name}' "
            f"does not match request body '{scan_request.container_name}'"
        )
    scan_request.container_name = container_name

    # The async model persists status + result in Redis for the poll endpoint.
    # Evaluate get_redis at call time (not as a default arg) so it stays
    # patchable in tests and the store re-reads it on every write.
    settings = get_settings()
    store = ScanTaskStore(
        key_prefix="security_scan_task:",
        ttl_seconds=settings.security_scan_task_ttl_seconds,
        redis_getter=get_redis,
        stale_after_seconds=settings.security_scan_stale_after_seconds,
    )
    budget = settings.security_async_scan_budget_seconds

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
            detail="async scan unavailable: results store offline",
        )

    # Enqueue the durable job. The full request travels as JSON so the worker
    # reconstructs the exact scan the caller asked for.
    await scan_queue.enqueue(
        get_redis(),
        settings,
        task_id=task_id,
        tenant_id=tenant_id,
        container_name=container_name,
        kind="container",
        budget_seconds=budget,
        scan_request=scan_request.model_dump_json(),
    )
    return {"task_id": task_id, "container_name": container_name, "status": "queued"}


@router.get(
    "/scan/results/{task_id}",
    operation_id="get_security_scan_results",
    summary="Poll Async Container Security Scan Result",
    description="""
    **Retrieve the result of an async security scan by task_id.**

    Returns the stored record (``queued`` / ``running`` / ``completed`` /
    ``failed``) written by ``POST /scan/{container_name}/async``. If the task is
    unknown (still running before the first store, or expired past the 24h TTL),
    returns ``status: pending``. Records are tenant-scoped: a task belonging to
    another tenant returns 404.
    """,
    responses={
        200: {"description": "Task status / result (or pending if unknown)"},
        404: {"model": Error404Response, "description": "Task not found for this tenant"},
    },
)
async def get_security_scan_results(
    task_id: str,
    tenant_id: str = Depends(require_tenant),
) -> dict:
    """Poll for an async security scan result by task_id."""
    settings = get_settings()
    store = ScanTaskStore(
        key_prefix="security_scan_task:",
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
            "message": "Scan is still running or results have expired (24h TTL).",
        }
    return record


@router.get(
    "/report/{container_name}",
    response_model=ContainerSecurityReportResponse,
    operation_id="get_security_report",
    summary="Container Security Report",
    description="""
    **Generate comprehensive security report for a container.**

    Performs a full security scan and generates a detailed report including:
    - Executive summary of security posture
    - Severity distribution (critical, high, medium, low)
    - Vulnerability breakdown by type
    - Security hotspots (files with multiple vulnerabilities)
    - Top priority vulnerabilities to fix
    - Security score and grade (A-F)
    - Actionable recommendations
    - Language-specific vulnerability analysis

    The report provides comprehensive insights for security assessment and remediation planning.
    """,
    responses={
        200: {
            "model": ContainerSecurityReportResponse,
            "description": "Security report generated successfully",
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid report parameters",
        },
        404: {
            "model": Error404Response,
            "description": "Container not found",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - report generation failed",
        },
    },
)
async def get_container_security_report(
    container_name: str,
    include_low_confidence: bool = True,
    max_files: int | None = None,
    tenant_id: str = Depends(require_tenant),
) -> ContainerSecurityReportResponse:
    """Generate comprehensive security report for a container."""
    try:
        # Validate container exists
        container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

        # Get security scan service
        scan_service = get_security_scan_service()

        # Create scan request
        scan_request = ContainerSecurityScanRequest(
            container_name=container_name,
            scan_type="full",
            include_dependencies=True,
            include_low_confidence=include_low_confidence,
            max_files=max_files,
        )

        # If codebase is remote (K8s container), fetch files to temp dir first —
        # without this the report path walks a nonexistent /workspace and grades
        # a fake "A" on zero files.
        materialized = await _materialize_codebase(container_info, container_name, tenant_id)

        try:
            # Perform security scan under an overall deadline.
            scan_result = await _run_scan_bounded(
                scan_service,
                container_info,
                scan_request,
                container_name,
                # Known before the scan runs — the grades must fail closed on it,
                # not be patched after they were computed.
                force_degraded=materialized.incomplete,
            )
            if materialized.incomplete:
                # Partial fetch → grade is over an unknown-incomplete file set.
                scan_result.scan_degraded = True
                scan_result.degraded_reasons.append("codebase fetch was incomplete")

            # Generate comprehensive report
            security_report = await scan_service.generate_security_report(
                container_info,
                scan_result,
            )
        finally:
            if materialized.temp_dir:
                shutil.rmtree(materialized.temp_dir, ignore_errors=True)

        logger.info(
            f"Security report {'DEGRADED' if security_report.scan_degraded else 'generated'} "
            f"for container '{container_name}': "
            f"grade {security_report.security_grade}, "
            f"{security_report.affected_files_count} affected files"
        )

        return ContainerSecurityReportResponse(
            status="degraded" if security_report.scan_degraded else "success",
            message=(
                f"Security report DEGRADED for container '{container_name}': "
                f"results are partial/incomplete — Security Grade "
                f"{security_report.security_grade}, "
                f"{security_report.affected_files_count} files with vulnerabilities"
                if security_report.scan_degraded
                else f"Security report generated for container '{container_name}': "
                f"Security Grade {security_report.security_grade}, "
                f"{security_report.affected_files_count} files with vulnerabilities"
            ),
            report=security_report,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Security report generation failed for container '{container_name}': {e}")
        raise internal_error(f"Security report generation failed: {str(e)}")


@router.post(
    "/scan/{container_name}/quick",
    response_model=ContainerSecurityScanResponse,
    operation_id="quick_scan_container_security",
    summary="Quick Container Security Scan",
    description="""
    **Perform quick security scan on a container with limited scope.**

    Performs a faster security scan with the following optimizations:
    - Scans up to 100 files by default
    - Focuses on high and critical severity vulnerabilities
    - Excludes low confidence findings
    - Ideal for CI/CD pipelines and quick assessments

    Returns essential security findings without detailed analysis.
    """,
    responses={
        200: {
            "model": ContainerSecurityScanResponse,
            "description": "Quick security scan completed successfully",
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid scan parameters",
        },
        404: {
            "model": Error404Response,
            "description": "Container not found",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - security scan failed",
        },
    },
)
async def quick_scan_container_security(
    container_name: str,
    max_files: int = 100,
    tenant_id: str = Depends(require_tenant),
) -> ContainerSecurityScanResponse:
    """Perform quick security scan on a container."""
    try:
        # Validate container exists
        container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

        # Get security scan service
        scan_service = get_security_scan_service()

        # Create quick scan request
        scan_request = ContainerSecurityScanRequest(
            container_name=container_name,
            scan_type="quick",
            include_dependencies=False,
            severity_filter=["critical", "high"],
            include_low_confidence=False,
            max_files=max_files,
        )

        # If codebase is remote (K8s container), fetch files to temp dir first —
        # without this the quick path walks a nonexistent /workspace and grades
        # a fake "A" on zero files.
        materialized = await _materialize_codebase(container_info, container_name, tenant_id)

        try:
            # Perform security scan under an overall deadline.
            scan_result = await _run_scan_bounded(
                scan_service,
                container_info,
                scan_request,
                container_name,
                # Known before the scan runs — the grades must fail closed on it,
                # not be patched after they were computed.
                force_degraded=materialized.incomplete,
            )
            if materialized.incomplete:
                # Partial fetch → grade is over an unknown-incomplete file set.
                scan_result.scan_degraded = True
                scan_result.degraded_reasons.append("codebase fetch was incomplete")
        finally:
            if materialized.temp_dir:
                shutil.rmtree(materialized.temp_dir, ignore_errors=True)

        logger.info(
            f"Quick security scan {'DEGRADED' if scan_result.scan_degraded else 'completed'} "
            f"for container '{container_name}': "
            f"{scan_result.total_vulnerabilities} high/critical vulnerabilities found"
        )

        return ContainerSecurityScanResponse(
            status="degraded" if scan_result.scan_degraded else "success",
            message=(
                f"Quick security scan DEGRADED for container '{container_name}': "
                f"results are partial/incomplete — found "
                f"{scan_result.total_vulnerabilities} high/critical vulnerabilities "
                f"in {scan_result.total_files_scanned} files scanned so far"
                if scan_result.scan_degraded
                else f"Quick security scan completed for container '{container_name}': "
                f"found {scan_result.total_vulnerabilities} high/critical vulnerabilities "
                f"in {scan_result.total_files_scanned} files"
            ),
            result=scan_result,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Quick security scan failed for container '{container_name}': {e}")
        raise internal_error(f"Quick security scan failed: {str(e)}")
