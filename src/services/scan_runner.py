"""Scan-execution helpers + durable-worker runner bodies.

This module owns the scan-execution machinery that both the synchronous scan
endpoints (``routers/security/container_scan.py``, ``routers/dependencies.py``)
and the durable Redis-Streams worker (``services/scan_worker.py``) need:

* ``_materialize_codebase`` / ``_run_scan_bounded`` — container-security source
  fetch + bounded scan.
* ``resolve_repo_path`` / ``fetch_manifests_to_tempdir`` — dependency-manifest
  fetch.
* ``run_container_scan`` / ``run_dependency_scan`` — the relocated async-scan
  ``scan_task`` bodies. They own the ``running`` / ``completed`` / ``failed``
  ``ScanTaskStore`` writes exactly as the in-process BackgroundTask version did;
  the worker calls them per dequeued job.

It lives under ``services/`` (not ``routers/``) so the worker imports it without
pulling in a router that does a module-level ``from app_factory import
get_redis`` — that would create an import cycle when the worker is wired into the
lifespan. The synchronous endpoints import the helpers back from here, keeping
their behaviour unchanged.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import random
import shutil
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from coding_client.clients import CodingWorkspacesClient, ServiceError
from fastapi import HTTPException

from clients.outbound import sibling_headers
from config.settings import get_settings
from models.architecture_models import mark_degraded
from models.container_models import ContainerInfo
from models.responses import internal_error
from models.security_api_models import ContainerSecurityScanRequest
from models.workspace_repos import (
    PRIMARY_REPO,
    hidden_exclude_args,
    normalize_repo,
    repo_root,
)
from services.scan_task_store import AsyncScanTaskRecord
from services.security_detector import PartialAnalysisState
from services.security_scan_service import (
    SecurityScanService,
    get_security_scan_service,
)
from utils.container_validation import validate_and_get_container_for_tenant

if TYPE_CHECKING:
    from config.settings import Settings
    from models.security_api_models import SecurityScanResult
    from services.scan_queue import ScanJob
    from services.scan_task_store import ScanTaskStore

logger = logging.getLogger(__name__)

# Remote-codebase bulk download tuning (E3.15/E3.16). The container-scan path
# fetches the workspace from the coding-containers /exec endpoint. Since E3.15
# added IaC patterns (*.yaml/*.json/*.tf/...), the file set can be hundreds of
# files; a `cat` per file blew past the httpx budget and the scan timed out
# upstream. We instead read many files per /exec round-trip via a whitelisted
# `python -c` reader that returns a {path: content} JSON map.
_DOWNLOAD_CHUNK = 400  # files per /exec round-trip (bounds argv size)
_MAX_FILE_BYTES = 5 * 1024 * 1024  # skip individual files larger than this
#: Attempts per download chunk: the first try plus two retries. A dropped chunk
#: is far more often a transient transport failure than a real coverage gap, and
#: a full re-scan costs minutes. The `incomplete` flag still marks the fetch
#: when every attempt fails.
_FETCH_CHUNK_ATTEMPTS = 3
#: Base for the jittered exponential backoff between attempts (seconds).
_FETCH_RETRY_BASE_SECONDS = 0.2


def _is_dotenv_path(path: str) -> bool:
    """True for ``.env`` / ``.env.*`` — the dotenv files secret engines target."""
    name = path.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.")


# Manifest + lockfiles the dependency extractor cares about.
# ⛔ ONE list: the dependency fetch and the workspace SBOM must catalog the SAME
# formats. They were two lists, and the dependency one omitted go.sum, pom.xml,
# composer.lock, yarn/pnpm and the rest — so a remote repo holding only one of
# those was fetched as an EMPTY tempdir and scanned clean. ``_MANIFEST_FILES``
# is assigned from ``_WORKSPACE_DEPENDENCY_MANIFESTS`` below (after it is
# defined), so a format added for one path can no longer be missing from the
# other. We only pull these from the remote container — a full-repo copy is
# wasteful for a scan that reads a handful of well-known files.
_MANIFEST_SUBDIR_GLOB = "requirements"  # matches ``repo.glob("requirements/*.txt")``


# What the workspace fetch pulls for a source scan / ``syft dir:`` SBOM.
# Code + IaC manifests (so the trivy-config iac_scanner has input) + every
# dependency manifest/lockfile syft catalogs. Without the lockfiles a workspace
# SBOM saw only requirements.txt/package.json and silently missed whole
# ecosystems (Go, Rust, Java, .NET, Ruby, PHP, resolved Python/JS trees).
_WORKSPACE_SOURCE_PATTERNS: tuple[str, ...] = (
    "*.py",
    "*.java",
    "*.js",
    "*.jsx",
    "*.ts",
    "*.tsx",
    "*.mjs",
    "*.cjs",
    "*.vue",
    "*.svelte",
    "*.go",
    "*.rs",
    "*.cs",
    "*.cpp",
    "*.c",
    "*.rb",
    "Dockerfile",
    "*.tf",
    "*.tofu",
    "*.yaml",
    "*.yml",
    "*.json",
    "*.dockerfile",
    "Containerfile",
    # Dotenv files have no suffix; name-matched so the secret engines see them
    # (``hidden_exclude_args`` keeps them in the dot-space allowlist).
    ".env",
    ".env.*",
)
_WORKSPACE_DEPENDENCY_MANIFESTS: tuple[str, ...] = (
    "requirements*.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
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
    "*.csproj",
    "packages.lock.json",
    "packages.config",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
)
# The dependency scan fetches exactly what the workspace scan catalogs (see the
# note above ``_MANIFEST_SUBDIR_GLOB``).
_MANIFEST_FILES: tuple[str, ...] = _WORKSPACE_DEPENDENCY_MANIFESTS


def _is_dependency_manifest(path: str) -> bool:
    """True when *path*'s basename is one of the dependency manifests above."""
    base = os.path.basename(path)
    return any(fnmatch.fnmatchcase(base, pattern) for pattern in _WORKSPACE_DEPENDENCY_MANIFESTS)


def _workspace_find_command(remote_root: str) -> list[str]:
    """``find`` over *remote_root* for source, IaC and dependency manifests.

    Hidden components are excluded only BELOW *remote_root* (see
    ``hidden_exclude_args``): for the primary repo that still drops ``.repos/``,
    ``.git`` etc.; for ``.repos/<name>`` it keeps the checkout scannable.
    """
    patterns = dict.fromkeys(_WORKSPACE_SOURCE_PATTERNS + _WORKSPACE_DEPENDENCY_MANIFESTS)
    name_clauses: list[str] = []
    for pattern in patterns:
        if name_clauses:
            name_clauses.append("-o")
        name_clauses += ["-name", pattern]
    return [
        "find",
        remote_root,
        "-type",
        "f",
        "(",
        *name_clauses,
        ")",
        *hidden_exclude_args(remote_root),
        "-not",
        "-path",
        "*/node_modules/*",
        "-not",
        "-path",
        "*/__pycache__/*",
    ]


# ===========================================================================
# Container-security source fetch + bounded scan
# ===========================================================================


@dataclass(slots=True)
class _MaterializeResult:
    """Outcome of fetching a remote container workspace to local disk.

    ``temp_dir`` is the tempdir to clean up (``None`` when the codebase was
    already local — nothing to remove). ``incomplete`` is True when the fetch
    could not retrieve the full file set the ``find`` listed — a failed
    download chunk, a path that would escape the tempdir (traversal) and was
    skipped, or a DEPENDENCY MANIFEST skipped for exceeding
    ``_MAX_FILE_BYTES``. An incomplete fetch means the scan examined LESS than
    the repo contains, so its grade is not trustworthy and the caller marks the
    result ``scan_degraded=True``. (A non-manifest source file over the bound
    is a deliberate, documented size limit, not a coverage gap.)
    """

    temp_dir: str | None
    incomplete: bool = False


async def _materialize_codebase(
    container_info: ContainerInfo,
    container_name: str,
    tenant_id: str,
    repo: str | None = None,
) -> _MaterializeResult:
    """Download a remote container codebase into a local tempdir for scanning.

    If ``container_info.codebase_path`` already exists locally, returns a result
    with ``temp_dir=None`` (nothing to clean up). Otherwise fetches the
    workspace source + IaC manifests from the coding-containers ``/exec``
    endpoint into a tempdir, rewrites ``container_info.codebase_path`` to point
    at it, and returns the tempdir path in ``temp_dir`` — the caller MUST
    ``shutil.rmtree`` it when done.

    ``result.incomplete`` is set True when a download chunk fails or a file
    would escape the tempdir (traversal, skipped) — a partial fetch means the
    scan saw less than the repo holds, so the caller degrades the grade rather
    than trusting a scan of an unknown-incomplete file set.
    """
    canonical_repo = normalize_repo(repo)
    if os.path.isdir(container_info.codebase_path):
        # Local codebase (legacy docker mode / tests): move the scan root to the
        # selected checkout. The local walk skips hidden dirs, so the primary
        # root already excludes .repos/.
        local_root = repo_root(container_info.codebase_path, canonical_repo)
        if canonical_repo != PRIMARY_REPO:
            if not os.path.isdir(local_root):
                raise HTTPException(
                    status_code=404,
                    detail=f"repo '{canonical_repo}' not found in workspace '{container_name}'",
                )
            container_info.codebase_path = local_root
        return _MaterializeResult(temp_dir=None)
    remote_root = repo_root(get_settings().workspace_root, canonical_repo)

    logger.info(
        "Codebase path %s not local, fetching from containers API for %s",
        container_info.codebase_path,
        container_name,
    )
    containers_url = get_settings().containers_service_url
    fetch_timeout = get_settings().security_fetch_timeout_seconds
    # Built BEFORE the tempdir: the constructor rejects an empty base_url, and
    # raising after mkdtemp would leak the directory.
    #
    # Scans are long-running and this fetch budget is settings-driven. The SDK
    # fixes its timeout at CONSTRUCTION, so it must be threaded through here —
    # a naive swap would silently truncate every workspace fetch at the SDK's
    # 30s default.
    hc = CodingWorkspacesClient(base_url=containers_url, timeout=fetch_timeout)
    temp_dir = tempfile.mkdtemp(prefix=f"scan-{container_name}-")
    incomplete = False
    find_payload: Any = None
    find_ok = True
    try:
        try:
            # List all code + IaC files.
            find_payload = await hc.exec(
                container_name,
                headers=sibling_headers(
                    tenant_id, operation=f"containers exec find {container_name}"
                ),
                command=_workspace_find_command(remote_root),
            )
        except ServiceError as exc:
            # The find itself failed — we have no file list at all. Leave the
            # tempdir empty (the scan sees 0 files → honest grade F) and flag
            # the fetch as incomplete for the degraded marker. The SDK raises
            # on >=400 where raw httpx returned the response, so this handler
            # replaces the old ``else`` branch — same log, same outcome, and
            # crucially still NOT a raise.
            logger.error(
                "find over /workspace failed for %s (HTTP %s); scan will be degraded",
                container_name,
                exc.status_code,
            )
            incomplete = True
            find_ok = False

        if (
            find_ok
            and canonical_repo != PRIMARY_REPO
            and isinstance(find_payload, dict)
            and find_payload.get("exit_code") not in (0, None)
            and not (find_payload.get("stdout") or "").strip()
        ):
            # `find <ws>/.repos/<name>` on a checkout that does not exist: a
            # wrong selector, not an empty repo — answer 404 rather than grade F.
            raise HTTPException(
                status_code=404,
                detail=f"repo '{canonical_repo}' not found in workspace '{container_name}'",
            )
        if find_ok and find_payload.get("truncated"):
            # A clipped listing names fewer files than the repo holds.
            incomplete = True
        if find_ok:
            file_list = [
                f.strip() for f in find_payload.get("stdout", "").strip().split("\n") if f.strip()
            ]
            # Bulk-download in a few /exec round-trips instead of one
            # `cat` per file. The IaC patterns above can match
            # hundreds of files; a per-file loop exceeds the httpx
            # budget and the scan times out upstream (E3.15). A
            # whitelisted `python -c` reader returns a {path: content}
            # JSON map per chunk -> O(files / chunk) round-trips,
            # seconds total. `python` is allowed by the containers
            # /exec command whitelist; `tar`/`base64` are not.
            # argv[1] = max bytes; argv[2:] = file paths to read.
            reader = (
                "import sys, json, os\n"
                "limit = int(sys.argv[1])\n"
                "out = {}\n"
                "skipped = []\n"
                "for p in sys.argv[2:]:\n"
                "    try:\n"
                "        if os.path.getsize(p) > limit:\n"
                "            skipped.append(p)\n"
                "            continue\n"
                "        with open(p, 'r', errors='replace') as fh:\n"
                "            out[p] = fh.read()\n"
                "    except Exception:\n"
                "        skipped.append(p)\n"
                "sys.stdout.write(json.dumps({'files': out, 'skipped': skipped}))\n"
            )
            downloaded = 0
            temp_root = os.path.realpath(temp_dir)
            # A work queue, not a fixed range: coding-containers caps /exec stdout
            # (1 MiB, measured 2026-11-04) and sets ``truncated`` when it clips. A
            # clipped chunk is invalid JSON, so a repo whose 400-file chunk exceeds
            # the cap (nonagenticai/openplanner: 2.4 MB) used to drop EVERY chunk
            # and scan 0 files. A truncated chunk is split in half and re-queued
            # until it fits; a single file whose JSON alone exceeds the cap is a
            # real coverage gap and marks the fetch incomplete.
            pending = [
                file_list[start : start + _DOWNLOAD_CHUNK]
                for start in range(0, len(file_list), _DOWNLOAD_CHUNK)
            ]

            def _split_chunk(chunk: list[str], reason: str) -> bool:
                """Re-queue two halves of *chunk*; on a single file, record the gap.

                Returns True when the caller should continue with the smaller
                chunks, False when this is a real coverage gap (one file) that
                must mark the fetch incomplete. Bounded: 1-element chunks take
                the False branch, so the split cannot loop.
                """
                if len(chunk) > 1:
                    mid = len(chunk) // 2
                    pending[0:0] = [chunk[:mid], chunk[mid:]]
                    return True
                logger.warning("File %s: %s; not scanned", chunk[0], reason)
                return False

            while pending:
                chunk = pending.pop(0)
                read_payload = None
                chunk_failed = False
                for attempt in range(_FETCH_CHUNK_ATTEMPTS):
                    try:
                        # ``timeout`` here is the CONTAINER-side command budget
                        # in the request body — unrelated to the client's HTTP
                        # timeout.
                        read_payload = await hc.exec(
                            container_name,
                            headers=sibling_headers(
                                tenant_id, operation=f"containers exec read {container_name}"
                            ),
                            command=[
                                "python",
                                "-c",
                                reader,
                                str(_MAX_FILE_BYTES),
                                *chunk,
                            ],
                            timeout=120,
                        )
                        break
                    except ServiceError as exc:
                        # A dropped chunk is retried before it is believed: a
                        # transient transport failure should not cost the repo a
                        # chunk and force a full re-scan. Only after every
                        # attempt fails is it the coverage gap it looks like.
                        # The SDK RAISES where raw httpx returned a non-200, so
                        # this must be caught per-chunk: letting it escape would
                        # abort the whole fetch into the 500 below and destroy
                        # the partial-download degrade. Only ServiceError is
                        # caught here — a transport error still propagates to the
                        # outer handler, exactly as it did before.
                        if attempt + 1 >= _FETCH_CHUNK_ATTEMPTS:
                            logger.warning(
                                "download chunk of %d file(s) failed after %d attempts "
                                "(%s: %s); marking the fetch incomplete",
                                len(chunk),
                                _FETCH_CHUNK_ATTEMPTS,
                                type(exc).__name__,
                                exc,
                            )
                            chunk_failed = True
                            break
                        delay = _FETCH_RETRY_BASE_SECONDS * (2**attempt) * (0.5 + random.random())
                        logger.info(
                            "download chunk of %d file(s) failed (%s: %s); retry %d/%d in %.2fs",
                            len(chunk),
                            type(exc).__name__,
                            exc,
                            attempt + 1,
                            _FETCH_CHUNK_ATTEMPTS - 1,
                            delay,
                        )
                        await asyncio.sleep(delay)
                if chunk_failed:
                    incomplete = True
                    continue
                # A chunk the transport answers with an empty body (the SDK
                # returns ``None``) or with a body that is not the reader's JSON
                # is a response lost in transit, not proof that its files cannot
                # be read: split it and re-read smaller, exactly like a clipped
                # one. Both paths used to set ``incomplete`` silently — measured
                # on the openplanner branch scan, where that lost ~170 of 1052
                # files with no line in the log to say which or why.
                if read_payload is None:
                    if not _split_chunk(chunk, "empty response from the containers exec"):
                        incomplete = True
                    continue
                if isinstance(read_payload, dict) and read_payload.get("truncated"):
                    if not _split_chunk(chunk, "exceeds the /exec output cap"):
                        incomplete = True
                    continue
                try:
                    payload = json.loads(read_payload.get("stdout") or "{}")
                except (ValueError, TypeError, AttributeError) as exc:
                    # AttributeError covers a payload shape the SDK returns for
                    # a 204/empty body that is not ``None``. Same recovery: the
                    # chunk is bisected before it is believed lost.
                    if not _split_chunk(chunk, f"unparseable /exec output ({type(exc).__name__})"):
                        incomplete = True
                    continue
                files = payload
                skipped: list[str] = []
                if isinstance(payload, dict) and isinstance(payload.get("files"), dict):
                    files = payload["files"]
                    raw_skipped = payload.get("skipped")
                    skipped = (
                        [path for path in raw_skipped if isinstance(path, str)]
                        if isinstance(raw_skipped, list)
                        else []
                    )
                # A reader that omits a file WITHOUT naming it (an older reader,
                # or a path dropped before the size check) would otherwise look
                # like a clean fetch: recover the omitted paths from the chunk.
                named = set(skipped)
                skipped.extend(p for p in chunk if p not in files and p not in named)
                # A skipped ordinary source file is the documented per-file size
                # bound. Two kinds are NOT that bound: a dependency
                # manifest/lockfile (its packages never reach the SBOM or the
                # dependency scan) and a dotenv file (the secret engines never
                # examined it). Either way, the scan saw less than the repo
                # holds and must degrade.
                for remote_path in skipped:
                    if _is_dependency_manifest(remote_path):
                        logger.warning(
                            "Dependency manifest %s was skipped (size/read failure); "
                            "scan will be degraded",
                            remote_path,
                        )
                        incomplete = True
                    elif _is_dotenv_path(remote_path):
                        logger.warning(
                            "Dotenv file %s was skipped (unreadable or over %d bytes); "
                            "scan will be degraded",
                            remote_path,
                            _MAX_FILE_BYTES,
                        )
                        incomplete = True
                for remote_path, content in files.items():
                    # Harden against path traversal: a scanned container
                    # controls its own filesystem, so a crafted path like
                    # ``/workspace/../../etc/x`` must NOT let a write escape
                    # the tempdir and clobber the coding-security pod. Strip
                    # the workspace prefix, then confirm the resolved target
                    # stays under the tempdir before writing.
                    rel_path = remote_path.removeprefix(remote_root + "/").lstrip("/")
                    local_path = os.path.join(temp_dir, rel_path)
                    if os.path.commonpath([os.path.realpath(local_path), temp_root]) != temp_root:
                        logger.warning(
                            "Skipping file with out-of-tree path %s (traversal)",
                            remote_path,
                        )
                        incomplete = True
                        continue
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    with open(local_path, "w") as wf:
                        wf.write(content)
                    downloaded += 1

            logger.info("Downloaded %d files to %s", downloaded, temp_dir)
            container_info.codebase_path = temp_dir
    except HTTPException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as fetch_err:
        logger.error("Failed to fetch remote files: %s", fetch_err)
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise internal_error(f"Cannot access container files: {fetch_err}")
    except BaseException:
        # Cancellation (client disconnect, scan deadline): the caller never gets
        # the tempdir, so it is removed here.
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    finally:
        # The SDK caches its httpx.AsyncClient on the instance, so unlike the
        # previous ``async with httpx.AsyncClient(...)`` it is not closed for us.
        await hc.close()

    return _MaterializeResult(temp_dir=temp_dir, incomplete=incomplete)


async def _run_scan_bounded(
    scan_service: SecurityScanService,
    container_info: ContainerInfo,
    scan_request: ContainerSecurityScanRequest,
    container_name: str,
    budget_seconds: float | None = None,
    force_degraded: bool = False,
) -> SecurityScanResult:
    """Run ``scan_container`` under an overall wall-clock deadline.

    On timeout, returns a degraded result built from whatever findings the
    completed engines already accumulated (via the caller-held ``partial``),
    flagged ``scan_degraded`` — rather than hanging past the upstream gateway
    budget OR discarding real vulnerabilities. Honest AND functional: not a fake
    "A", not an infinite hang, and not a fake "F, 0 vulns" that throws away the
    findings the scan actually made before the deadline.

    ``budget_seconds`` lets the async (task_id + poll) submit path run under the
    wider ``security_async_scan_budget_seconds`` instead of the sync-path
    ``security_scan_budget_seconds``. The three sync callers pass nothing and
    keep the original behaviour.
    """
    budget = (
        budget_seconds
        if budget_seconds is not None
        else get_settings().security_scan_budget_seconds
    )
    # Accumulator the scan fills incrementally; because we (the caller) hold it,
    # it survives the coroutine cancellation asyncio.wait_for raises on timeout.
    partial = PartialAnalysisState()
    # Absolute monotonic deadline handed to the engines: the base-image scan
    # budgets itself against what is actually left of this budget, so it can
    # never be the reason the whole scan overruns.
    deadline = asyncio.get_running_loop().time() + budget
    try:
        return await asyncio.wait_for(
            scan_service.scan_container(
                container_info,
                scan_request,
                partial=partial,
                deadline=deadline,
                force_degraded=force_degraded,
            ),
            timeout=budget,
        )
    except TimeoutError:
        logger.error(
            "Security scan for '%s' exceeded %.0fs budget; returning degraded "
            "result from %d partial finding(s) across %d file(s) examined",
            container_name,
            budget,
            len(partial.regex_matches) + len(partial.external_matches),
            len(partial.parsed_files),
        )
        return await scan_service.build_partial_result(container_info, partial, budget)


# ===========================================================================
# Dependency-manifest fetch
# ===========================================================================


@dataclass(frozen=True)
class ResolvedRepo:
    """A resolved codebase path plus whether the manifest fetch was complete.

    ``incomplete`` is True when the remote manifest fetch dropped a file (a
    failed ``cat``, or a path that would escape the tempdir and was skipped) —
    the scan then examined LESS than the repo holds, so the caller marks the
    resulting report ``scan_degraded``. A local codebase is always complete.
    """

    path: Path
    incomplete: bool


def _containers_service_url() -> str:
    """Resolve coding-containers base URL from settings (env-only, no fallback)."""
    return get_settings().containers_service_url


async def fetch_manifests_to_tempdir(
    container_name: str,
    remote_root: str,
    tenant_id: str,
) -> tuple[Path, bool]:
    """Download dependency manifest files from a remote container to a tempdir.

    Uses the coding-containers ``/api/workspaces/{name}/exec`` endpoint
    (``find`` + ``cat``) to pull only the manifest files the extractor reads.

    Returns ``(tempdir, incomplete)`` where ``incomplete`` is True when a
    ``cat`` failed or a manifest path would escape the tempdir (traversal,
    skipped) — a partial fetch means the scan sees fewer files than the repo
    holds, so the caller degrades the resulting report. The caller is
    responsible for cleanup of the tempdir.
    """
    url = _containers_service_url()
    # The 60s budget is carried over verbatim from the previous raw-httpx call;
    # the SDK fixes its timeout at construction so it must be passed explicitly.
    # Built BEFORE the tempdir: the constructor rejects an empty base_url, and
    # raising after mkdtemp would leak the directory.
    client = CodingWorkspacesClient(base_url=url, timeout=60.0)
    temp_dir = Path(tempfile.mkdtemp(prefix=f"dep-scan-{container_name}-"))
    incomplete = False

    # Build a ``find`` invocation that matches every manifest filename at any
    # depth, excluding common vendor/cache dirs. Combined ``-o`` clauses must
    # be parenthesised to bind tighter than the subsequent ``-not -path``.
    name_expr: list[str] = []
    for i, fname in enumerate(_MANIFEST_FILES):
        if i > 0:
            name_expr.append("-o")
        name_expr.extend(["-name", fname])
    # Also include ``requirements/*.txt`` — the extractor globs that subdir.
    name_expr.extend(["-o", "-name", "*.txt"])  # filtered below by path prefix

    find_cmd: list[str] = [
        "find",
        remote_root,
        "-type",
        "f",
        "(",
        *name_expr,
        ")",
        # Anchored at remote_root so a `.repos/<name>` root is not itself
        # excluded as a hidden path (the primary root still skips .repos/).
        *hidden_exclude_args(remote_root),
        "-not",
        "-path",
        "*/node_modules/*",
        "-not",
        "-path",
        "*/__pycache__/*",
        "-not",
        "-path",
        "*/venv/*",
        "-not",
        "-path",
        "*/.venv/*",
    ]

    try:
        try:
            find_payload = await client.exec(
                container_name,
                headers=sibling_headers(
                    tenant_id, operation=f"containers exec find {container_name}"
                ),
                command=find_cmd,
            )
        except ServiceError as exc:
            # The SDK raises on >=400 where raw httpx returned the response;
            # this replaces the old ``if find_resp.status_code != 200`` branch
            # and keeps the same RuntimeError shape the caller maps to a 502.
            raise RuntimeError(
                f"containers exec (find) returned HTTP {exc.status_code}: {str(exc.body)[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"containers exec (find) failed: {exc}") from exc

        stdout = find_payload.get("stdout", "") or ""
        remote_files = [line.strip() for line in stdout.splitlines() if line.strip()]
        if find_payload.get("truncated"):
            # A clipped listing names fewer manifests than the repo holds.
            incomplete = True

        # Filter bare ``*.txt`` matches: only keep requirements.txt or files
        # under a ``requirements/`` directory. Everything non-manifest is dropped.
        filtered: list[str] = []
        for rp in remote_files:
            base = os.path.basename(rp)
            # Glob-aware (``*.csproj`` / ``requirements*.txt``): an exact-name
            # test silently dropped every manifest pattern added as a glob.
            if any(fnmatch.fnmatchcase(base, pattern) for pattern in _MANIFEST_FILES):
                filtered.append(rp)
            elif base.endswith(".txt") and f"/{_MANIFEST_SUBDIR_GLOB}/" in rp:
                filtered.append(rp)

        if not filtered:
            logger.info(
                "No dependency manifest files found in container %s under %s",
                container_name,
                remote_root,
            )
            return temp_dir, False

        remote_root_rstrip = remote_root.rstrip("/") + "/"
        for remote_path in filtered:
            rel = (
                remote_path[len(remote_root_rstrip) :]
                if remote_path.startswith(remote_root_rstrip)
                else os.path.basename(remote_path)
            )
            try:
                cat_payload = await client.exec(
                    container_name,
                    headers=sibling_headers(
                        tenant_id, operation=f"containers exec cat {container_name}"
                    ),
                    command=["cat", remote_path],
                )
            except ServiceError as exc:
                # Was ``if cat_resp.status_code != 200``. The SDK raises instead
                # of returning, so this is caught PER MANIFEST: the loop must
                # continue and degrade, never abort the whole fetch.
                logger.warning("cat returned HTTP %d for %s", exc.status_code, remote_path)
                incomplete = True
                continue
            except httpx.HTTPError as exc:
                # A dropped manifest means we scan fewer files than the repo
                # holds — coverage gap, not a clean scan.
                logger.warning("cat failed for %s: %s", remote_path, exc)
                incomplete = True
                continue
            if cat_payload.get("truncated"):
                # A clipped manifest is not that manifest: skip it, degrade.
                logger.warning("cat output truncated for %s", remote_path)
                incomplete = True
                continue
            content = cat_payload.get("stdout", "") or ""
            local_path = temp_dir / rel
            # Harden against path traversal: a scanned container controls its own
            # filesystem, so a crafted path must NOT let a write escape the
            # tempdir and clobber the coding-security pod.
            temp_root = os.path.realpath(str(temp_dir))
            if os.path.commonpath([os.path.realpath(str(local_path)), temp_root]) != temp_root:
                logger.warning("Skipping out-of-tree manifest path %s (traversal)", remote_path)
                incomplete = True
                continue
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_text(content, encoding="utf-8")

        logger.info(
            "Fetched %d manifest file(s) from container %s into %s",
            len(filtered),
            container_name,
            temp_dir,
        )
    except BaseException:
        # Any failure or cancellation before the tempdir is handed back: the
        # caller never sees it, so it is removed here.
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    finally:
        # The SDK caches its httpx.AsyncClient on the instance, so unlike the
        # previous ``async with httpx.AsyncClient(...)`` it is not closed for us.
        await client.close()

    return temp_dir, incomplete


@asynccontextmanager
async def resolve_repo_path(container_name: str, tenant_id: str) -> AsyncGenerator[ResolvedRepo]:
    """Yield a ``ResolvedRepo`` for the container's codebase manifests.

    If the container's ``codebase_path`` is locally accessible (legacy Docker
    hostPath mode), yield it directly (``incomplete=False``). Otherwise (k8s
    mode where the codebase only exists inside the pod at ``/workspace``), fetch
    the manifest files via the coding-containers exec API into a tempdir and
    yield that, carrying the fetch's ``incomplete`` flag so the caller can mark
    a partially-fetched scan degraded.

    Cleans up any tempdir on exit.
    """
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)
    codebase_path = container_info.codebase_path
    local_path = Path(codebase_path)

    if local_path.is_dir():
        yield ResolvedRepo(local_path, False)
        return

    logger.info(
        "Codebase path %s not local for container %s; fetching manifests via containers API",
        codebase_path,
        container_name,
    )
    try:
        temp_dir, incomplete = await fetch_manifests_to_tempdir(
            container_name, codebase_path, tenant_id
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot access container files via coding-containers: {exc}",
        ) from exc
    try:
        yield ResolvedRepo(temp_dir, incomplete)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ===========================================================================
# Durable-worker runner bodies (relocated async scan_task closures)
# ===========================================================================


async def run_container_scan(job: ScanJob, store: ScanTaskStore, settings: Settings) -> None:
    """Execute a container-security scan job to a terminal ``ScanTaskStore`` write.

    This is the relocated body of the old ``scan_container_security_async`` inner
    ``scan_task`` closure: it stamps ``running``, materialises the codebase,
    re-stamps a ``running`` heartbeat after the fetch phase, runs the bounded
    scan, and writes ``completed`` (or ``failed`` on any exception). The worker
    XACKs only after this returns (a terminal store write happened). A shutdown
    ``CancelledError`` propagates un-acked so the job is reclaimed.
    """
    container_name = job.container_name
    tenant_id = job.tenant_id
    try:
        container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)
        scan_request = ContainerSecurityScanRequest.model_validate_json(job.scan_request)
        scan_request.container_name = container_name

        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="running",
                tenant_id=tenant_id,
                extra={"container_name": container_name},
            )
        )
        scan_service = get_security_scan_service()

        # If codebase is remote (K8s container), fetch files to temp dir first.
        materialized = await _materialize_codebase(
            container_info, container_name, tenant_id, scan_request.repo
        )
        # Heartbeat: the fetch above is a multi-round-trip phase OUTSIDE the scan
        # budget; re-stamp running so a poll can tell a live scan (fresh
        # updated_at) from a worker that died mid-fetch (stale → failed).
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="running",
                tenant_id=tenant_id,
                extra={"container_name": container_name},
            )
        )
        try:
            result = await _run_scan_bounded(
                scan_service,
                container_info,
                scan_request,
                container_name,
                budget_seconds=job.budget_seconds,
                # The fetch already happened, so the coverage answer is known
                # BEFORE the scan runs: hand it to the assembler so the grades
                # fail closed. Setting scan_degraded afterwards leaves
                # security_grade/code_grade/base_image_grade computed over an
                # unknown-incomplete file set (measured: grade D with no
                # Dockerfiles fetched and base_image_grade A).
                force_degraded=materialized.incomplete,
            )
            if materialized.incomplete:
                # force_degraded already made the assembler grade F; the flag
                # stays explicit so a service layer that ignores it still
                # reports the scan degraded.
                result.scan_degraded = True
                result.degraded_reasons.append("codebase fetch was incomplete")
        finally:
            if materialized.temp_dir:
                shutil.rmtree(materialized.temp_dir, ignore_errors=True)

        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="completed",
                tenant_id=tenant_id,
                scan_degraded=result.scan_degraded,
                result=result.model_dump(mode="json"),
                extra={"container_name": container_name},
            )
        )
    except asyncio.CancelledError:
        # Shutdown: leave the job un-acked so it is reclaimed and re-run.
        raise
    except Exception as exc:
        logger.exception("Async security scan failed for '%s': %s", container_name, exc)
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="failed",
                tenant_id=tenant_id,
                error=str(exc),
                extra={"container_name": container_name},
            )
        )


async def run_dependency_scan(job: ScanJob, store: ScanTaskStore, settings: Settings) -> None:
    """Execute a dependency scan job to a terminal ``ScanTaskStore`` write.

    Relocated body of the old ``scan_container_dependencies_async`` inner
    ``scan_task`` closure: stamps ``running``, resolves the repo manifests,
    re-stamps a ``running`` heartbeat after the fetch, runs the analyzer under
    the job budget, and writes ``completed`` / ``failed``. The worker uses a
    fresh ``ArchitectureDependencyAnalyzer`` per job (empty cache = genuinely
    fresh scan), so no explicit cache-clear is needed.
    """
    from services.dependency_analyzer import ArchitectureDependencyAnalyzer
    from services.dependency_visualization import PartialDependencyState

    container_name = job.container_name
    tenant_id = job.tenant_id
    budget = job.budget_seconds
    analyzer = ArchitectureDependencyAnalyzer()
    # Caller-held accumulator so a budget timeout can recover partial findings
    # instead of discarding them (parity with the container scan path).
    partial = PartialDependencyState()
    try:
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="running",
                tenant_id=tenant_id,
                extra={"container_name": container_name},
            )
        )
        async with resolve_repo_path(container_name, tenant_id) as repo:
            # Heartbeat after the (round-trip) manifest fetch phase.
            await store.store(
                AsyncScanTaskRecord(
                    task_id=job.task_id,
                    status="running",
                    tenant_id=tenant_id,
                    extra={"container_name": container_name},
                )
            )
            report = await asyncio.wait_for(
                analyzer.analyze(repo.path, container_name, partial=partial),
                timeout=budget,
            )
            # OR, never overwrite: analyze() already flags its own degradations.
            if repo.incomplete:
                mark_degraded(report, "dependency-manifest fetch was incomplete")
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="completed",
                tenant_id=tenant_id,
                scan_degraded=report.scan_degraded,
                result=report.model_dump(mode="json"),
                extra={"container_name": container_name},
            )
        )
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        # asyncio.TimeoutError is an alias of the builtin TimeoutError on
        # py3.11+, so this catches the wait_for deadline. Rather than discard
        # the scan, surface whatever completed as a degraded ``completed``
        # record (parity with the container path's ``build_partial_result``).
        logger.warning(
            "Async dependency scan for '%s' exceeded %.0fs budget; surfacing "
            "%d partial finding(s) across %d package(s) as degraded",
            container_name,
            budget,
            len(partial.vulnerabilities),
            len(partial.packages),
        )
        # Building/persisting the degraded report must never escape this handler:
        # an exception raised inside one ``except`` is NOT caught by the sibling
        # ``except Exception`` below, so it would leave the job with no terminal
        # write → un-acked → reclaimed → re-timed-out every cycle. Fall back to a
        # ``failed`` terminal record instead (e.g. build_partial_report → an empty
        # codebase_id ValueError, or a store hiccup).
        try:
            report = analyzer.build_partial_report(container_name, partial)
            await store.store(
                AsyncScanTaskRecord(
                    task_id=job.task_id,
                    status="completed",
                    tenant_id=tenant_id,
                    scan_degraded=True,
                    result=report.model_dump(mode="json"),
                    extra={"container_name": container_name},
                )
            )
        except Exception as exc:
            logger.exception(
                "Failed to build/store the partial dependency report for '%s' after "
                "timeout; recording failed instead: %s",
                container_name,
                exc,
            )
            await store.store(
                AsyncScanTaskRecord(
                    task_id=job.task_id,
                    status="failed",
                    tenant_id=tenant_id,
                    error=f"dependency scan exceeded {budget}s budget",
                    extra={"container_name": container_name},
                )
            )
    except Exception as exc:
        logger.exception("Async dependency scan failed for '%s': %s", container_name, exc)
        await store.store(
            AsyncScanTaskRecord(
                task_id=job.task_id,
                status="failed",
                tenant_id=tenant_id,
                error=str(exc),
                extra={"container_name": container_name},
            )
        )
