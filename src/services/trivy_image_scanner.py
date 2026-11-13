"""Base-image OS-package CVE scanner (``trivy image``, against the baked DB).

Why this exists
---------------
The container scan ran five engines (pattern, bandit, semgrep, detect-secrets,
``trivy config``) and the dependency scan read manifests/lockfiles. Between
them they never looked at the **OS packages of the image a Dockerfile is built
FROM**. A real repo whose Dockerfile said ``FROM python:3.12-slim-bookworm``
reported 0 critical / 2 high while its base image carried CVE-2026-109518
(HIGH) in ``apt 2.6.1`` — fixed in ``2.6.2``. The dependency scan cannot see it
(nothing imports ``apt``) and ``trivy config`` only reads the Dockerfile text.

This engine closes that gap: it parses the scanned repo's Dockerfiles, resolves
every unique base image, scans each one with ``trivy image`` against the
vulnerability DB baked into the image, and maps the OS-package findings into
the same finding list the other engines feed.

Why the refs are rewritten through the internal registry
--------------------------------------------------------
The runtime pod has no egress to docker.io/ghcr.io (ambient-mesh policy). The
estate mirrors the official library images into ``mirror.example.com``
(``library/python``, ``library/debian``, ...), so ``python:3.12-slim`` is scanned
as ``mirror.example.com/library/python:3.12-slim``. A ref hosted on any
OTHER registry cannot be pulled from the pod; that is reported as a degraded
reason, never silently skipped.

The DB
------
The Dockerfile bakes ``trivy image --download-db-only`` into
``/opt/trivy-cache`` (the same dir as the misconfig policy bundle). The
deployment's ``seed-trivy-cache`` init container copies that dir into the
emptyDir ``TRIVY_CACHE_DIR`` points at, so scans run with ``--skip-db-update``
and never touch the network for the DB. If the baked DB is absent (a local dev
image), the scanner lets trivy use ``TRIVY_DB_REPOSITORY`` instead of failing
outright.

Scan granularity
----------------
One ``trivy image`` invocation per UNIQUE base ref per scan (two Dockerfiles
building on the same ref share the result). Findings are attached to the
Dockerfile path and the line of the first ``FROM`` that references the image.
``scratch`` is not an image and is skipped; a ``FROM <stage>`` that names an
earlier build stage is skipped; ``ARG`` defaults (``ARG BASE=python:3.12-slim``
then ``FROM ${BASE}``) are substituted, with one layer of quotes removed
(``ARG BASE="python:3.12-slim"`` means the image, not a name with quotes). An
ARG with no default cannot be resolved without the build arguments, so that
ref is reported as degraded. ``Containerfile`` is accepted as the same format.
Comments are stripped BEFORE continuations are joined, exactly as Docker does.

The engine is bounded by the scan's remaining wall-clock deadline: each image
gets at most what is left (minus a small margin), and running out of time is
reported as DEGRADED, never as a clean run and never as a whole-scan failure.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from models.architecture_models import Vulnerability
from services.scanner_errors import (
    ScannerExecutionError,
    ScannerPartialRunError,
    load_json_report,
)
from services.security_detector import (
    ScanEngine,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)

# Trivy `Severity` -> VulnerabilitySeverity. UNKNOWN is a real trivy value (a
# record with no vendor severity); it is reported at INFO so it never inflates
# the critical/high gate, but the row is kept (it is still a real advisory).
_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "CRITICAL": VulnerabilitySeverity.CRITICAL,
    "HIGH": VulnerabilitySeverity.HIGH,
    "MEDIUM": VulnerabilitySeverity.MEDIUM,
    "LOW": VulnerabilitySeverity.LOW,
    "UNKNOWN": VulnerabilitySeverity.INFO,
}

# One `docker image` pull+scan is ~2-20s; a repo with dozens of Dockerfiles
# would spend the whole scan budget on base images alone. Bound the work and
# say so (degraded), rather than silently scanning only some of them.
_MAX_BASE_IMAGES = 10

# Per-image budget. A base image is small; a slow registry is a failure to
# report, not a reason to hold the whole repo scan open for minutes.
_SCAN_TIMEOUT_SECONDS = 180

# Total engine budget when the caller does NOT supply a scan deadline (the
# direct /api/security/analyze endpoint has no wait_for of its own). It sits
# inside the 60s sync scan budget so the engine can never be the reason a repo
# scan overruns. When the caller DOES supply a deadline (the bounded scan
# runner), the remaining deadline replaces this — never exceeds it.
_DEFAULT_TOTAL_SECONDS = 45.0

# Left for the caller's own bookkeeping (result assembly, the partial-state
# build on timeout) after the engine returns.
_BUDGET_MARGIN_SECONDS = 5.0

# Never hand trivy a sub-second budget: a 0s timeout is a guaranteed failure.
_MIN_IMAGE_BUDGET_SECONDS = 1.0

# How stale a baked DB may be before the engine reports DEGRADED. The image is
# rebuilt weekly (ci-cd.yaml schedule, Mondays 04:17 UTC), so a healthy bake is
# 0-7 days old; 10 days allows rollout lag and trips ~3 days into a missed
# rebuild — the same threshold and rationale as the baked OSV DB.
_DB_MAX_AGE_DAYS = 10.0

# Dockerfile names this engine parses. `Dockerfile*` covers
# Dockerfile.prod/Dockerfile-dev; `*.Dockerfile` covers app.Dockerfile; the
# Containerfile spelling is the same format and `trivy config` already treats
# it as a Dockerfile. The match is case-insensitive (`dockerfile` is what
# people actually type).
_DOCKERFILE_PREFIXES = ("dockerfile", "containerfile")
_DOCKERFILE_SUFFIXES = (".dockerfile", ".containerfile")

_ARG_LINE = re.compile(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$", re.IGNORECASE)
_FROM_LINE = re.compile(r"^FROM\s+(.*)$", re.IGNORECASE)
_STAGE_ALIAS = re.compile(r"\bAS\s+([A-Za-z0-9_.-]+)\s*$", re.IGNORECASE)
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")

# Docker Hub's canonical host names; all three mean the same namespace and are
# served by our `library/*` mirror.
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


def is_dockerfile(path: str | Path) -> bool:
    """True for a filename this engine parses (Dockerfile*/Containerfile*, *.Dockerfile)."""
    name = Path(path).name.lower()
    return name.startswith(_DOCKERFILE_PREFIXES) or name.endswith(_DOCKERFILE_SUFFIXES)


@dataclass(frozen=True)
class BaseImageRef:
    """One ``FROM`` line that names a real image."""

    image: str
    line: int
    line_text: str
    stage_alias: str | None = None


@dataclass(frozen=True)
class ResolvedImage:
    """A base ref mapped onto the registry the runtime pod can actually reach."""

    ref: str | None
    reason: str | None = None


@dataclass(frozen=True)
class _ImageScan:
    """Findings for one base image, shared by every Dockerfile that uses it."""

    vulnerabilities: list[Vulnerability]


#: One coverage row, appended to the caller's ``coverage_out`` list:
#: ``{"ref", "dockerfile", "line", "status", "error"}``. A plain dict, not a
#: dataclass, because the detector hands the caller's partial-state list
#: straight through — the rows are appended up front and mutated as each image
#: resolves, so coverage survives a scan cancelled mid-image.
CoverageRow = dict[str, Any]


def _coverage_row(ref: str, dockerfile: str, line: int) -> CoverageRow:
    """An initial "unresolved / not scanned" row, updated as the scan proceeds."""
    return {
        "ref": ref,
        "dockerfile": dockerfile,
        "line": line,
        "status": "unresolved",
        "error": "not scanned before the scan deadline",
    }


class _ImageScanTimeoutError(ScannerExecutionError):
    """One image's scan hit the engine's remaining-budget deadline.

    A distinct type so the caller can report DEGRADED (the scan was cut short)
    instead of FAILED (the tool is broken) — a budget timeout says nothing
    about the tool's health.
    """


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Yield (first instruction line number, logical line) with continuations joined.

    Docker strips COMMENT lines BEFORE joining continuations: a ``# ... \\``
    line is a comment, not the start of a continuation — and a comment may sit
    INSIDE a continued instruction (between the ``\\`` line and its tail).
    Joining first (the old behaviour) swallowed the line after a
    comment-continuation, which could hide the Dockerfile's only FROM and make
    the engine report ``ok`` with nothing scanned.
    """
    out: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.rstrip()
        if stripped.lstrip().startswith("#"):
            # A comment line is removed entirely — including any trailing ``\``.
            continue
        if not pending:
            start = number
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        out.append((start, pending + stripped))
        pending = ""
    if pending:
        out.append((start, pending))
    return out


def _unquote(value: str) -> str:
    """Strip one layer of matching single/double quotes from an ARG default.

    ``ARG BASE="python:3.12-slim"`` is how people write it; the quotes are
    not part of the image ref. Without this the ref is ``"python:3.12-slim"``
    (quotes included), which no registry can resolve, so every scan of the
    repo would degrade forever.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _substitute(value: str, args: dict[str, str]) -> tuple[str | None, str | None]:
    """Expand ``$VAR`` / ``${VAR}`` / ``${VAR:-default}`` from Dockerfile ARG defaults.

    Returns ``(expanded, unresolved_name)``. ``expanded`` is None when the
    value references an ARG with no default — the image cannot be known without
    the build arguments, so the caller reports it degraded instead of guessing.
    """
    unresolved: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3) or ""
        fallback = match.group(2)
        if name in args:
            return args[name]
        if fallback is not None:
            return fallback
        unresolved.append(name)
        return match.group(0)

    expanded = _VAR_REF.sub(_replace, value)
    if unresolved:
        return None, unresolved[0]
    return expanded, None


def extract_base_images(dockerfile_text: str) -> tuple[list[BaseImageRef], list[str]]:
    """Extract the base image the FINAL stage is built FROM.

    Returns ``(refs, problems)`` with at most ONE ref: the base of the last
    stage — i.e. what the image this Dockerfile builds actually ships. Builder
    stages are deliberately NOT reported: their OS packages never reach the
    runtime image (only the files copied out of them do), so scanning them
    would report CVEs against software the repo does not deploy. A final stage
    written ``FROM <alias>`` is resolved through its alias chain to the real
    image.

    Handles multi-stage (a ``FROM <stage>`` that names an earlier ``AS`` alias
    is not an image), ``--platform=...`` flags, ``scratch``, digests and ARG
    defaults declared before the first FROM.
    """
    refs: list[BaseImageRef] = []
    problems: list[str] = []
    args: dict[str, str] = {}
    stage_aliases: set[str] = set()
    seen_from = False
    #: (alias, ref, parent-alias) per stage, in file order. ``parent`` is set
    #: when the stage is built FROM an earlier stage's alias.
    stages: list[tuple[str | None, BaseImageRef | None, str | None]] = []

    for line_number, line in _logical_lines(dockerfile_text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Global ARGs (declared before the first FROM) are the only ones a
        # FROM may reference — Docker scopes stage ARGs to the stage.
        if not seen_from:
            arg_match = _ARG_LINE.match(stripped)
            if arg_match:
                name, default = arg_match.group(1), arg_match.group(2)
                if default is not None:
                    args[name] = _unquote(default)
                continue

        from_match = _FROM_LINE.match(stripped)
        if not from_match:
            continue
        seen_from = True

        rest = from_match.group(1).strip()
        alias_match = _STAGE_ALIAS.search(rest)
        stage_alias = alias_match.group(1) if alias_match else None
        if alias_match:
            rest = rest[: alias_match.start()].strip()

        # FROM [--platform=<p>] <image>; the flag value is never the image.
        tokens = [t for t in rest.split() if not t.startswith("--")]
        if not tokens:
            problems.append(f"line {line_number}: FROM without an image")
            continue
        raw_image = tokens[0]
        alias_key = stage_alias.lower() if stage_alias else None

        image, unresolved = _substitute(raw_image, args)
        if image is None:
            problems.append(
                f"line {line_number}: {raw_image} references ARG {unresolved} "
                "with no default (not resolvable without build args)"
            )
            stages.append((alias_key, None, None))
            continue
        if image.lower() in stage_aliases:
            # A later stage built FROM an earlier stage: no new base image,
            # but remember the parent so a FINAL stage of this shape can still
            # be resolved back to the real image.
            stages.append((alias_key, None, image.lower()))
            if alias_key:
                stage_aliases.add(alias_key)
            continue
        if alias_key:
            stage_aliases.add(alias_key)
        if image.lower() == "scratch":
            stages.append((alias_key, None, None))
            continue

        ref = BaseImageRef(
            image=image,
            line=line_number,
            line_text=stripped,
            stage_alias=stage_alias,
        )
        stages.append((alias_key, ref, None))
        refs.append(ref)

    # The LAST stage is what this Dockerfile builds by default; follow its
    # alias chain to the real image that ships.
    final_ref: BaseImageRef | None = None
    if stages:
        by_alias = {alias: (alias, ref, parent) for alias, ref, parent in stages if alias}
        _alias, final_ref, parent = stages[-1]
        seen: set[str] = set()
        while final_ref is None and parent and parent in by_alias and parent not in seen:
            seen.add(parent)
            _alias, final_ref, parent = by_alias[parent]
    return ([final_ref] if final_ref is not None else []), problems


def resolve_image_ref(image: str, registry: str) -> ResolvedImage:
    """Map a Dockerfile image ref onto ``registry`` (the only reachable one).

    ``python:3.12-slim`` -> ``mirror.example.com/library/python:3.12-slim``.
    A ref that names another registry cannot be pulled from the pod and is
    returned with a reason for the degraded report.
    """
    if not registry:
        return ResolvedImage(None, "no internal registry is configured (DOCKER_REGISTRY_URL)")

    # Split the digest first: a digest may itself contain a colon-free sha256.
    digest = ""
    name_and_tag = image
    if "@" in image:
        name_and_tag, digest = image.split("@", 1)
        digest = "@" + digest

    # A tag is a ':' AFTER the last '/' (a registry port is before it).
    tag = ""
    last_slash = name_and_tag.rfind("/")
    last_colon = name_and_tag.rfind(":")
    if last_colon > last_slash:
        name_and_tag, tag = name_and_tag[:last_colon], name_and_tag[last_colon:]

    parts = name_and_tag.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host, path = parts[0], "/".join(parts[1:])
        # Docker Hub is written as an explicit host in Dockerfiles
        # (`ARG BASE_REGISTRY=docker.io` -> `FROM docker.io/library/python`),
        # and it IS mirrored (as `library/python` on our registry).
        if host in _DOCKER_HUB_HOSTS:
            pass
        elif host != registry:
            return ResolvedImage(
                None,
                f"{image} is hosted on {host}, which the runtime pod cannot reach "
                f"(only {registry} is mirrored)",
            )
    else:
        path = name_and_tag
    if "/" not in path:
        path = f"library/{path}"

    if not path:
        return ResolvedImage(None, f"{image} has no image name")
    return ResolvedImage(f"{registry}/{path}{tag}{digest}")


def _trivy_cache_dir() -> str:
    return os.environ.get("TRIVY_CACHE_DIR") or "/opt/trivy-cache"


def _baked_db_present(cache_dir: str) -> bool:
    return Path(cache_dir, "db", "trivy.db").is_file()


def _db_age_days(cache_dir: str) -> float | None:
    """Age in days of the baked vulnerability DB, from trivy's own metadata.

    Returns None when the metadata is missing or unreadable — existence of
    ``trivy.db`` alone says nothing about its freshness, and a scan that
    silently uses a year-old DB is the same silent miss this engine exists to
    prevent.
    """
    metadata = Path(cache_dir, "db", "metadata.json")
    try:
        data = json.loads(metadata.read_text(encoding="utf-8"))
        updated = data["UpdatedAt"]
        if not isinstance(updated, str) or not updated:
            return None
        when = datetime.fromisoformat(updated.replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - when).total_seconds() / 86400.0)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class TrivyImageScanner:
    """Scan Dockerfile base images with ``trivy image`` and map OS CVEs."""

    def __init__(self) -> None:
        # shutil.which, never `trivy --version`: a CLI cold start would make
        # is_available() slow (the E3.8 lesson pinned in iac_scanner).
        self.trivy_available = shutil.which("trivy") is not None

    def is_available(self) -> bool:
        return self.trivy_available

    async def scan(
        self,
        file_paths: Sequence[str | Path],
        timeout: int = _SCAN_TIMEOUT_SECONDS,
        *,
        deadline: float | None = None,
        coverage_out: list[CoverageRow] | None = None,
    ) -> list[VulnerabilityMatch]:
        """Scan every unique base image referenced by the given Dockerfiles.

        ``deadline`` is an absolute ``loop.time()`` value supplied by the
        bounded scan runner. The engine NEVER spends past it: each image gets
        ``min(timeout, remaining - margin)`` and the loop stops when nothing is
        left. Without a deadline (the direct analysis endpoint) the engine caps
        itself at ``_DEFAULT_TOTAL_SECONDS``, which sits inside the 60s sync
        scan budget.

        ``coverage_out`` (optional, caller-owned) receives one row per
        Dockerfile FROM reference describing whether that image was actually
        scanned; rows are appended before scanning starts and updated in place,
        so the coverage list is accurate on the success path, on the degraded
        path and when the scan is cancelled. Unresolved rows are never clean.

        Raises ``ScannerPartialRunError`` (engine status DEGRADED) when the
        budget runs out, an image times out, the DB is stale, or only some
        images could be scanned — carrying whatever findings were collected.
        Raises ``ScannerExecutionError`` (FAILED) only when NO image could be
        scanned for a non-budget reason (bad ref, auth, missing DB).
        """
        if not self.trivy_available:
            raise ScannerExecutionError("trivy-image", -1, "trivy is not on PATH")

        # (dockerfile path, ref) -> findings source; the first FROM of a ref in
        # a Dockerfile is the one reported (a multi-stage file often repeats it).
        targets: dict[tuple[str, str], BaseImageRef] = {}
        problems: list[str] = []
        for raw_path in file_paths:
            path = str(raw_path)
            if not is_dockerfile(path):
                continue
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                problems.append(f"{path}: could not be read ({exc})")
                continue
            refs, parse_problems = extract_base_images(text)
            problems.extend(f"{path}: {p}" for p in parse_problems)
            for ref in refs:
                targets.setdefault((path, ref.image), ref)

        # Coverage rows exist before any scan starts: unresolved by default,
        # flipped to "scanned" only when trivy returned a report for the image.
        # Appended up front so the list is accurate even if this scan is
        # cancelled mid-image by the caller's overall deadline.
        coverage_by_image: dict[str, list[CoverageRow]] = {}
        if coverage_out is not None:
            for (dockerfile, image), ref in targets.items():
                row = _coverage_row(image, dockerfile, ref.line)
                coverage_out.append(row)
                coverage_by_image.setdefault(image, []).append(row)

        if not targets and not problems:
            # No Dockerfile in this repo, or only scratch/alias FROMs: the
            # engine had nothing to do, which is a complete (not failed) run.
            return []

        # A baked DB that has aged out silently under-reports CVEs (that is the
        # class of miss this engine exists to close), so it degrades the engine
        # even when every image scan itself succeeds.
        cache_dir = _trivy_cache_dir()
        if _baked_db_present(cache_dir):
            age_days = _db_age_days(cache_dir)
            if age_days is None:
                problems.append(
                    f"baked trivy DB metadata is unreadable ({cache_dir}/db/metadata.json); "
                    "CVE coverage is unknown"
                )
            elif age_days > _DB_MAX_AGE_DAYS:
                problems.append(
                    f"baked trivy DB is {age_days:.0f} days old (max "
                    f"{_DB_MAX_AGE_DAYS:.0f}); rebuild the image to refresh it"
                )

        unique_images = list(dict.fromkeys(ref.image for _, ref in targets.items()))
        if len(unique_images) > _MAX_BASE_IMAGES:
            dropped = unique_images[_MAX_BASE_IMAGES:]
            problems.append(
                f"{len(unique_images) - _MAX_BASE_IMAGES} base image(s) not scanned "
                f"(bounded to {_MAX_BASE_IMAGES} per scan)"
            )
            unique_images = unique_images[:_MAX_BASE_IMAGES]
            for image in dropped:
                for row in coverage_by_image.get(image, []):
                    row["error"] = (
                        f"not scanned (bounded to {_MAX_BASE_IMAGES} base images per scan)"
                    )

        loop = asyncio.get_running_loop()
        end = deadline if deadline is not None else loop.time() + _DEFAULT_TOTAL_SECONDS
        registry = self._registry()
        scans: dict[str, _ImageScan] = {}
        scanned = 0
        timed_out = False
        budget_exhausted = False
        last_error: ScannerExecutionError | None = None
        for index, image in enumerate(unique_images):
            resolved = resolve_image_ref(image, registry)
            if resolved.ref is None:
                problems.append(f"{image}: {resolved.reason}")
                for row in coverage_by_image.get(image, []):
                    row["error"] = resolved.reason or "could not be resolved"
                continue
            remaining = end - loop.time() - _BUDGET_MARGIN_SECONDS
            if remaining < _MIN_IMAGE_BUDGET_SECONDS:
                budget_exhausted = True
                problems.append(
                    f"scan deadline reached: {len(unique_images) - index} base image(s) "
                    f"not scanned ({image} and later)"
                )
                break
            try:
                scans[image] = _ImageScan(
                    await self._scan_image(resolved.ref, min(float(timeout), remaining))
                )
                scanned += 1
                for row in coverage_by_image.get(image, []):
                    row["status"] = "scanned"
                    row["error"] = None
            except _ImageScanTimeoutError as exc:
                timed_out = True
                problems.append(f"{image}: {exc}")
                last_error = exc
                for row in coverage_by_image.get(image, []):
                    row["error"] = str(exc)
            except ScannerExecutionError as exc:
                problems.append(f"{image}: {exc}")
                last_error = exc
                for row in coverage_by_image.get(image, []):
                    row["error"] = str(exc)

        matches: list[VulnerabilityMatch] = []
        for (dockerfile, image), ref in targets.items():
            scan = scans.get(image)
            if scan is None:
                continue
            matches.extend(
                self._to_match(
                    vuln,
                    dockerfile=dockerfile,
                    from_ref=ref,
                    base_image=image,
                )
                for vuln in scan.vulnerabilities
            )

        if problems:
            reason = "; ".join(problems[:5])
            if len(problems) > 5:
                reason += f" (+{len(problems) - 5} more)"
            if scanned == 0 and not (timed_out or budget_exhausted):
                raise ScannerExecutionError(
                    "trivy-image",
                    getattr(last_error, "returncode", -1),
                    reason,
                    reason=f"no base image could be scanned: {reason}",
                ) from last_error
            # Budget/timeout => DEGRADED, never FAILED: the tool is healthy,
            # it was not given enough time (or some images were not scanned).
            raise ScannerPartialRunError(
                "trivy-image",
                0,
                reason,
                partial_findings=matches,
                reason=f"base-image scan incomplete: {reason}",
            )
        return matches

    @staticmethod
    def _registry() -> str:
        # Imported lazily: settings builds a pydantic model at import time and
        # this module is imported by the detector's constructor.
        from config.settings import get_settings

        try:
            return get_settings().docker_registry_url
        except Exception:  # pragma: no cover - settings validation failures
            logger.warning("could not load settings for the internal registry", exc_info=True)
            return ""

    async def _scan_image(self, image_ref: str, timeout: float) -> list[Vulnerability]:
        """Run one `trivy image` inside the caller's remaining budget.

        ``timeout`` is the HARD bound on this subprocess: it never exceeds the
        remaining scan deadline. trivy's own ``--timeout`` gets 5s less so it
        can exit cleanly before the process-group kill.
        """
        hard_timeout = max(_MIN_IMAGE_BUDGET_SECONDS, float(timeout))
        trivy_timeout = max(1, int(hard_timeout - 5))
        cache_dir = _trivy_cache_dir()
        baked = _baked_db_present(cache_dir)
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln",
            # Only OS packages: language packages are the dependency scan's job
            # (reading them here would double-report the same npm/pip CVEs).
            "--pkg-types",
            "os",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            "--cache-dir",
            cache_dir,
            "--timeout",
            f"{trivy_timeout}s",
            "--skip-version-check",
            "--quiet",
        ]
        if baked:
            # The DB is in the image (and the pod seeds it into the cache dir).
            # Skip the update so a scan cannot block on an egress the pod does
            # not have; the weekly rebuild refreshes the bake.
            cmd.extend(["--skip-db-update", "--skip-java-db-update"])
        if _env_truthy("TRIVY_INSECURE"):
            # A private mirror can serve a self-signed cert Go rejects outright
            # ("not standards compliant"), so such a deployment sets TRIVY_INSECURE.
            cmd.append("--insecure")
        cmd.append(image_ref)

        logger.debug("Running trivy image scan: %s", " ".join(cmd))
        try:
            returncode, stdout, stderr = await run_subprocess(cmd, timeout=hard_timeout)
        except TimeoutError as exc:
            raise _ImageScanTimeoutError(
                "trivy-image",
                -1,
                "timed out",
                reason=f"timed out after {hard_timeout:.0f}s (scan budget)",
            ) from exc

        text = stdout.decode("utf-8", errors="ignore") if isinstance(stdout, bytes) else stdout
        err_text = stderr.decode("utf-8", errors="ignore") if isinstance(stderr, bytes) else stderr
        report = load_json_report(
            "trivy-image",
            returncode,
            text,
            err_text,
            ok_exit_codes={0},
            # Results may be omitted when trivy found no OS packages; that is a
            # clean report, not a wrong-shape one (same rule as trivy config).
            required={"SchemaVersion": int},
        )
        return _parse_os_vulnerabilities(report, image_ref)

    @staticmethod
    def _to_match(
        vuln: Vulnerability,
        *,
        dockerfile: str,
        from_ref: BaseImageRef,
        base_image: str,
    ) -> VulnerabilityMatch:
        severity = _SEVERITY_MAP.get(vuln.severity.upper(), VulnerabilitySeverity.INFO)
        cve = vuln.id
        fixed = vuln.fixed_versions[0] if vuln.fixed_versions else ""
        installed = vuln.package_version or (
            vuln.affected_versions[0] if vuln.affected_versions else ""
        )
        if fixed:
            remediation = (
                f"Update {vuln.package_name} from {installed} to {fixed} in the "
                f"base image ({base_image}) and rebuild; or pin the package in the "
                "Dockerfile (apt-get install -y "
                f"{vuln.package_name}={fixed})."
            )
        else:
            remediation = (
                f"No fixed version is published yet for {vuln.package_name} ({cve}). "
                "Track the advisory or move to a newer base image."
            )
        description = (
            f"{vuln.package_name} {installed}"
            + (f" -> {fixed}" if fixed else " (no fix published)")
            + f" in base image {base_image}"
        )
        return VulnerabilityMatch(
            id=f"trivy_image_{cve}_{vuln.package_name}_{from_ref.line}",
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=VulnerabilityConfidence.HIGH,
            file_path=dockerfile,
            language="dockerfile",
            line_start=from_ref.line,
            line_end=from_ref.line,
            pattern_id=cve,
            title=f"{cve}: {vuln.package_name} {installed} in {base_image}",
            description=description,
            code_snippet=from_ref.line_text,
            remediation_advice=remediation,
            references=list(vuln.references),
            context_evidence={
                "cve": cve,
                "package": vuln.package_name,
                "installed_version": installed,
                "fixed_version": fixed,
                "base_image": base_image,
                "dockerfile": dockerfile,
                "from_line": from_ref.line,
            },
            # Structured fields for consumers (the API mirrors these onto the
            # finding): the free-text description stays for backward compat.
            package_name=vuln.package_name,
            installed_version=installed,
            fixed_version=fixed,
            fix_available=bool(fixed),
            image_ref=base_image,
            engine=ScanEngine.TRIVY_IMAGE,
        )

    def get_status(self) -> dict:
        return {
            "available": self.trivy_available,
            "engine": "trivy image",
            "db_cache_dir": _trivy_cache_dir(),
            "baked_db": _baked_db_present(_trivy_cache_dir()),
        }


def _parse_os_vulnerabilities(report: dict, image_ref: str) -> list[Vulnerability]:
    """Map a ``trivy image`` report's OS-package rows to the Vulnerability model.

    Only ``Class == "os-pkgs"`` results are read (see ``--pkg-types os``); the
    mapping keeps the package, the installed and fixed versions, the CVE id and
    the trivy severity, exactly as the dependency path's Vulnerability rows do.
    """
    rows: list[Vulnerability] = []
    seen: set[tuple[str, str]] = set()
    for result in report.get("Results") or []:
        if not isinstance(result, dict) or result.get("Class") != "os-pkgs":
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cve = str(vuln.get("VulnerabilityID") or "").strip()
            package = str(vuln.get("PkgName") or "").strip()
            if not cve or not package:
                continue
            key = (cve, package)
            if key in seen:
                continue
            seen.add(key)
            installed = str(vuln.get("InstalledVersion") or "")
            fixed = vuln.get("FixedVersion")
            fixed_versions = [str(fixed)] if fixed else []
            references = [str(r) for r in (vuln.get("References") or []) if r]
            primary = str(vuln.get("PrimaryURL") or "")
            if primary and primary not in references:
                references.insert(0, primary)
            if not references:
                references = [f"https://avd.aquasec.com/nvd/{cve}"]
            rows.append(
                Vulnerability(
                    id=cve,
                    severity=str(vuln.get("Severity") or "UNKNOWN").upper(),
                    summary=str(vuln.get("Title") or f"{cve} in {package}"),
                    details=str(vuln.get("Description") or ""),
                    affected_versions=[installed] if installed else [],
                    fixed_versions=fixed_versions,
                    references=references,
                    published_date=str(vuln.get("PublishedDate") or ""),
                    modified_date=str(vuln.get("LastModifiedDate") or ""),
                    package_name=package,
                    package_version=installed,
                )
            )
    logger.debug("trivy image %s: %d OS-package CVE(s)", image_ref, len(rows))
    return rows
