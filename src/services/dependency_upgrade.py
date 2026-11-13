"""Dependency upgrade orchestrator.

Responsibilities:
  * Resolve / validate the target container against the caller's tenant.
  * Auto-detect the package manager when the caller didn't specify one
    (look at which manifests are present in the project_path).
  * Call coding-containers' typed ``/package-upgrade`` endpoint.
  * Compute manifest diffs + parse per-package results.
  * If requested, commit the diff via coding-github ``/apply-changes`` and
    optionally open a pull request.

The split is deliberate: coding-security owns policy (tenant auth,
manager detection from the existing extractor surface, diff computation,
optional commit/PR) while coding-containers owns per-manager command
construction and execution. coding-containers never touches GitHub.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import NamedTuple

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from auth.tenant import require_tenant  # noqa: F401  (re-exported via routers)
from clients.containers_client import ContainersClient, ContainersClientError
from clients.github_client import GithubClient, GithubClientError
from models.architecture_models import Vulnerability, mark_degraded
from models.package_manager_models import ExternalPackage, LanguagePackageManager
from models.upgrade_models import (
    AddDependenciesRequest,
    CommitSkipReason,
    CveSummary,
    MajorUpgradeSpec,
    ManifestDiff,
    PackageResult,
    RemoveDependenciesRequest,
    ReplaceDependenciesRequest,
    ReplacementSpec,
    UpgradeCvesRequest,
    UpgradeMajorRequest,
    UpgradePackageRef,
    UpgradeRequest,
    UpgradeResponse,
)
from utils.container_validation import validate_and_get_container_for_tenant

logger = logging.getLogger(__name__)


# Manifests that uniquely identify a package manager (i.e. no false positives
# between managers). Ordered: the first match wins. ``pyproject.toml`` is
# deliberately NOT a unique signal — it could be uv, poetry, pipenv or pip.
# We disambiguate Python via the lockfile.
_UNIQUE_LOCK_TO_MANAGER: tuple[tuple[str, LanguagePackageManager], ...] = (
    ("uv.lock", LanguagePackageManager.UV),
    ("poetry.lock", LanguagePackageManager.POETRY),
    ("Pipfile.lock", LanguagePackageManager.PIPENV),
    ("Pipfile", LanguagePackageManager.PIPENV),
    ("Cargo.lock", LanguagePackageManager.CARGO),
    ("Cargo.toml", LanguagePackageManager.CARGO),
    ("pnpm-lock.yaml", LanguagePackageManager.PNPM),
    ("yarn.lock", LanguagePackageManager.YARN),
    ("bun.lockb", LanguagePackageManager.BUN),
    ("package-lock.json", LanguagePackageManager.NPM),
    ("package.json", LanguagePackageManager.NPM),  # last-resort npm
    ("go.sum", LanguagePackageManager.GO_MOD),
    ("go.mod", LanguagePackageManager.GO_MOD),
    ("composer.lock", LanguagePackageManager.COMPOSER),
    ("composer.json", LanguagePackageManager.COMPOSER),
    ("Gemfile.lock", LanguagePackageManager.BUNDLER),
    ("Gemfile", LanguagePackageManager.BUNDLER),
    ("environment.yml", LanguagePackageManager.CONDA),
    ("environment.yaml", LanguagePackageManager.CONDA),
    ("pom.xml", LanguagePackageManager.MAVEN),
    ("build.gradle", LanguagePackageManager.GRADLE),
    ("build.gradle.kts", LanguagePackageManager.GRADLE),
    # pip is the fallback for requirements.txt — only if no other Python
    # lockfile is present.
    ("requirements.txt", LanguagePackageManager.PIP),
)


@dataclass
class _UpgradeOptions:
    """Shared bag for the two route handlers."""

    container_name: str
    tenant_id: str
    manager: LanguagePackageManager | None
    project_path: str
    dry_run: bool
    timeout_seconds: int
    commit: bool
    branch_name: str | None
    open_pr: bool
    draft: bool
    pr_title: str | None
    pr_body: str | None


async def _detect_manager(
    client: ContainersClient,
    container_name: str,
    tenant_id: str,
    project_path: str,
) -> LanguagePackageManager:
    """Inspect ``project_path`` inside the container; pick the manager whose
    lock/manifest file is present.

    Strategy: ``ls -1`` the project_path; first match in
    ``_UNIQUE_LOCK_TO_MANAGER`` wins. Raises if nothing matches.
    """
    workdir = "/workspace"
    rel = project_path.strip()
    if rel and rel != ".":
        # The exec workdir is the repo root; we list the project subdir.
        target = f"{workdir}/{rel.lstrip('/')}"
    else:
        target = workdir

    result = await client.exec_command(
        container_name=container_name,
        tenant_id=tenant_id,
        command=["ls", "-1", target],
        workdir=workdir,
        timeout=30,
    )
    entries = {line.strip() for line in (result.get("stdout") or "").splitlines() if line.strip()}

    for filename, manager in _UNIQUE_LOCK_TO_MANAGER:
        if filename in entries:
            return manager

    # .csproj / .fsproj / .vbproj — glob match.
    for ext, mgr in (
        (".csproj", LanguagePackageManager.DOTNET),
        (".fsproj", LanguagePackageManager.DOTNET),
        (".vbproj", LanguagePackageManager.DOTNET),
    ):
        if any(e.endswith(ext) for e in entries):
            return mgr

    raise ValueError(
        f"could not auto-detect a package manager in {target}; "
        "pass ``manager`` explicitly. Listed entries: "
        f"{sorted(entries)[:20]}"
    )


def _compute_diffs(before: dict[str, str], after: dict[str, str]) -> list[ManifestDiff]:
    paths = sorted(set(before) | set(after))
    diffs: list[ManifestDiff] = []
    for p in paths:
        b = before.get(p, "")
        a = after.get(p, "")
        if b != a:
            diffs.append(ManifestDiff(path=p, before=b, after=a))
    return diffs


# Patterns to discover the previous installed version of a package from a
# lockfile / manifest. Best-effort — the runner already returns the file
# contents, so we just regex out the relevant version literal. Used for
# populating ``PackageResult.previous_version`` and ``.new_version``.
_LOCK_VERSION_PATTERNS: dict[str, str] = {
    "uv.lock": r'name\s*=\s*"{name}"\s*\nversion\s*=\s*"([^"]+)"',
    "poetry.lock": r'name\s*=\s*"{name}"\s*\nversion\s*=\s*"([^"]+)"',
    "Pipfile.lock": r'"{name}"\s*:\s*\{{[^}}]*"version"\s*:\s*"==([^"]+)"',
    "Cargo.lock": r'name\s*=\s*"{name}"\s*\nversion\s*=\s*"([^"]+)"',
    "package-lock.json": r'"node_modules/{name}"\s*:\s*\{{[^}}]*"version"\s*:\s*"([^"]+)"',
    "yarn.lock": r'^"?{name}@[^"]*"?:\s*\n\s*version\s*"([^"]+)"',
    "pnpm-lock.yaml": r"/{name}@([0-9][^\s:]*):",
    "composer.lock": r'"name":\s*"{name}"\s*,\s*"version":\s*"([^"]+)"',
    "Gemfile.lock": r"^\s*{name}\s+\(([^)]+)\)\s*$",
    "go.sum": r"^{name}\s+(v[0-9][^\s/]+)",
}


def _find_version(name: str, manifests: dict[str, str]) -> str | None:
    name_esc = re.escape(name)
    for filename, pattern in _LOCK_VERSION_PATTERNS.items():
        content = manifests.get(filename)
        if not content:
            continue
        m = re.search(pattern.format(name=name_esc), content, flags=re.MULTILINE)
        if m:
            return m.group(1)
    return None


# Capture the constraint expression in pyproject.toml's ``project.dependencies``
# list (PEP 621 style: ``"name>=1.0,<2.0"``).
_PYPROJECT_CONSTRAINT_RE = r'"\s*{name}\s*([^"]*)"'


_GITHUB_OWNER_REPO_RE = re.compile(r"[/:]([^/]{1,256})/([^/.]{1,256})")


def _github_owner_repo(url: str) -> tuple[str, str] | None:
    """``(owner, repo)`` after the LAST ``github.com`` that is followed by one.

    Same answer as the old ``re.match(r".*github\\.com[/:]([^/]+)/([^/.]+)", url)``
    (greedy ``.*`` = last viable occurrence) but linear: that pattern re-scanned
    the rest of the string from every occurrence and never finished on 200k of
    ``github.com:``. Each attempt here is bounded.
    """
    end = len(url)
    while True:
        i = url.rfind("github.com", 0, end)
        if i < 0:
            return None
        m = _GITHUB_OWNER_REPO_RE.match(url, i + len("github.com"))
        if m:
            return m.group(1), m.group(2)
        end = i + len("github.com") - 1


def _find_constraint(name: str, manifests: dict[str, str]) -> str | None:
    name_esc = re.escape(name)
    pyproject = manifests.get("pyproject.toml")
    if pyproject:
        m = re.search(_PYPROJECT_CONSTRAINT_RE.format(name=name_esc), pyproject)
        if m:
            return m.group(1).strip() or None
    # JavaScript ecosystem: package.json deps/devDeps.
    pkgjson = manifests.get("package.json")
    if pkgjson:
        m = re.search(rf'"{name_esc}"\s*:\s*"([^"]+)"', pkgjson)
        if m:
            return m.group(1)
    # Rust: Cargo.toml.
    cargo = manifests.get("Cargo.toml")
    if cargo:
        # Horizontal whitespace only: `\s*` after `^` spans newlines, so every
        # line start rescanned the rest of a whitespace-heavy manifest
        # (quadratic: >68 s on 200k whitespace).
        m = re.search(
            rf'^[ \t]*{name_esc}[ \t]*=[ \t]*[{{"]([^"\n]+)["}}]', cargo, flags=re.MULTILINE
        )
        if m:
            return m.group(1)
    return None


def _build_package_results(
    names_with_intent: list[tuple[str, str | None]],
    manifests_before: dict[str, str],
    manifests_after: dict[str, str],
    overall_success: bool,
) -> list[PackageResult]:
    results: list[PackageResult] = []
    for name, expected_target in names_with_intent:
        prev_v = _find_version(name, manifests_before)
        new_v = _find_version(name, manifests_after)
        prev_c = _find_constraint(name, manifests_before)
        new_c = _find_constraint(name, manifests_after)
        changed = (prev_v != new_v) or (prev_c != new_c)
        results.append(
            PackageResult(
                name=name,
                previous_version=prev_v,
                new_version=new_v,
                previous_constraint=prev_c,
                new_constraint=new_c,
                success=overall_success and (changed or expected_target is None),
                error=None if overall_success else "upgrade command exited non-zero",
            )
        )
    return results


class _CommitOutcome(NamedTuple):
    """What the commit/PR step did, and — when it did nothing — WHY.

    A bare ``(None, None, None)`` was returned for four genuinely different situations
    and the caller could not tell them apart, so a card printed ``commit_url: null`` with
    no way to say whether the work was refused, skipped, or silently lost. Naming the
    refusal is the whole point; the values are ``CommitSkipReason``.
    """

    commit_url: str | None
    pr_url: str | None
    pr_number: int | None
    commit_skip_reason: CommitSkipReason | None = None


async def _maybe_commit_and_pr(
    *,
    github_client: GithubClient | None,
    options: _UpgradeOptions,
    container_info,
    manifest_diffs: list[ManifestDiff],
    success: bool = True,
    manifests_after: dict[str, str] | None = None,
) -> _CommitOutcome:
    # Never commit a failed upgrade — half-applied manifest changes (the
    # remove of a /replace landed but the add failed, say) must not ship.
    if not success:
        return _CommitOutcome(None, None, None, "upgrade_failed")

    # coding-github's GitHubFileChangeOperation requires `file_path` (no `path` alias);
    # sending `path` yields HTTP 422 body.changes.0.file_path "Field required".
    if manifests_after is not None:
        # Base-relative (idempotent) mode. coding-github creates the head branch
        # FROM the base branch and skips no-op file writes, so applying the FULL
        # post-upgrade manifest set produces a real diff whenever the target
        # differs from base — even when the container's workspace was already
        # mutated by a prior run (re-drive of the same version, which makes the
        # workspace before/after diff empty). Gating on that workspace diff is
        # exactly the bug that made re-drives no-op; gate on `commit` instead.
        if not options.commit:
            return _CommitOutcome(None, None, None, "commit_not_requested")
        changes = [{"file_path": p, "content": c} for p, c in sorted(manifests_after.items())]
        if not changes:
            return _CommitOutcome(None, None, None, "no_manifest_changes")
    else:
        # Legacy workspace-diff mode (in-range / modify callers).
        # Split purely to NAME the cause — the truth table is unchanged. "commit was not
        # asked for" and "there was nothing to commit" are different answers to a card
        # asking why no PR exists, and they used to arrive as the same silent None.
        if not options.commit:
            return _CommitOutcome(None, None, None, "commit_not_requested")
        if not manifest_diffs:
            return _CommitOutcome(None, None, None, "no_workspace_diff")
        changes = [{"file_path": d.path, "content": d.after} for d in manifest_diffs]

    if github_client is None:
        raise RuntimeError(
            "commit=true but github_service_url is not configured for coding-security"
        )
    if not options.branch_name:
        raise ValueError("commit=true requires branch_name")
    try:
        apply_resp = await github_client.apply_changes(
            tenant_id=options.tenant_id,
            container_name=options.container_name,
            branch_name=options.branch_name,
            changes=changes,
        )
    except GithubClientError as exc:
        raise RuntimeError(f"apply-changes failed: {exc}") from exc
    # ⛔ THIS LINE USED TO ASK FOR TWO KEYS THAT DO NOT EXIST.
    #
    #     commit_url = apply_resp.get("branch_url") or apply_resp.get("commit_url")
    #
    # coding-github's ApplyChangesResponse (src/schemas/github_api_models.py:416) emits
    # branch_name / commit_sha / changes_applied / no_changes / fork_url / authoring_identity
    # — and NEITHER `branch_url` NOR `commit_url`. So this was not "null sometimes": it was
    # STRUCTURALLY ALWAYS null, on every successful commit this service has ever made. It
    # surfaced as enterprise_mcp_server#90 — a real three-file diff, a real PR, and a card
    # reporting `"commit_url": null`.
    #
    # It survived because the unit tests mocked apply_changes as
    # `{"branch_url": "http://gh/branch"}` — a shape the real service never produces. The
    # fixture agreed with the bug, so the bug was invisible from both sides.
    #
    # fork_url is `<repo>/tree/<branch>`; the commit lives at `<repo>/commit/<sha>`.
    commit_sha = apply_resp.get("commit_sha")
    fork_url = str(apply_resp.get("fork_url") or "")
    repo_url = fork_url.split("/tree/")[0].rstrip("/") if fork_url else ""
    commit_url = f"{repo_url}/commit/{commit_sha}" if (repo_url and commit_sha) else None
    if commit_url is None:
        # A successful apply with nothing to point at. `no_changes=True` is the benign,
        # typed "every requested change was already present" signal coding-github emits
        # rather than fabricating a commit sha; anything else means the response shape
        # moved again, and the caller should be told which.
        return _CommitOutcome(
            None,
            None,
            None,
            "no_changes_to_apply"
            if apply_resp.get("no_changes") is True
            else "apply_changes_returned_no_commit_sha",
        )

    pr_url: str | None = None
    pr_number: int | None = None
    if options.open_pr:
        # Best effort to derive owner/repo from the container's repo_url.
        repo_url = getattr(container_info, "repo_url", "") or ""
        m = _github_owner_repo(repo_url)
        if not m:
            raise ValueError(
                f"cannot derive github owner/repo from container repo_url={repo_url!r}; "
                "open_pr=true requires a github.com URL"
            )
        owner, repo = m
        base_branch = getattr(container_info, "branch", "main") or "main"
        try:
            pr_resp = await github_client.create_pull_request(
                tenant_id=options.tenant_id,
                original_owner=owner,
                original_repo=repo,
                fork_owner=owner,
                fork_repo=repo,
                head_branch=options.branch_name,
                base_branch=base_branch,
                title=options.pr_title or f"deps: upgrade {len(changes)} manifest(s)",
                message=options.pr_body or "Automated dependency upgrade.",
                draft=options.draft,
            )
        except GithubClientError as exc:
            # Benign no-op: the post-upgrade manifests match the base branch, so
            # there is genuinely nothing to PR (e.g. the target version already
            # equals base). coding-github surfaces GitHub's "No commits between
            # <base> and <head>" 422 here — treat it as "no PR", not an error.
            if "no commits between" in str(exc).lower():
                return _CommitOutcome(commit_url, None, None)
            raise RuntimeError(f"create-pull-request failed: {exc}") from exc
        pr_url = pr_resp.get("pr_url")
        pr_number = pr_resp.get("pr_number")

    return _CommitOutcome(commit_url, pr_url, pr_number)


async def execute_in_range_upgrade(
    *,
    container_name: str,
    tenant_id: str,
    body: UpgradeRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
) -> UpgradeResponse:
    """Handle a /upgrade request (in-range bump)."""
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

    manager = body.manager
    if manager is None:
        manager = await _detect_manager(
            containers_client, container_name, tenant_id, body.project_path
        )

    container_body = {
        "manager": manager.value,
        "mode": "in-range",
        "packages": [{"name": p.name, "is_dev": p.is_dev} for p in body.packages],
        "major_specs": [],
        "project_path": body.project_path,
        "dry_run": body.dry_run,
        "timeout_seconds": body.timeout_seconds,
    }
    try:
        resp = await containers_client.package_upgrade(
            container_name=container_name,
            tenant_id=tenant_id,
            body=container_body,
        )
    except ContainersClientError as exc:
        raise RuntimeError(f"coding-containers /package-upgrade failed: {exc}") from exc

    manifest_diffs = _compute_diffs(
        resp.get("manifest_files_before") or {},
        resp.get("manifest_files_after") or {},
    )
    overall_success = int(resp.get("exit_code") or 0) == 0
    results = _build_package_results(
        [(p.name, None) for p in body.packages],
        resp.get("manifest_files_before") or {},
        resp.get("manifest_files_after") or {},
        overall_success,
    )

    options = _UpgradeOptions(
        container_name=container_name,
        tenant_id=tenant_id,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        commit=body.commit,
        branch_name=body.branch_name,
        open_pr=body.open_pr,
        draft=body.draft,
        pr_title=body.pr_title,
        pr_body=body.pr_body,
    )
    commit_url, pr_url, pr_number, commit_skip_reason = await _maybe_commit_and_pr(
        github_client=github_client,
        options=options,
        container_info=container_info,
        manifest_diffs=manifest_diffs,
        success=overall_success,
    )

    return UpgradeResponse(
        container_name=container_name,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        mode="in-range",
        results=results,
        manifest_diffs=manifest_diffs,
        commands_executed=resp.get("commands_executed") or [],
        stdout=resp.get("stdout") or "",
        stderr=resp.get("stderr") or "",
        exit_code=int(resp.get("exit_code") or 0),
        duration_seconds=float(resp.get("duration_seconds") or 0.0),
        commit_url=commit_url,
        commit_skip_reason=commit_skip_reason,
        pr_url=pr_url,
        pr_number=pr_number,
    )


async def execute_cross_major_upgrade(
    *,
    container_name: str,
    tenant_id: str,
    body: UpgradeMajorRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
) -> UpgradeResponse:
    """Handle a /upgrade-major request (constraint rewrite + bump)."""
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

    manager = body.manager
    if manager is None:
        manager = await _detect_manager(
            containers_client, container_name, tenant_id, body.project_path
        )

    container_body = {
        "manager": manager.value,
        "mode": "cross-major",
        "packages": [],
        "major_specs": [
            {
                "name": s.name,
                "target_version": s.target_version,
                "new_constraint": s.new_constraint,
                "is_dev": s.is_dev,
            }
            for s in body.packages
        ],
        "project_path": body.project_path,
        "dry_run": body.dry_run,
        "timeout_seconds": body.timeout_seconds,
    }
    try:
        resp = await containers_client.package_upgrade(
            container_name=container_name,
            tenant_id=tenant_id,
            body=container_body,
        )
    except ContainersClientError as exc:
        raise RuntimeError(f"coding-containers /package-upgrade failed: {exc}") from exc

    manifest_diffs = _compute_diffs(
        resp.get("manifest_files_before") or {},
        resp.get("manifest_files_after") or {},
    )
    overall_success = int(resp.get("exit_code") or 0) == 0
    results = _build_package_results(
        [(s.name, s.target_version) for s in body.packages],
        resp.get("manifest_files_before") or {},
        resp.get("manifest_files_after") or {},
        overall_success,
    )

    options = _UpgradeOptions(
        container_name=container_name,
        tenant_id=tenant_id,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        commit=body.commit,
        branch_name=body.branch_name,
        open_pr=body.open_pr,
        draft=body.draft,
        pr_title=body.pr_title,
        pr_body=body.pr_body,
    )
    commit_url, pr_url, pr_number, commit_skip_reason = await _maybe_commit_and_pr(
        github_client=github_client,
        options=options,
        container_info=container_info,
        manifest_diffs=manifest_diffs,
        success=overall_success,
        # Idempotent, base-relative commit: apply the full post-upgrade manifest
        # set onto a branch off base so a re-drive of an already-upgraded
        # container still opens (or returns the existing) PR.
        manifests_after=resp.get("manifest_files_after") or {},
    )

    return UpgradeResponse(
        container_name=container_name,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        mode="cross-major",
        results=results,
        manifest_diffs=manifest_diffs,
        commands_executed=resp.get("commands_executed") or [],
        stdout=resp.get("stdout") or "",
        stderr=resp.get("stderr") or "",
        exit_code=int(resp.get("exit_code") or 0),
        duration_seconds=float(resp.get("duration_seconds") or 0.0),
        commit_url=commit_url,
        commit_skip_reason=commit_skip_reason,
        pr_url=pr_url,
        pr_number=pr_number,
    )


# ============================================================================
# CVE-driven upgrade
# ============================================================================


_SEVERITY_RANK: dict[str, int] = {
    "LOW": 1,
    "MODERATE": 2,
    "MEDIUM": 2,  # OSV uses MEDIUM; treat as MODERATE
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_at_or_above(vuln_sev: str, threshold: str) -> bool:
    """Compare a vulnerability's severity string to the request threshold.

    Unknown severities (empty / non-standard) are treated as "high enough to
    surface" so callers don't silently miss CVEs with quirky severity fields.
    """
    sev = (vuln_sev or "").upper()
    if sev not in _SEVERITY_RANK:
        return True
    return _SEVERITY_RANK[sev] >= _SEVERITY_RANK[threshold.upper()]


def pick_safest_fix_version(
    installed_version: str | None,
    vulnerabilities: list[Vulnerability],
) -> str | None:
    """Pick the smallest version that clears every vulnerability for a package.

    Algorithm: for each vuln, pick the MINIMUM ``fixed_versions[i]`` that is
    strictly greater than ``installed_version`` (the per-vuln "smallest
    sufficient" target). The package-level answer is the MAXIMUM of those
    per-vuln minimums.

    Returns ``None`` if any vuln has no usable fix (empty ``fixed_versions``
    or only the ``*`` wildcard) — signal to the caller that the CVE can't
    be resolved by a version bump.
    """
    if not vulnerabilities:
        return None

    installed: Version | None = None
    if installed_version:
        try:
            installed = Version(installed_version)
        except InvalidVersion:
            installed = None

    per_vuln_minimum: list[Version] = []
    for vuln in vulnerabilities:
        usable = [v for v in vuln.fixed_versions if v and v != "*"]
        if not usable:
            return None  # at least one vuln has no fix → can't remediate

        parsed: list[Version] = []
        for raw in usable:
            try:
                parsed.append(Version(raw))
            except InvalidVersion:
                continue
        if not parsed:
            return None

        # Smallest fix strictly greater than installed.
        candidates = [v for v in parsed if installed is None or v > installed]
        if not candidates:
            # Already past every listed fix — package is no longer vulnerable
            # from this vuln's perspective. Skip it.
            continue
        per_vuln_minimum.append(min(candidates))

    if not per_vuln_minimum:
        return None  # everything is already-safe → no upgrade needed

    return str(max(per_vuln_minimum))


def constraint_allows(constraint: str | None, target_version: str) -> bool:
    """Return True if a PEP 440 constraint admits ``target_version``.

    Empty / missing constraint counts as "allows anything" (the package
    is lockfile-only or a transitive). Unparsable constraints fall back
    to True (permissive) so we don't refuse to apply a fix because we
    couldn't parse the spec.
    """
    if not constraint:
        return True
    try:
        spec = SpecifierSet(constraint)
        return Version(target_version) in spec
    except (InvalidSpecifier, InvalidVersion):
        return True


def _is_major_bump(current: str | None, target: str) -> bool:
    """True when ``target`` is a higher MAJOR version than ``current``.

    A same-major CVE fix (e.g. 2.31.0 -> 2.32.0) is a safe in-range remediation;
    a major bump (2.x -> 3.x) is potentially breaking and stays gated on
    ``allow_major``. Unparseable / missing current → treat as non-major.
    """
    if not current:
        return False
    try:
        return Version(target).major > Version(current).major
    except InvalidVersion:
        return False


def _version_ge(a: str | None, b: str) -> bool:
    """True when version ``a`` >= version ``b`` (both PEP 440); False if a is None/unparseable."""
    if not a:
        return False
    try:
        return Version(a) >= Version(b)
    except InvalidVersion:
        return False


def _join_vulns_by_package(
    vulnerabilities: list[Vulnerability],
    packages: list[ExternalPackage],
    severity_threshold: str,
    cve_filter: list[str] | None,
    pkg_filter: list[str] | None,
) -> dict[str, list[Vulnerability]]:
    """Group filtered vulnerabilities by their owning package name.

    Falls back to name-substring match against ``ExternalPackage.name`` when
    a vuln has no ``package_name`` (legacy data) — best effort, will miss
    cases where the vuln id doesn't mention the package.
    """
    cve_set = {c.upper() for c in cve_filter} if cve_filter else None
    pkg_set = {p.lower() for p in pkg_filter} if pkg_filter else None
    pkg_names = {p.name.lower() for p in packages}

    grouped: dict[str, list[Vulnerability]] = {}
    for vuln in vulnerabilities:
        if cve_set and vuln.id.upper() not in cve_set:
            continue
        if not _severity_at_or_above(vuln.severity, severity_threshold):
            continue

        name = (vuln.package_name or "").lower()
        if not name:
            # Legacy vuln without package_name — try to match via the vuln id
            # (e.g. ``PYSEC-2024-asyncpg-1234``) by checking each known
            # package name as a substring.
            for candidate in pkg_names:
                if candidate and candidate in vuln.id.lower():
                    name = candidate
                    break
            if not name:
                continue

        if pkg_set and name not in pkg_set:
            continue

        grouped.setdefault(name, []).append(vuln)
    return grouped


def _installed_version_for(name: str, packages: list[ExternalPackage]) -> str | None:
    for p in packages:
        if p.name.lower() == name.lower():
            return p.current_version or p.version
    return None


def _constraint_for(name: str, packages: list[ExternalPackage]) -> str | None:
    """The package's declared CONSTRAINT, for ``constraint_allows`` -> ``SpecifierSet``.

    This returned ``p.version``, which the manifest parsers strip of its operator — so
    ``SpecifierSet("3.4.7")`` was being asked to parse something that is not a PEP 440
    specifier at all. Prefer ``specifier``, which carries the operator as written; fall back
    to ``version`` for lockfile-sourced packages, which have no constraint to carry.
    """
    for p in packages:
        if p.name.lower() == name.lower():
            return p.specifier or p.version
    return None


async def execute_cve_upgrade(
    *,
    container_name: str,
    tenant_id: str,
    body: UpgradeCvesRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
    analyzer,  # ArchitectureDependencyAnalyzer; typed loosely to avoid import cycle
) -> UpgradeResponse:
    """Drive an upgrade off the analyzer's vulnerability report.

    See ``UpgradeCvesRequest`` docstring for behaviour. The ``analyzer``
    argument is dependency-injected so tests can swap a mock without
    importing the heavy real analyzer at module load.
    """
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)

    manager = body.manager
    if manager is None:
        manager = await _detect_manager(
            containers_client, container_name, tenant_id, body.project_path
        )

    # Reuse the existing dependency-fetch + analyze path.
    from routers.dependencies import resolve_repo_path

    async with resolve_repo_path(container_name, tenant_id) as repo:
        report = await analyzer.analyze(repo.path, container_name)
        # OR, never overwrite: analyze() already flags its own degradations.
        if repo.incomplete:
            mark_degraded(report, "dependency-manifest fetch was incomplete")

    severity_breakdown: dict[str, int] = {}
    for v in report.vulnerabilities:
        sev = (v.severity or "UNKNOWN").upper()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    grouped = _join_vulns_by_package(
        report.vulnerabilities,
        report.packages,
        body.min_severity,
        body.cve_ids,
        body.packages,
    )

    in_range_targets: list[UpgradePackageRef] = []
    cross_major_targets: list[MajorUpgradeSpec] = []
    fixed_cve_map: dict[str, list[str]] = {}
    package_constraints: dict[str, str | None] = {}
    package_targets: dict[str, str] = {}
    package_installed: dict[str, str | None] = {}
    skipped_results: list[PackageResult] = []
    skipped_needs_major = 0
    skipped_no_fix = 0
    fixed_count = 0

    for pkg_name, vulns in grouped.items():
        installed = _installed_version_for(pkg_name, report.packages)
        target = pick_safest_fix_version(installed, vulns)
        if target is None:
            skipped_no_fix += 1
            skipped_results.append(
                PackageResult(
                    name=pkg_name,
                    previous_version=installed,
                    success=False,
                    error="no remediation available (no fixed_versions for at least one CVE)",
                    fixed_cves=[v.id for v in vulns],
                    operation="upgrade",
                )
            )
            continue

        constraint = _constraint_for(pkg_name, report.packages)
        package_constraints[pkg_name] = constraint
        package_targets[pkg_name] = target
        package_installed[pkg_name] = installed
        fixed_cve_map[pkg_name] = [v.id for v in vulns]

        if constraint_allows(constraint, target):
            in_range_targets.append(UpgradePackageRef(name=pkg_name))
            fixed_count += 1
        elif body.allow_major:
            cross_major_targets.append(MajorUpgradeSpec(name=pkg_name, target_version=target))
            fixed_count += 1
        else:
            skipped_needs_major += 1
            skipped_results.append(
                PackageResult(
                    name=pkg_name,
                    previous_version=installed,
                    previous_constraint=constraint,
                    success=False,
                    error=(
                        f"needs allow_major=true (target={target}, current constraint={constraint})"
                    ),
                    fixed_cves=fixed_cve_map[pkg_name],
                    operation="upgrade-major",
                )
            )

    # Run the two batches sequentially (in-range first, then cross-major)
    # so the cross-major resolver sees an already-bumped lockfile.
    all_results: list[PackageResult] = list(skipped_results)
    manifest_diffs_combined: dict[str, ManifestDiff] = {}
    combined_stdout: list[str] = []
    combined_stderr: list[str] = []
    combined_commands: list[list[str]] = []
    overall_exit = 0
    duration_total = 0.0

    async def _dispatch_batch(
        mode: str, refs: list[UpgradePackageRef], specs: list[MajorUpgradeSpec]
    ) -> dict:
        cb = {
            "manager": manager.value,
            "mode": mode,
            "packages": [{"name": r.name, "is_dev": r.is_dev} for r in refs],
            "major_specs": [
                {
                    "name": s.name,
                    "target_version": s.target_version,
                    "new_constraint": s.new_constraint,
                    "is_dev": s.is_dev,
                }
                for s in specs
            ],
            "project_path": body.project_path,
            "dry_run": body.dry_run,
            "timeout_seconds": body.timeout_seconds,
        }
        return await containers_client.package_upgrade(
            container_name=container_name, tenant_id=tenant_id, body=cb
        )

    last_manifests_before: dict[str, str] = {}
    last_manifests_after: dict[str, str] = {}

    if in_range_targets:
        try:
            resp = await _dispatch_batch("in-range", in_range_targets, [])
        except ContainersClientError as exc:
            raise RuntimeError(f"coding-containers /package-upgrade failed: {exc}") from exc
        last_manifests_before = resp.get("manifest_files_before") or {}
        last_manifests_after = resp.get("manifest_files_after") or {}
        for d in _compute_diffs(last_manifests_before, last_manifests_after):
            manifest_diffs_combined[d.path] = d
        combined_stdout.append(resp.get("stdout") or "")
        combined_stderr.append(resp.get("stderr") or "")
        combined_commands.extend(resp.get("commands_executed") or [])
        overall_exit = int(resp.get("exit_code") or 0)
        duration_total += float(resp.get("duration_seconds") or 0.0)
        for ref in in_range_targets:
            prev = _find_version(ref.name, last_manifests_before)
            new = _find_version(ref.name, last_manifests_after)
            target = package_targets.get(ref.name)
            cleared = target is not None and _version_ge(new, target)
            if overall_exit == 0 and target is not None and not cleared:
                # The in-range path (`uv lock --upgrade-package`) respects the
                # pyproject constraint, so an EXACT pin (`requests==2.31.0`) — or
                # a constraint capped below the fix — leaves the version unmoved
                # and the CVE unfixed (it would otherwise be marked a false
                # "success" with no diff and no PR). Rewrite the constraint to
                # `>=target` (the cross-major path uses `uv add`, which rewrites
                # pyproject AND the lock). Same-major is a safe CVE remediation;
                # a genuine major bump still requires allow_major.
                if (
                    _is_major_bump(prev or package_installed.get(ref.name), target)
                    and not body.allow_major
                ):
                    all_results.append(
                        PackageResult(
                            name=ref.name,
                            previous_version=prev or package_installed.get(ref.name),
                            previous_constraint=package_constraints.get(ref.name),
                            success=False,
                            error=(
                                f"needs allow_major=true (target={target}; in-range "
                                f"upgrade could not clear the CVE within the current constraint)"
                            ),
                            fixed_cves=fixed_cve_map.get(ref.name, []),
                            operation="upgrade-major",
                        )
                    )
                    skipped_needs_major += 1
                    fixed_count -= 1
                else:
                    cross_major_targets.append(
                        MajorUpgradeSpec(
                            name=ref.name,
                            target_version=target,
                            new_constraint=f">={target}",
                        )
                    )
            else:
                all_results.append(
                    _single_package_result(
                        ref.name,
                        last_manifests_before,
                        last_manifests_after,
                        overall_exit == 0,
                        operation="upgrade",
                        cves=fixed_cve_map.get(ref.name, []),
                    )
                )

    if cross_major_targets and overall_exit == 0:
        try:
            resp = await _dispatch_batch("cross-major", [], cross_major_targets)
        except ContainersClientError as exc:
            raise RuntimeError(f"coding-containers /package-upgrade failed: {exc}") from exc
        before2 = resp.get("manifest_files_before") or {}
        after2 = resp.get("manifest_files_after") or {}
        # Diff against the in-range baseline so we capture only what
        # cross-major changed on top of the earlier bump.
        for d in _compute_diffs(before2, after2):
            manifest_diffs_combined[d.path] = d
        last_manifests_before = before2 if not last_manifests_before else last_manifests_before
        last_manifests_after = after2
        combined_stdout.append(resp.get("stdout") or "")
        combined_stderr.append(resp.get("stderr") or "")
        combined_commands.extend(resp.get("commands_executed") or [])
        overall_exit = int(resp.get("exit_code") or 0)
        duration_total += float(resp.get("duration_seconds") or 0.0)
        for spec in cross_major_targets:
            all_results.append(
                _single_package_result(
                    spec.name,
                    before2,
                    after2,
                    overall_exit == 0,
                    operation="upgrade-major",
                    cves=fixed_cve_map.get(spec.name, []),
                )
            )

    # `fixed_count` above is the PLANNED target count (packages we intended to
    # bump). Report `fixed` as what was ACTUALLY applied — the per-package
    # results whose upgrade command succeeded AND whose version cleared the fix.
    # Otherwise a repo whose `uv lock` cannot resolve (e.g. internally
    # unsatisfiable constraints → "No solution found", overall_exit != 0) would
    # be reported as `fixed=N` with no diff, no commit and no PR — a false
    # success. `applied_fixed` is 0 in that case; `exit_code` + `stderr` +
    # per-package `results[].error` carry the resolver reason.
    applied_fixed = sum(
        1 for r in all_results if r.success and r.operation in ("upgrade", "upgrade-major")
    )
    cve_summary = CveSummary(
        total_vulnerabilities_considered=sum(len(v) for v in grouped.values()),
        fixed=applied_fixed,
        skipped_needs_major=skipped_needs_major,
        skipped_no_fix_available=skipped_no_fix,
        severity_breakdown=severity_breakdown,
    )

    manifest_diffs = list(manifest_diffs_combined.values())
    options = _UpgradeOptions(
        container_name=container_name,
        tenant_id=tenant_id,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        commit=body.commit,
        branch_name=body.branch_name,
        open_pr=body.open_pr,
        draft=body.draft,
        pr_title=body.pr_title,
        pr_body=body.pr_body,
    )
    commit_url, pr_url, pr_number, commit_skip_reason = await _maybe_commit_and_pr(
        github_client=github_client,
        options=options,
        container_info=container_info,
        manifest_diffs=manifest_diffs,
        success=overall_exit == 0,
        # Idempotent, base-relative commit (same as execute_cross_major_upgrade):
        # apply the FULL post-upgrade manifest set onto a branch off base, so the
        # commit is gated on `options.commit` + a real diff-vs-base — NOT on the
        # fragile workspace before/after `manifest_diffs`, which comes back empty
        # when the container was already mutated (re-drive / multi-batch) and left
        # the CVE sweep with commit_url=null → no remote branch → no winner PR.
        manifests_after=last_manifests_after or {},
    )

    return UpgradeResponse(
        container_name=container_name,
        manager=manager,
        project_path=body.project_path,
        dry_run=body.dry_run,
        mode="upgrade-cves",
        results=all_results,
        manifest_diffs=manifest_diffs,
        commands_executed=combined_commands,
        stdout="\n".join(s for s in combined_stdout if s),
        stderr="\n".join(s for s in combined_stderr if s),
        exit_code=overall_exit,
        duration_seconds=duration_total,
        commit_url=commit_url,
        commit_skip_reason=commit_skip_reason,
        pr_url=pr_url,
        pr_number=pr_number,
        cve_summary=cve_summary,
    )


_VALID_OPERATIONS: frozenset[str] = frozenset(
    {"upgrade", "upgrade-major", "add", "remove", "replace"}
)


def _single_package_result(
    name: str,
    before: dict[str, str],
    after: dict[str, str],
    success: bool,
    *,
    operation: str,
    cves: list[str] | None = None,
) -> PackageResult:
    # Belt-and-braces: PackageResult.operation is a narrow Literal; coerce
    # via model_validate so a stray caller-supplied string surfaces as a
    # Pydantic ValidationError rather than a runtime AttributeError.
    return PackageResult.model_validate(
        {
            "name": name,
            "previous_version": _find_version(name, before),
            "new_version": _find_version(name, after),
            "previous_constraint": _find_constraint(name, before),
            "new_constraint": _find_constraint(name, after),
            "success": success,
            "error": None if success else "upgrade command exited non-zero",
            "fixed_cves": cves or [],
            "operation": operation if operation in _VALID_OPERATIONS else "upgrade",
        }
    )


# ============================================================================
# Add / Remove / Replace
# ============================================================================


async def execute_add(
    *,
    container_name: str,
    tenant_id: str,
    body: AddDependenciesRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
) -> UpgradeResponse:
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)
    manager = body.manager or await _detect_manager(
        containers_client, container_name, tenant_id, body.project_path
    )
    return await _call_modify(
        container_name=container_name,
        tenant_id=tenant_id,
        container_info=container_info,
        manager=manager,
        action="add",
        add_specs=[
            {
                "name": s.name,
                "version": s.version,
                "constraint": s.constraint,
                "is_dev": s.is_dev,
                "extras": s.extras,
            }
            for s in body.packages
        ],
        remove_names=[],
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        opts=_UpgradeOptions(
            container_name=container_name,
            tenant_id=tenant_id,
            manager=manager,
            project_path=body.project_path,
            dry_run=body.dry_run,
            timeout_seconds=body.timeout_seconds,
            commit=body.commit,
            branch_name=body.branch_name,
            open_pr=body.open_pr,
            draft=body.draft,
            pr_title=body.pr_title,
            pr_body=body.pr_body,
        ),
        containers_client=containers_client,
        github_client=github_client,
        names_for_results=[s.name for s in body.packages],
    )


async def execute_remove(
    *,
    container_name: str,
    tenant_id: str,
    body: RemoveDependenciesRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
) -> UpgradeResponse:
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)
    manager = body.manager or await _detect_manager(
        containers_client, container_name, tenant_id, body.project_path
    )
    return await _call_modify(
        container_name=container_name,
        tenant_id=tenant_id,
        container_info=container_info,
        manager=manager,
        action="remove",
        add_specs=[],
        remove_names=list(body.packages),
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        opts=_UpgradeOptions(
            container_name=container_name,
            tenant_id=tenant_id,
            manager=manager,
            project_path=body.project_path,
            dry_run=body.dry_run,
            timeout_seconds=body.timeout_seconds,
            commit=body.commit,
            branch_name=body.branch_name,
            open_pr=body.open_pr,
            draft=body.draft,
            pr_title=body.pr_title,
            pr_body=body.pr_body,
        ),
        containers_client=containers_client,
        github_client=github_client,
        names_for_results=list(body.packages),
    )


async def execute_replace(
    *,
    container_name: str,
    tenant_id: str,
    body: ReplaceDependenciesRequest,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
) -> UpgradeResponse:
    container_info = await validate_and_get_container_for_tenant(container_name, tenant_id)
    manager = body.manager or await _detect_manager(
        containers_client, container_name, tenant_id, body.project_path
    )

    add_specs: list[dict] = []
    remove_names: list[str] = []
    for r in body.replacements:
        remove_names.append(r.old)
        add_specs.append(
            {
                "name": r.new,
                "version": r.new_version,
                "constraint": r.new_constraint,
                "is_dev": r.is_dev,
                "extras": r.extras,
            }
        )

    return await _call_modify(
        container_name=container_name,
        tenant_id=tenant_id,
        container_info=container_info,
        manager=manager,
        action="replace",
        add_specs=add_specs,
        remove_names=remove_names,
        project_path=body.project_path,
        dry_run=body.dry_run,
        timeout_seconds=body.timeout_seconds,
        opts=_UpgradeOptions(
            container_name=container_name,
            tenant_id=tenant_id,
            manager=manager,
            project_path=body.project_path,
            dry_run=body.dry_run,
            timeout_seconds=body.timeout_seconds,
            commit=body.commit,
            branch_name=body.branch_name,
            open_pr=body.open_pr,
            draft=body.draft,
            pr_title=body.pr_title,
            pr_body=body.pr_body,
        ),
        containers_client=containers_client,
        github_client=github_client,
        names_for_results=[r.new for r in body.replacements],
        replacements_for_pr=body.replacements,
    )


async def _call_modify(
    *,
    container_name: str,
    tenant_id: str,
    container_info,
    manager: LanguagePackageManager,
    action: str,
    add_specs: list[dict],
    remove_names: list[str],
    project_path: str,
    dry_run: bool,
    timeout_seconds: int,
    opts: _UpgradeOptions,
    containers_client: ContainersClient,
    github_client: GithubClient | None,
    names_for_results: list[str],
    replacements_for_pr: list[ReplacementSpec] | None = None,
) -> UpgradeResponse:
    cb = {
        "manager": manager.value,
        "action": action,
        "add_specs": add_specs,
        "remove_names": remove_names,
        "project_path": project_path,
        "dry_run": dry_run,
        "timeout_seconds": timeout_seconds,
    }
    try:
        resp = await containers_client.package_modify(
            container_name=container_name, tenant_id=tenant_id, body=cb
        )
    except ContainersClientError as exc:
        raise RuntimeError(f"coding-containers /package-modify failed: {exc}") from exc

    manifest_diffs = _compute_diffs(
        resp.get("manifest_files_before") or {},
        resp.get("manifest_files_after") or {},
    )
    overall_success = int(resp.get("exit_code") or 0) == 0
    results = [
        _single_package_result(
            n,
            resp.get("manifest_files_before") or {},
            resp.get("manifest_files_after") or {},
            overall_success,
            operation=action,
        )
        for n in names_for_results
    ]

    # For /replace specifically, run an import-site grep against each OLD
    # name and tack the results onto the PR body so the reviewer doesn't
    # merge a broken codebase.
    if replacements_for_pr and opts.open_pr and overall_success:
        hints = await _build_replace_pr_hints(
            containers_client,
            container_name,
            tenant_id,
            project_path,
            manager,
            replacements_for_pr,
        )
        if hints:
            opts.pr_body = (opts.pr_body or "") + "\n\n## Still needed: code changes\n" + hints

    commit_url, pr_url, pr_number, commit_skip_reason = await _maybe_commit_and_pr(
        github_client=github_client,
        options=opts,
        container_info=container_info,
        manifest_diffs=manifest_diffs,
        success=overall_success,
    )

    return UpgradeResponse(
        container_name=container_name,
        manager=manager,
        project_path=project_path,
        dry_run=dry_run,
        mode=action,
        results=results,
        manifest_diffs=manifest_diffs,
        commands_executed=resp.get("commands_executed") or [],
        stdout=resp.get("stdout") or "",
        stderr=resp.get("stderr") or "",
        exit_code=int(resp.get("exit_code") or 0),
        duration_seconds=float(resp.get("duration_seconds") or 0.0),
        commit_url=commit_url,
        commit_skip_reason=commit_skip_reason,
        pr_url=pr_url,
        pr_number=pr_number,
    )


# ============================================================================
# Import-site grep — used by /replace to annotate PR bodies
# ============================================================================


_GREP_PATTERNS_BY_MANAGER: dict[LanguagePackageManager, list[str]] = {
    LanguagePackageManager.UV: [
        r"^\s*(from|import)\s+{name}\b",
    ],
    LanguagePackageManager.PIP: [r"^\s*(from|import)\s+{name}\b"],
    LanguagePackageManager.POETRY: [r"^\s*(from|import)\s+{name}\b"],
    LanguagePackageManager.PIPENV: [r"^\s*(from|import)\s+{name}\b"],
    LanguagePackageManager.CONDA: [r"^\s*(from|import)\s+{name}\b"],
    LanguagePackageManager.NPM: [r"from\s+['\"]{name}['\"]", r"require\(['\"]{name}['\"]\)"],
    LanguagePackageManager.YARN: [r"from\s+['\"]{name}['\"]", r"require\(['\"]{name}['\"]\)"],
    LanguagePackageManager.PNPM: [r"from\s+['\"]{name}['\"]", r"require\(['\"]{name}['\"]\)"],
    LanguagePackageManager.BUN: [r"from\s+['\"]{name}['\"]", r"require\(['\"]{name}['\"]\)"],
    LanguagePackageManager.CARGO: [r"^\s*use\s+{name}(::|;)"],
    LanguagePackageManager.GO_MOD: [r'"{name}"'],
    LanguagePackageManager.COMPOSER: [r"use\s+{name}\\", r"\\{name}\\"],
    LanguagePackageManager.BUNDLER: [r"require\s+['\"]{name}['\"]"],
    LanguagePackageManager.GEM: [r"require\s+['\"]{name}['\"]"],
}


async def _grep_import_sites(
    client: ContainersClient,
    container_name: str,
    tenant_id: str,
    project_path: str,
    old_name: str,
    manager: LanguagePackageManager,
) -> list[str]:
    """Return up to 50 file paths that import ``old_name`` inside the project.

    Best-effort — failures (no grep, weird stdout) return an empty list so
    the replace PR ships without the hint section rather than blocking.
    """
    patterns = _GREP_PATTERNS_BY_MANAGER.get(manager)
    if not patterns:
        return []

    # ``grep -rlE pattern path`` is the simplest cross-distro flag set.
    # Quote both ourselves; the exec wrapper joins argv as-is.
    workdir = "/workspace"
    target = (
        f"{workdir}/{project_path.lstrip('/')}" if project_path and project_path != "." else workdir
    )
    name_esc = re.escape(old_name)
    combined_pattern = "|".join(p.format(name=name_esc) for p in patterns)

    try:
        result = await client.exec_command(
            container_name=container_name,
            tenant_id=tenant_id,
            command=["grep", "-rlE", combined_pattern, target],
            workdir=workdir,
            timeout=30,
        )
    except (ContainersClientError, RuntimeError):
        return []

    out = (result.get("stdout") or "").strip()
    if not out:
        return []
    files = [line.strip() for line in out.splitlines() if line.strip()]
    return files[:50]


async def _build_replace_pr_hints(
    client: ContainersClient,
    container_name: str,
    tenant_id: str,
    project_path: str,
    manager: LanguagePackageManager,
    replacements: list[ReplacementSpec],
) -> str:
    """Compose a bullet list of import-site hits for the PR body."""
    sections: list[str] = []
    for r in replacements:
        hits = await _grep_import_sites(
            client, container_name, tenant_id, project_path, r.old, manager
        )
        if hits:
            section = f"### `{r.old}` → `{r.new}` ({len(hits)} file(s))\n" + "\n".join(
                f"- `{h}`" for h in hits
            )
            sections.append(section)
    if not sections:
        return ""
    return (
        "Dependency manifest + lockfile have been updated, but the code below "
        "still references the old package. These must be migrated before the PR "
        "can build:\n\n" + "\n\n".join(sections)
    )


__all__ = [
    "MajorUpgradeSpec",  # re-export for routes
    "UpgradePackageRef",
    "constraint_allows",
    "execute_add",
    "execute_cross_major_upgrade",
    "execute_cve_upgrade",
    "execute_in_range_upgrade",
    "execute_remove",
    "execute_replace",
    "pick_safest_fix_version",
]
