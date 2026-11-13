"""Request / response models for the dependency-upgrade endpoints.

Mirrors the typed contract of coding-containers' ``POST /api/workspaces/{name}/package-upgrade``
but exposes a more user-friendly surface — auto-detect manager, optional commit + PR.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from models.package_manager_models import LanguagePackageManager


class UpgradePackageRef(BaseModel):
    """Identifier used in /upgrade (in-range bump)."""

    name: str = Field(..., min_length=1, max_length=128)
    is_dev: bool = Field(
        default=False,
        description="Hint for managers that distinguish dev deps (npm/yarn/pnpm/composer).",
    )

    model_config = ConfigDict(extra="forbid")


class UpgradeRequest(BaseModel):
    """In-range upgrade. Bumps within the constraint currently in the manifest."""

    packages: list[UpgradePackageRef] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Packages to bump.",
        json_schema_extra={"x-n8n-type": "json"},
    )
    manager: LanguagePackageManager | None = Field(
        default=None,
        description="Override auto-detected package manager. Auto-detect inspects the "
        "manifests present in ``project_path``.",
    )
    project_path: str = Field(
        default=".",
        max_length=512,
        description="Relative path inside the repo root where the manager runs.",
    )
    dry_run: bool = False
    timeout_seconds: int = Field(default=300, ge=10, le=1800)

    commit: bool = Field(
        default=False,
        description="Commit the resulting lockfile changes via coding-github "
        "/api/repositories/apply-changes. Requires ``branch_name``.",
    )
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = Field(
        default=False,
        description="If commit=True, additionally open a PR back to the upstream repo.",
    )
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")


class MajorUpgradeSpec(BaseModel):
    """Identifier used in /upgrade-major (constraint rewrite + bump)."""

    name: str = Field(..., min_length=1, max_length=128)
    target_version: str | None = Field(default=None, max_length=64)
    new_constraint: str | None = Field(
        default=None,
        max_length=128,
        description="Explicit constraint (e.g., '>=3.0.0,<4.0.0'). When absent the "
        "endpoint derives ``>={target_version},<{major+1}.0.0`` for SemVer ecosystems.",
    )
    is_dev: bool = False

    model_config = ConfigDict(extra="forbid")


class UpgradeMajorRequest(BaseModel):
    """Cross-major upgrade. Rewrites the manifest constraint AND bumps the lock."""

    packages: list[MajorUpgradeSpec] = Field(
        ..., min_length=1, max_length=20, json_schema_extra={"x-n8n-type": "json"}
    )
    manager: LanguagePackageManager | None = None
    project_path: str = Field(default=".", max_length=512)
    dry_run: bool = False
    timeout_seconds: int = Field(default=600, ge=10, le=1800)

    commit: bool = False
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = False
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")


class ManifestDiff(BaseModel):
    path: str
    before: str
    after: str

    model_config = ConfigDict(extra="forbid")


class PackageResult(BaseModel):
    name: str
    previous_version: str | None = None
    new_version: str | None = None
    previous_constraint: str | None = None
    new_constraint: str | None = None
    success: bool
    error: str | None = None
    # New in v1.2.0 — used by the CVE-driven and modify routes.
    fixed_cves: list[str] = Field(default_factory=list)
    operation: Literal["upgrade", "upgrade-major", "add", "remove", "replace"] = "upgrade"

    model_config = ConfigDict(extra="forbid")


class CveSummary(BaseModel):
    """High-level rollup of a CVE-driven upgrade run."""

    total_vulnerabilities_considered: int
    fixed: int
    skipped_needs_major: int
    skipped_no_fix_available: int
    severity_breakdown: dict[str, int] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


CommitSkipReason = Literal[
    # The upgrade itself failed; committing a half-applied manifest set is never right.
    "upgrade_failed",
    # commit=False — the caller asked for a dry run of the change, not a commit.
    "commit_not_requested",
    # commit=True but there was nothing to write (empty post-upgrade manifest set).
    "no_manifest_changes",
    # commit=True but the workspace before/after diff was empty (legacy diff mode).
    "no_workspace_diff",
    # ⛔ THE DEFECT THIS ENUM WAS ADDED FOR. coding-security asked apply-changes for
    # `branch_url` or `commit_url`; ApplyChangesResponse emits NEITHER — its fields are
    # branch_name / commit_sha / changes_applied / no_changes / fork_url. So commit_url
    # was not "sometimes null", it was STRUCTURALLY ALWAYS null on this path. The URL is
    # now derived from commit_sha + fork_url, and this reason survives only for the case
    # where apply-changes reports a successful commit with no sha to point at.
    "apply_changes_returned_no_commit_sha",
    # apply-changes reported no_changes=True: every requested change was already present.
    "no_changes_to_apply",
]


class UpgradeResponse(BaseModel):
    container_name: str
    manager: LanguagePackageManager
    project_path: str
    dry_run: bool
    mode: str  # "in-range" | "cross-major" | "add" | "remove" | "replace" | "upgrade-cves"
    results: list[PackageResult]
    manifest_diffs: list[ManifestDiff]
    commands_executed: list[list[str]]
    stdout: str
    stderr: str
    exit_code: int
    duration_seconds: float
    commit_url: str | None = None
    # WHY A REASON, AND NOT JUST A NULL. `commit_url` was null on a chore that
    # demonstrably committed (enterprise_mcp_server#90, a real three-file diff), and
    # the caller could not tell that apart from "nothing to commit" or "commit was not
    # requested" — four different situations arriving as one silent None. A card cannot
    # print a refusal it cannot name. This field names it; it is None whenever
    # `commit_url` is set, so the two are never both meaningful.
    commit_skip_reason: CommitSkipReason | None = None
    pr_url: str | None = None
    # PR number of the opened PR (when open_pr=True). Threaded downstream so the
    # AA delivery pipeline can mark a draft PR ready for review once QA is green.
    pr_number: int | None = None
    # Populated only by ``/upgrade-cves``; None on the other routes.
    cve_summary: CveSummary | None = None

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# CVE-driven upgrade
# ============================================================================


class UpgradeCvesRequest(BaseModel):
    """Drive an upgrade off the analyzer's vulnerability report.

    For each affected package, the orchestrator picks the minimum version
    that clears every CVE meeting the ``min_severity`` threshold (and any
    ``cve_ids`` / ``packages`` filters) and dispatches the right verb —
    in-range when the current manifest constraint admits the fix,
    cross-major otherwise.
    """

    min_severity: Literal["LOW", "MODERATE", "HIGH", "CRITICAL"] = "HIGH"
    cve_ids: list[str] | None = None
    packages: list[str] | None = None
    allow_major: bool = True
    manager: LanguagePackageManager | None = None
    project_path: str = Field(default=".", max_length=512)
    dry_run: bool = False
    timeout_seconds: int = Field(default=900, ge=10, le=1800)
    commit: bool = False
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = False
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# Add / remove / replace
# ============================================================================


class AddDependencySpec(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    constraint: str | None = Field(default=None, max_length=128)
    is_dev: bool = False
    extras: list[str] = Field(default_factory=list, max_length=16)

    model_config = ConfigDict(extra="forbid")


class AddDependenciesRequest(BaseModel):
    packages: list[AddDependencySpec] = Field(
        ..., min_length=1, max_length=20, json_schema_extra={"x-n8n-type": "json"}
    )
    manager: LanguagePackageManager | None = None
    project_path: str = Field(default=".", max_length=512)
    dry_run: bool = False
    timeout_seconds: int = Field(default=600, ge=10, le=1800)
    commit: bool = False
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = False
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")


class RemoveDependenciesRequest(BaseModel):
    packages: list[str] = Field(..., min_length=1, max_length=20)
    manager: LanguagePackageManager | None = None
    project_path: str = Field(default=".", max_length=512)
    dry_run: bool = False
    timeout_seconds: int = Field(default=600, ge=10, le=1800)
    commit: bool = False
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = False
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")


class ReplacementSpec(BaseModel):
    old: str = Field(..., min_length=1, max_length=128)
    new: str = Field(..., min_length=1, max_length=128)
    new_version: str | None = Field(default=None, max_length=64)
    new_constraint: str | None = Field(default=None, max_length=128)
    is_dev: bool = False
    extras: list[str] = Field(default_factory=list, max_length=16)

    model_config = ConfigDict(extra="forbid")


class ReplaceDependenciesRequest(BaseModel):
    replacements: list[ReplacementSpec] = Field(..., min_length=1, max_length=10)
    manager: LanguagePackageManager | None = None
    project_path: str = Field(default=".", max_length=512)
    dry_run: bool = False
    timeout_seconds: int = Field(default=900, ge=10, le=1800)
    commit: bool = False
    branch_name: str | None = Field(default=None, max_length=255)
    open_pr: bool = False
    draft: bool = Field(
        default=False,
        description="If open_pr=True, open the PR as a draft (not ready for review). "
        "The AA delivery pipeline opens during DOING as draft and publishes "
        "(marks ready) only once QA is green.",
    )
    pr_title: str | None = Field(default=None, max_length=255)
    pr_body: str | None = Field(default=None, max_length=10_000)

    model_config = ConfigDict(extra="forbid")
