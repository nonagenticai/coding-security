"""Which repository of a multi-repo workspace a scan is about.

Same contract (field name ``repo``, values, semantics) as coding-analysis
``src/processing/workspace_repos.py``, so an agent passes the same selector to
every coding service.

A py2rust workspace holds ONE primary repository at the workspace root (the
Rust target) plus read-only source checkouts that coding-containers places at
``<root>/.repos/<owner>__<repo>``.

* the default selector is :data:`PRIMARY_REPO`: the scan root is the workspace
  root and ``.repos/`` is EXCLUDED from it;
* ``repo=".repos/<name>"`` (or the bare ``<name>``) moves the scan root to that
  checkout; paths in the answer are then relative to that checkout.
"""

from __future__ import annotations

import re

#: Selector value for the workspace's own repository (the workspace root).
PRIMARY_REPO = "primary"
#: Directory, relative to the workspace root, that holds the source checkouts.
REPOS_DIR = ".repos"

#: One safe path segment: no ``/``, no ``..``, not hidden -> cannot escape ``.repos/``.
_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")

REPO_FIELD_DESCRIPTION = (
    "Which repository of the workspace to scan. Omitted or 'primary' = the "
    "workspace's own repository at the workspace root, with the source checkouts "
    "under '.repos/' EXCLUDED. '.repos/<name>' (or the bare '<name>') = that one "
    "source checkout; file paths in the answer are then relative to it."
)


def normalize_repo(value: str | None) -> str:
    """Return the canonical selector: ``"primary"`` or ``".repos/<name>"``.

    Raises:
        ValueError: anything that is not ``primary``, ``<name>`` or
            ``.repos/<name>`` with a single safe path segment as ``<name>``.
    """
    if value is None:
        return PRIMARY_REPO
    if not isinstance(value, str):
        raise ValueError("repo must be a string")
    raw = value.strip().strip("/")
    if raw in ("", PRIMARY_REPO, "."):
        return PRIMARY_REPO
    name = raw[len(REPOS_DIR) + 1 :] if raw.startswith(REPOS_DIR + "/") else raw
    if not _REPO_NAME_RE.match(name) or ".." in name:
        raise ValueError(
            f"repo must be 'primary' or '{REPOS_DIR}/<name>' with a single-segment name, "
            f"got {value!r}"
        )
    return f"{REPOS_DIR}/{name}"


def repo_root(workspace_root: str, repo: str | None) -> str:
    """Absolute scan root for *repo* under *workspace_root* (remote or local)."""
    root = workspace_root.rstrip("/") or "/"
    canonical = normalize_repo(repo)
    if canonical == PRIMARY_REPO:
        return root
    return f"{root.rstrip('/')}/{canonical}"


#: Dot-paths a source fetch must still pull even though the rest of the hidden
#: space is excluded. CI workflow definitions and environment files are where
#: hardcoded secrets live; the blanket dot-exclusion made them invisible to
#: every engine. Patterns are relative to the scan root. ``*`` crosses ``/`` in
#: ``find -path``, so ``*/.env`` covers an ``.env`` at ANY depth while
#: ``{base}/.env`` covers one at the root. CI definitions are listed at the
#: root AND under ``*/`` so nested checkouts (``frontend/.github/...``) fetch
#: the same files the local walk admits.
_ALLOWED_HIDDEN_PATHS: tuple[str, ...] = (
    # GitHub: workflows and composite actions, root and nested.
    ".github/workflows/*",
    ".github/actions/*",
    "*/.github/workflows/*",
    "*/.github/actions/*",
    # GitLab CI, root and nested.
    ".gitlab-ci.yml",
    "*/.gitlab-ci.yml",
    ".gitlab/ci/*",
    "*/.gitlab/ci/*",
    # CircleCI config, root and nested.
    ".circleci/config.yml",
    "*/.circleci/config.yml",
    # Pre-commit config, root and nested.
    ".pre-commit-config.yaml",
    "*/.pre-commit-config.yaml",
    # Dotenv files have no language and live at any depth.
    ".env",
    ".env.*",
    "*/.env",
    "*/.env.*",
)


def hidden_exclude_args(root: str) -> list[str]:
    """``find`` arguments that drop hidden path components BELOW *root* only.

    The fetches used to pass ``-not -path '*/.*'``, which (``*`` crosses ``/``)
    also matched the root itself when the root is ``<ws>/.repos/<name>`` and so
    excluded every file of a source checkout. Anchoring at *root* keeps the
    old behaviour for the primary repo (``.repos/``, ``.git``, ``.venv`` ... are
    still skipped) and makes an explicit ``.repos/<name>`` root scannable.

    Hidden paths are excluded EXCEPT the CI/dotenv files a secrets scan must
    see (:data:`_ALLOWED_HIDDEN_PATHS`). ``find`` has no lookahead, so
    "hidden AND NOT allowlisted" is expressed as
    ``-not \\( \\( hidden... \\) -not \\( allowed... \\) \\)``.
    """
    base = root.rstrip("/")
    hidden = [f"{base}/.*", f"{base}/*/.*"]
    allowed = [f"{base}/{pattern}" for pattern in _ALLOWED_HIDDEN_PATHS]

    def path_group(patterns: list[str]) -> list[str]:
        """``( -path A -o -path B ... )`` — one primary per pattern."""
        args = ["("]
        for index, pattern in enumerate(patterns):
            if index:
                args.append("-o")
            args.extend(["-path", pattern])
        args.append(")")
        return args

    return ["-not", "("] + path_group(hidden) + ["-not"] + path_group(allowed) + [")"]
