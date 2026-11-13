"""Latest-version lookup for the ``/outdated`` path, resolved INSIDE the workspace.

``ExternalPackage.latest_version`` has no other setter in the request path, so
without this ``/outdated`` filters on a field that is always None and answers
``[]`` for every repo.

The coding-security pod has NO internet egress (the namespace's
``default-restrict`` NetworkPolicy allows only the coding-* namespaces, DNS, the
registry and minio), so the lookup must never go to PyPI from here. The
per-repo workspace pod can reach PyPI, so we ask uv there::

    uv tree --outdated --depth 1 --all-groups --frozen --color never --no-progress

``--frozen`` reads ``uv.lock`` without re-locking or touching the venv, so the
call is read-only and needs no sync. Sample output (uv 0.10.x)::

    x v0.1
    ├── httpx v0.24.0 (latest: v0.28.1)
    ├── ruff v0.1.0 (latest: v0.17.3)
    └── pytest v7.0.0 (group: dev) (latest: v9.1.1)

``--depth 1`` limits it to the project's DIRECT dependencies, so transitive
packages never get a ``latest_version`` and are never reported as outdated.
``uv lock --upgrade --dry-run`` was rejected: it only reports moves permitted by
the declared constraints, so an exact pin (``==``) reads as "no changes".
Only uv projects are supported; other ecosystems keep their previous behaviour.
"""

from __future__ import annotations

import logging
import re

from clients.containers_client import ContainersClient, ContainersClientError
from models.package_manager_models import ExternalPackage

logger = logging.getLogger(__name__)

UV_OUTDATED_COMMAND = [
    "uv",
    "tree",
    "--outdated",
    "--depth",
    "1",
    "--all-groups",
    "--frozen",
    "--color",
    "never",
    "--no-progress",
]
EXEC_TIMEOUT_SECONDS = 90

# "├── ruff v0.1.0 (group: dev) (latest: v0.17.3)" -> name, current, latest.
# Two linear steps: the head (possessive, nothing to backtrack into) and then the
# first ``(latest: v...)`` after it. The previous one-pattern form
# ``v(\S+).*?\(latest: ...`` backtracked ``\S+`` one character at a time and rescanned
# the rest of the line for each, i.e. quadratic on a long token with no marker.
_LINE = re.compile(r"^[\s│├└─]*+(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*+) v\S")
_LATEST = re.compile(r"\(latest: v(?P<latest>[^)\s]++)\)")


class LatestLookupError(RuntimeError):
    """The in-workspace lookup could not run; the result would be unknown, not empty."""


def normalize_name(name: str) -> str:
    """PEP 503 normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_uv_tree_outdated(stdout: str) -> dict[str, str]:
    """Map normalised package name -> latest version from ``uv tree --outdated`` output."""
    latest: dict[str, str] = {}
    for line in stdout.splitlines():
        head = _LINE.match(line)
        marker = _LATEST.search(line, head.end()) if head else None
        if head and marker:
            latest[normalize_name(head.group("name"))] = marker.group("latest")
    return latest


async def fetch_latest_in_workspace(
    client: ContainersClient, *, container_name: str, tenant_id: str
) -> dict[str, str]:
    """Run uv in the workspace and return ``{normalised name: latest version}``.

    Raises :class:`LatestLookupError` on any transport/HTTP/exit-code failure so
    the caller answers 503 instead of an empty list that reads "up to date".
    """
    try:
        resp = await client.exec_command(
            container_name=container_name,
            tenant_id=tenant_id,
            command=UV_OUTDATED_COMMAND,
            workdir="/workspace",
            timeout=EXEC_TIMEOUT_SECONDS,
        )
    except ContainersClientError as exc:
        raise LatestLookupError(f"workspace exec failed: {exc}") from exc
    exit_code = int(resp.get("exit_code") or 0)
    if exit_code != 0:
        stderr = (resp.get("stderr") or "").strip()[:300]
        raise LatestLookupError(f"`uv tree --outdated` exited {exit_code}: {stderr}")
    return parse_uv_tree_outdated(resp.get("stdout") or "")


def apply_latest_versions(
    packages: list[ExternalPackage], latest: dict[str, str]
) -> list[ExternalPackage]:
    """Copy packages with ``current_version`` (the resolved ``version``) and ``latest_version`` set."""
    out: list[ExternalPackage] = []
    for pkg in packages:
        found = latest.get(normalize_name(pkg.name)) if pkg.ecosystem == "pypi" else None
        if not found:
            out.append(pkg)
            continue
        out.append(
            pkg.model_copy(
                update={
                    "current_version": pkg.current_version or pkg.version,
                    "latest_version": found,
                }
            )
        )
    return out
