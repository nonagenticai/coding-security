"""Typed httpx wrapper for coding-github apply-changes + create-pull-request.

Both endpoints live in ``coding-github`` (port 8692). This wrapper makes the
optional ``commit`` / ``open_pr`` path on the upgrade endpoints easy to mock
in tests and avoids leaking httpx into the orchestrator.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from clients.outbound import sibling_headers

logger = logging.getLogger(__name__)


class GithubClientError(RuntimeError):
    def __init__(self, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class GithubClient:
    def __init__(self, base_url: str, *, timeout: float = 120.0) -> None:
        if not base_url:
            raise ValueError("github_service_url is empty")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    async def apply_changes(
        self,
        *,
        tenant_id: str,
        container_name: str,
        branch_name: str,
        changes: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Commit ``changes`` (list of {file_path, content}) on a new branch.

        Mirrors the request shape of coding-github's
        ``POST /api/repositories/apply-changes`` (``ApplyChangesRequest``).
        """
        url = f"{self._base_url}/api/repositories/apply-changes"
        body = {
            "container_name": container_name,
            "branch_name": branch_name,
            "changes": changes,
        }
        return await self._post(url, tenant_id, body)

    async def create_pull_request(
        self,
        *,
        tenant_id: str,
        original_owner: str,
        original_repo: str,
        fork_owner: str,
        fork_repo: str,
        head_branch: str,
        base_branch: str,
        title: str,
        message: str,
        draft: bool = False,
    ) -> dict[str, Any]:
        url = f"{self._base_url}/api/repositories/create-pull-request"
        body = {
            "original_owner": original_owner,
            "original_repo": original_repo,
            "fork_owner": fork_owner,
            "fork_repo": fork_repo,
            "head_branch": head_branch,
            "base_branch": base_branch,
            "title": title,
            "message": message,
            "draft": draft,
        }
        return await self._post(url, tenant_id, body)

    async def _post(self, url: str, tenant_id: str, body: dict) -> dict[str, Any]:
        headers = {
            **sibling_headers(tenant_id, operation=f"coding-github {url}"),
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise GithubClientError(None, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise GithubClientError(
                resp.status_code,
                f"coding-github HTTP {resp.status_code}: {resp.text[:500]}",
            )
        return resp.json()
