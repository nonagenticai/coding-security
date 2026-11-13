"""Container registry module — fetches container metadata from coding-containers service.

Instead of reading a local JSON file (which is never populated), this module
makes HTTP calls to the coding-containers service. The URL is read from
``settings.containers_service_url`` (env: ``CONTAINERS_SERVICE_URL``); it must
be set via gitops env in production — there is no code-side default.

Public API (unchanged):
    ContainerMetadataRegistry
        .get_container(name)          -> ContainerInfo | None   (sync)
        .find_by_name(name)           -> ContainerInfo | None   (sync)
        .find_by_name_pattern(ident)  -> ContainerInfo | None   (sync)
        .list()                       -> list[ContainerInfo]     (sync)
        .get_container_async(name)    -> ContainerInfo | None   (async)
        .find_by_name_async(name)     -> ContainerInfo | None   (async)
        .list_async()                 -> list[ContainerInfo]     (async)

    get_container_registry()          -> ContainerMetadataRegistry (singleton)
"""

from __future__ import annotations

import builtins
import logging
from typing import Any

import httpx
from coding_client.clients import CodingWorkspacesClient, ServiceError

from clients.outbound import optional_sibling_headers
from config.settings import get_settings
from models.container_models import ContainerInfo

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


def _containers_service_url() -> str:
    """Resolve coding-containers base URL from settings (env-only, no fallback)."""
    return get_settings().containers_service_url


def _parse_container(data: dict[str, Any]) -> ContainerInfo:
    """Build a ContainerInfo from the JSON returned by coding-containers."""
    return ContainerInfo(**data)


class ContainerMetadataRegistry:
    """Registry that delegates to the coding-containers HTTP service."""

    # ── synchronous helpers (used by _resolve_container_file_paths etc.) ──
    #
    # DELIBERATE ASYMMETRY, do not "fix" by deleting one half: the async methods
    # below go through ``CodingWorkspacesClient`` (the SDK owns the workspace
    # route paths), while ``_sync_get`` stays on raw httpx because the SDK is
    # async-only — every one of its methods is ``async def``. Driving it from a
    # sync caller would need ``asyncio.run()``, which raises outright when a
    # running event loop is already on the thread, i.e. inside any FastAPI
    # handler. The two halves must still agree on OBSERVABLE behaviour — same
    # headers, and every failure maps to None/[] — and that is what the tests
    # pin. The URL-construction duplication is the price of the sync path; it is
    # bounded to the one ``_sync_get`` below.

    def _sync_get(self, path: str, tenant_id: str | None = None) -> httpx.Response | None:
        """Perform a synchronous GET and return the response (or None on error).

        coding-containers scopes container lookups by tenant: a request with no
        ``X-Tenant-Id`` header 404s any tenant-owned container. Forward the
        caller's tenant so tenant-isolated containers resolve correctly.

        The tenant is optional here (some lookups are unscoped admin listings)
        so a missing one is omitted, never defaulted. This service's own licence
        rides in ``Authorization`` either way — without it, a callee with
        ``TRUST_TENANT_HEADER=false`` refuses the bare header and the ``except``
        below turns the 401 into "container not found".
        """
        url = f"{_containers_service_url()}{path}"
        headers = optional_sibling_headers(tenant_id) or None
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                return resp
        except httpx.HTTPError as exc:
            logger.warning("HTTP request to %s failed: %s", url, exc)
            return None

    # ── asynchronous helpers (SDK-backed) ────────────────────────────────

    @staticmethod
    def _swallow(exc: Exception, what: str) -> None:
        """Map any fetch failure onto this registry's "absent is None" contract.

        Every caller of the async helpers treats None as "not found", so no
        failure may escape. A 404 is deliberately silent: a missing workspace is
        the ANSWER, not an incident. Everything else is logged at warning, which
        is what ``_sync_get``'s ``except httpx.HTTPError`` did for the same
        cases (``raise_for_status`` turned a non-404 4xx/5xx into an
        ``HTTPStatusError``).
        """
        if isinstance(exc, ServiceError):
            if exc.status_code == 404:
                return
            logger.warning("Workspace request for %s failed: HTTP %s", what, exc.status_code)
            return
        logger.warning("HTTP request for %s failed: %s", what, exc)

    async def _fetch_workspace(
        self, container_name: str, tenant_id: str | None = None
    ) -> Any | None:
        """GET one workspace via the SDK; None on any failure (incl. 404)."""
        client = CodingWorkspacesClient(base_url=_containers_service_url(), timeout=_TIMEOUT)
        try:
            return await client.get_workspace(
                container_name, headers=optional_sibling_headers(tenant_id) or None
            )
        except (ServiceError, httpx.HTTPError) as exc:
            self._swallow(exc, f"workspace '{container_name}'")
            return None
        finally:
            await client.close()

    async def _fetch_workspace_list(self) -> Any | None:
        """GET the workspace listing via the SDK; None on any failure."""
        client = CodingWorkspacesClient(base_url=_containers_service_url(), timeout=_TIMEOUT)
        try:
            return await client.list_workspaces()
        except (ServiceError, httpx.HTTPError) as exc:
            self._swallow(exc, "the workspace listing")
            return None
        finally:
            await client.close()

    # ── sync public methods (backwards-compatible) ───────────────────────

    def get_container(
        self, container_name: str, tenant_id: str | None = None
    ) -> ContainerInfo | None:
        """Get container by name (sync).

        Args:
            container_name: Container name
            tenant_id: Owning tenant; forwarded to coding-containers so
                tenant-isolated containers resolve.

        Returns:
            ContainerInfo if found, None otherwise
        """
        return self.find_by_name(container_name, tenant_id=tenant_id)

    def find_by_name(
        self, container_name: str, tenant_id: str | None = None
    ) -> ContainerInfo | None:
        """Find container by container name (sync).

        Args:
            container_name: Container name
            tenant_id: Owning tenant; forwarded as ``X-Tenant-Id``.

        Returns:
            ContainerInfo if found, None otherwise
        """
        resp = self._sync_get(f"/api/workspaces/{container_name}", tenant_id=tenant_id)
        if resp is None:
            return None
        try:
            data = resp.json()
            # The detail endpoint wraps the container in a "container" key
            container_data = data.get("container", data)
            return _parse_container(container_data)
        except Exception as exc:
            logger.warning("Failed to parse container response for '%s': %s", container_name, exc)
            return None

    def find_by_name_pattern(self, identifier: str) -> ContainerInfo | None:
        """Find container by name with pattern matching (sync).

        Tries exact match first, then falls back to checking all containers.

        Args:
            identifier: Container name or pattern

        Returns:
            ContainerInfo if found, None otherwise
        """
        # Try exact match first
        exact = self.find_by_name(identifier)
        if exact is not None:
            return exact

        # Fall back to listing all and doing partial matching
        all_containers = self.list()
        for container in all_containers:
            name = container.container_name
            if identifier in name or name.endswith(f"_{identifier}") or identifier.startswith(name):
                logger.debug("Found container by name pattern match: %s", name)
                return container

        return None

    def list(self) -> builtins.list[ContainerInfo]:
        """List all containers in the registry (sync).

        Returns:
            List of all container info objects
        """
        resp = self._sync_get("/api/workspaces/")
        if resp is None:
            return []
        try:
            data = resp.json()
            containers_data = data.get("containers", [])
            return [_parse_container(c) for c in containers_data]
        except Exception as exc:
            logger.warning("Failed to parse container list response: %s", exc)
            return []

    # ── async public methods ─────────────────────────────────────────────

    async def get_container_async(
        self, container_name: str, tenant_id: str | None = None
    ) -> ContainerInfo | None:
        """Get container by name (async).

        Args:
            container_name: Container name
            tenant_id: Owning tenant; forwarded to coding-containers so
                tenant-isolated containers resolve.

        Returns:
            ContainerInfo if found, None otherwise
        """
        return await self.find_by_name_async(container_name, tenant_id=tenant_id)

    async def find_by_name_async(
        self, container_name: str, tenant_id: str | None = None
    ) -> ContainerInfo | None:
        """Find container by container name (async).

        Args:
            container_name: Container name
            tenant_id: Owning tenant; forwarded as ``X-Tenant-Id``.

        Returns:
            ContainerInfo if found, None otherwise
        """
        data = await self._fetch_workspace(container_name, tenant_id=tenant_id)
        if data is None:
            return None
        try:
            # The detail endpoint wraps the container in a "container" key
            container_data = data.get("container", data)
            return _parse_container(container_data)
        except Exception as exc:
            logger.warning("Failed to parse container response for '%s': %s", container_name, exc)
            return None

    async def list_async(self) -> builtins.list[ContainerInfo]:
        """List all containers in the registry (async).

        Returns:
            List of all container info objects
        """
        data = await self._fetch_workspace_list()
        if data is None:
            return []
        try:
            containers_data = data.get("containers", [])
            return [_parse_container(c) for c in containers_data]
        except Exception as exc:
            logger.warning("Failed to parse container list response: %s", exc)
            return []


class _RegistrySingleton:
    """Singleton holder for container registry instance."""

    instance: ContainerMetadataRegistry | None = None


def get_container_registry() -> ContainerMetadataRegistry:
    """Get singleton instance of container metadata registry."""
    if _RegistrySingleton.instance is None:
        _RegistrySingleton.instance = ContainerMetadataRegistry()
    return _RegistrySingleton.instance
