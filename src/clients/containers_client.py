"""Typed wrapper over the coding-containers workspace API.

The transport is delegated to :class:`coding_client.clients.CodingWorkspacesClient`
so the workspace route paths are spelled in exactly ONE place (the SDK) instead
of being re-typed at every call site. Hand-built workspace URLs are how a
sibling service shipped a silent bug: it sent ``file_path=`` where the route
reads ``path=``, FastAPI ignored the unknown field, and every read returned 200
with ``content: None``.

This module keeps its own :class:`ContainersClientError` façade rather than
letting the SDK's ``ServiceError`` leak upwards, because
``services.dependency_upgrade`` and the unit tests already branch on
``ContainersClientError.status_code``. The error mapping below is deliberately
1:1 with the previous raw-httpx behaviour.

Retry policy (deliberate, not an oversight)
-------------------------------------------
``ServiceClient`` retries ``ConnectError`` / ``ReadTimeout`` / ``PoolTimeout``
up to ``max_retries`` times. The previous implementation retried NOTHING. For
``package-upgrade`` / ``package-modify`` — which mutate a workspace's installed
package set — a ``ReadTimeout`` means the request *landed* and only the reply
was lost, so a retry can apply the same upgrade twice. Those two calls are
therefore pinned to ``max_retries=1`` to preserve today's exactly-once
semantics. ``exec_command`` keeps the SDK default because its callers use it
for read-only auto-detection commands, where a reconnect is safe.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from coding_client.clients import CodingWorkspacesClient, ServiceError

from clients.outbound import sibling_headers

logger = logging.getLogger(__name__)

# Mutating calls must not be retried: a ReadTimeout means the request landed and
# only the response was lost, so a retry risks applying the change twice.
_NO_RETRY = 1


class ContainersClientError(RuntimeError):
    """Raised on transport failure or non-2xx response from coding-containers."""

    def __init__(self, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class ContainersClient:
    """Thin async wrapper around the coding-containers workspace surface."""

    def __init__(self, base_url: str, *, timeout: float = 1800.0) -> None:
        if not base_url:
            raise ValueError("containers_service_url is empty")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @asynccontextmanager
    async def _session(
        self, *, label: str = "", operation: str, max_retries: int = 3
    ) -> AsyncGenerator[CodingWorkspacesClient]:
        """Yield an SDK client and map its failures onto ``ContainersClientError``.

        The SDK fixes its timeout at construction, so it is threaded from
        ``self._timeout`` (1800s by default — package upgrades are long) rather
        than inheriting the SDK's 30s default, which would truncate every
        upgrade this service issues.

        The mapping reproduces the previous raw-httpx behaviour exactly:

        * transport failure (``httpx.HTTPError``) -> ``ContainersClientError(None, ...)``
        * any response >= 400 -> ``ContainersClientError(status_code, ...)``
        """
        client = CodingWorkspacesClient(
            base_url=self._base_url,
            timeout=self._timeout,
            max_retries=max_retries,
        )
        try:
            yield client
        except ServiceError as exc:
            # The SDK raises instead of returning the response; re-shape it into
            # the message the previous implementation produced so callers that
            # surface ``str(err)`` are unchanged.
            raise ContainersClientError(
                exc.status_code,
                f"coding-containers {label}HTTP {exc.status_code}: {str(exc.body)[:500]}",
            ) from exc
        except httpx.HTTPError as exc:
            logger.error("containers %s transport error: %s", operation, exc)
            raise ContainersClientError(None, f"transport error: {exc}") from exc
        finally:
            await client.close()

    def _headers(self, tenant_id: str, operation: str) -> dict[str, str]:
        return {
            **sibling_headers(tenant_id, operation=operation),
            "Content-Type": "application/json",
        }

    @staticmethod
    def _require_object(payload: Any, label: str = "") -> dict[str, Any]:
        """A 2xx with an empty or non-object body is not a usable result.

        The previous code raised a raw ``JSONDecodeError`` here; raising our own
        typed error is the one deliberate deviation, so callers that already
        handle ``ContainersClientError`` stop seeing a json error escape.
        """
        if not isinstance(payload, dict):
            raise ContainersClientError(
                None,
                f"coding-containers {label}returned a non-object body: {type(payload).__name__}",
            )
        return payload

    async def package_upgrade(
        self,
        *,
        container_name: str,
        tenant_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Call ``POST /api/workspaces/{name}/package-upgrade``.

        Returns the JSON body on 2xx. Raises ``ContainersClientError`` on any
        other status or transport failure — the caller can map to an HTTP
        exception of its choosing.
        """
        operation = f"coding-containers /api/workspaces/{container_name}/package-upgrade"
        async with self._session(operation=operation, max_retries=_NO_RETRY) as client:
            payload = await client.package_upgrade(
                container_name, headers=self._headers(tenant_id, operation), **body
            )
        return self._require_object(payload)

    async def package_modify(
        self,
        *,
        container_name: str,
        tenant_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Call ``POST /api/workspaces/{name}/package-modify`` (add / remove / replace).

        Same error semantics as :meth:`package_upgrade`.
        """
        operation = f"coding-containers /api/workspaces/{container_name}/package-modify"
        async with self._session(operation=operation, max_retries=_NO_RETRY) as client:
            payload = await client.package_modify(
                container_name, headers=self._headers(tenant_id, operation), **body
            )
        return self._require_object(payload)

    async def exec_command(
        self,
        *,
        container_name: str,
        tenant_id: str,
        command: list[str],
        workdir: str = "/workspace",
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Convenience wrapper for ``/exec`` — used by auto-detection.

        ``timeout`` is the *container-side* command budget carried in the
        request body; it is unrelated to this client's HTTP timeout.
        """
        operation = f"coding-containers exec {container_name}"
        async with self._session(label="exec ", operation=operation) as client:
            payload = await client.exec(
                container_name,
                headers=self._headers(tenant_id, operation),
                command=command,
                workdir=workdir,
                timeout=timeout,
            )
        return self._require_object(payload, "exec ")
