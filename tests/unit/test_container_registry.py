"""Tests for ContainerMetadataRegistry (HTTP-based)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from models.container_models import ContainerStatus
from services.container_registry import (
    ContainerMetadataRegistry,
    _RegistrySingleton,
    get_container_registry,
)

CONTAINER_DETAIL_JSON = {
    "message": "Container 'test-container' details retrieved",
    "container": {
        "container_name": "test-container",
        "api_endpoint": "http://localhost:8080",
        "code_graph_id": "cg-123",
        "codebase_path": "/tmp/test",
        "repo_url": "https://github.com/test/repo",
        "branch": "main",
        "status": "running",
    },
    "request_id": "abc",
}

CONTAINER_LIST_JSON = {
    "message": "Found 1 containers",
    "containers": [
        {
            "container_name": "test-container",
            "api_endpoint": "http://localhost:8080",
            "code_graph_id": "cg-123",
            "codebase_path": "/tmp/test",
            "repo_url": "https://github.com/test/repo",
            "branch": "main",
            "status": "running",
        }
    ],
    "total": 1,
}


def _mock_response(status_code: int, json_data=None):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _async_mock_client(mock_resp):
    """Build a stub ``httpx.AsyncClient`` for the SDK-backed async registry path.

    The async half of the registry now goes through ``CodingWorkspacesClient``,
    which calls ``httpx.AsyncClient.request(...)`` and closes the client itself
    rather than using ``async with``. ``.get`` is still wired so the stub keeps
    working for anything driving httpx directly.
    """
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.request = AsyncMock(return_value=mock_resp)
    mock_client.aclose = AsyncMock(return_value=None)
    mock_client.is_closed = False
    return mock_client


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset singleton between tests."""
    _RegistrySingleton.instance = None
    yield
    _RegistrySingleton.instance = None


@pytest.fixture
def registry():
    return ContainerMetadataRegistry()


class TestContainerMetadataRegistrySync:
    def test_find_by_name_found(self, registry):
        """find_by_name returns ContainerInfo when service returns 200."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name("test-container")
        assert result is not None, "find_by_name should return ContainerInfo for 200 response"
        assert result.container_name == "test-container"
        assert result.status == ContainerStatus.RUNNING
        assert result.api_endpoint == "http://localhost:8080"

    def test_find_by_name_not_found(self, registry):
        """find_by_name returns None when service returns 404."""
        mock_resp = _mock_response(404)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name("nonexistent")
        assert result is None

    def test_find_by_name_server_error(self, registry):
        """find_by_name returns None on server error."""
        mock_resp = _mock_response(500)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name("test-container")
        assert result is None

    def test_get_container_delegates_to_find_by_name(self, registry):
        """get_container is an alias for find_by_name."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.get_container("test-container")
        assert result is not None, "get_container should return ContainerInfo for 200 response"
        assert result.container_name == "test-container"
        assert result.status == ContainerStatus.RUNNING

    def test_list_returns_containers(self, registry):
        """list returns all containers from the service."""
        mock_resp = _mock_response(200, CONTAINER_LIST_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.list()
        assert len(result) == 1
        assert result[0].container_name == "test-container"

    def test_list_empty(self, registry):
        """list returns empty list when service returns no containers."""
        mock_resp = _mock_response(200, {"containers": [], "total": 0})
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.list()
        assert result == []

    def test_list_server_error(self, registry):
        """list returns empty list on server error."""
        mock_resp = _mock_response(500)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.list()
        assert result == []


class TestContainerMetadataRegistryAsync:
    @pytest.mark.asyncio
    async def test_get_container_async_found(self, registry):
        """Async get_container returns ContainerInfo on 200."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.get_container_async("test-container")
        assert result is not None, "Async get_container should return ContainerInfo for 200"
        assert result.container_name == "test-container"
        assert result.status == ContainerStatus.RUNNING

    @pytest.mark.asyncio
    async def test_get_container_async_not_found(self, registry):
        """Async get_container returns None on 404."""
        mock_resp = _mock_response(404)
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.get_container_async("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_container_async_forwards_tenant_header(self, registry):
        """tenant_id is forwarded as X-Tenant-Id so tenant-isolated containers resolve.

        Regression: coding-containers 404s tenant-owned containers when no
        X-Tenant-Id header is sent, which silently blocked every dependency op
        (getContainerDependencies / upgradeCves) against BYO/EXEC-tenant
        containers.
        """
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.get_container_async("test-container", tenant_id="tenant-abc")
        assert result is not None
        # The SDK issues the call via httpx.AsyncClient.request(method, path, ...).
        _, kwargs = mock_client.request.call_args
        assert kwargs["headers"] == {"X-Tenant-Id": "tenant-abc"}

    def test_find_by_name_forwards_tenant_header(self, registry):
        """Sync find_by_name forwards X-Tenant-Id when a tenant is supplied."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name("test-container", tenant_id="tenant-xyz")
        assert result is not None
        _, kwargs = mock_client.get.call_args
        assert kwargs["headers"] == {"X-Tenant-Id": "tenant-xyz"}

    def test_find_by_name_no_tenant_sends_no_header(self, registry):
        """Without a tenant, no X-Tenant-Id header is sent (legacy/internal callers)."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            registry.find_by_name("test-container")
        _, kwargs = mock_client.get.call_args
        assert kwargs["headers"] is None

    @pytest.mark.asyncio
    async def test_list_async(self, registry):
        """Async list returns containers."""
        mock_resp = _mock_response(200, CONTAINER_LIST_JSON)
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.list_async()
        assert len(result) == 1
        assert result[0].container_name == "test-container"

    @pytest.mark.asyncio
    async def test_list_async_empty(self, registry):
        """Async list returns empty list when no containers."""
        mock_resp = _mock_response(200, {"containers": [], "total": 0})
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.list_async()
        assert result == []


class TestContainerMetadataRegistryPatternMatch:
    def test_find_by_name_pattern_exact_match(self, registry):
        """find_by_name_pattern returns result for exact match."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name_pattern("test-container")
        assert result is not None, "Exact pattern match should return ContainerInfo"
        assert result.container_name == "test-container"
        assert result.status == ContainerStatus.RUNNING

    def test_find_by_name_pattern_partial_match(self, registry):
        """find_by_name_pattern falls back to listing and partial match."""
        mock_resp_404 = _mock_response(404)
        mock_resp_list = _mock_response(200, CONTAINER_LIST_JSON)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_resp_404, mock_resp_list]

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name_pattern("test")
        assert result is not None, "Partial pattern match should fallback and return ContainerInfo"
        assert result.container_name == "test-container"

    def test_find_by_name_pattern_no_match(self, registry):
        """find_by_name_pattern returns None when no match found."""
        mock_resp_404 = _mock_response(404)
        mock_resp_list = _mock_response(200, {"containers": [], "total": 0})
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = [mock_resp_404, mock_resp_list]

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name_pattern("nonexistent")
        assert result is None

    def test_find_by_name_parse_error_returns_none(self, registry):
        """find_by_name returns None when JSON parsing fails."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_resp.json.side_effect = ValueError("bad json")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.find_by_name("test-container")
        assert result is None

    def test_list_parse_error_returns_empty(self, registry):
        """list returns empty list when JSON parsing fails."""
        mock_resp = _mock_response(200, CONTAINER_LIST_JSON)
        mock_resp.json.side_effect = ValueError("bad json")
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp

        with patch("services.container_registry.httpx.Client", return_value=mock_client):
            result = registry.list()
        assert result == []


class TestContainerAsyncErrorHandling:
    @pytest.mark.asyncio
    async def test_find_by_name_async_parse_error(self, registry):
        """Async find_by_name returns None when JSON parsing fails."""
        mock_resp = _mock_response(200, CONTAINER_DETAIL_JSON)
        mock_resp.json.side_effect = ValueError("bad json")
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.find_by_name_async("test-container")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_async_parse_error(self, registry):
        """Async list returns empty list when JSON parsing fails."""
        mock_resp = _mock_response(200, CONTAINER_LIST_JSON)
        mock_resp.json.side_effect = ValueError("bad json")
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.list_async()
        assert result == []

    @pytest.mark.asyncio
    async def test_list_async_server_error(self, registry):
        """Async list returns empty list on server error."""
        mock_resp = _mock_response(500)
        mock_client = _async_mock_client(mock_resp)

        with patch("services.container_registry.httpx.AsyncClient", return_value=mock_client):
            result = await registry.list_async()
        assert result == []


class TestSingleton:
    def test_get_container_registry_singleton(self):
        """get_container_registry returns the same instance."""
        r1 = get_container_registry()
        r2 = get_container_registry()
        assert r1 is r2
