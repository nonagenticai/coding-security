"""Tests for container validation utilities."""

from typing import cast
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from utils.container_validation import (
    ContainerAccessDeniedError,
    ContainerNotFoundError,
    InvalidContainerStateError,
    handle_container_access_denied,
    handle_container_not_found,
    handle_invalid_container_state,
    validate_and_get_container,
    validate_and_get_container_for_tenant,
)

# ============================================================================
# Custom Exception Classes
# ============================================================================


class TestContainerNotFoundError:
    def test_default_message(self):
        err = ContainerNotFoundError("my-container")
        assert err.container_name == "my-container"
        assert "my-container" in str(err)

    def test_custom_message(self):
        err = ContainerNotFoundError("c1", message="Custom msg")
        assert err.message == "Custom msg"


class TestContainerAccessDeniedError:
    def test_default_message(self):
        err = ContainerAccessDeniedError("my-container")
        assert err.container_name == "my-container"
        assert "Access denied" in str(err)

    def test_custom_message(self):
        err = ContainerAccessDeniedError("c1", message="Nope")
        assert err.message == "Nope"


class TestInvalidContainerStateError:
    def test_default_message_with_state(self):
        err = InvalidContainerStateError("c1", state="error")
        assert err.container_name == "c1"
        assert err.state == "error"
        assert "error" in str(err)

    def test_default_message_without_state(self):
        err = InvalidContainerStateError("c1")
        assert "invalid state" in str(err).lower()

    def test_custom_message(self):
        err = InvalidContainerStateError("c1", message="Bad state")
        assert err.message == "Bad state"


# ============================================================================
# Error Handler Functions
# ============================================================================


class TestHandleContainerNotFound:
    def test_returns_404(self):
        exc = handle_container_not_found("test-container")
        assert isinstance(exc, HTTPException)
        assert exc.status_code == 404
        detail = cast(dict, exc.detail)
        assert detail["container_name"] == "test-container"
        assert detail["error"] == "ContainerNotFound"


class TestHandleContainerAccessDenied:
    def test_returns_403(self):
        exc = handle_container_access_denied("test-container")
        assert isinstance(exc, HTTPException)
        assert exc.status_code == 403
        detail = cast(dict, exc.detail)
        assert detail["container_name"] == "test-container"
        assert detail["error"] == "ContainerAccessDenied"


class TestHandleInvalidContainerState:
    def test_returns_409(self):
        exc = handle_invalid_container_state("test-container", "error")
        assert isinstance(exc, HTTPException)
        assert exc.status_code == 409
        detail = cast(dict, exc.detail)
        assert detail["container_name"] == "test-container"
        assert detail["current_state"] == "error"
        assert detail["error"] == "InvalidContainerState"


# ============================================================================
# validate_and_get_container
# ============================================================================


class TestValidateAndGetContainer:
    async def test_success(self):
        from models.container_models import ContainerInfo, ContainerStatus

        mock_info = ContainerInfo(
            container_name="c1",
            api_endpoint="http://localhost:8080",
            codebase_path="/tmp/repo",
            repo_url="https://github.com/test/repo",
            branch="main",
            status=ContainerStatus.RUNNING,
        )
        mock_registry = AsyncMock()
        mock_registry.get_container_async = AsyncMock(return_value=mock_info)

        with patch(
            "utils.container_validation.get_container_registry",
            return_value=mock_registry,
        ):
            result = await validate_and_get_container("c1")
            assert result.container_name == "c1"

    async def test_missing_container_raises_404(self):
        mock_registry = AsyncMock()
        mock_registry.get_container_async = AsyncMock(return_value=None)

        with patch(
            "utils.container_validation.get_container_registry",
            return_value=mock_registry,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await validate_and_get_container("missing")
            assert exc_info.value.status_code == 404


# ============================================================================
# validate_and_get_container_for_tenant
# ============================================================================


class TestValidateAndGetContainerForTenant:
    async def test_success(self):
        from models.container_models import ContainerInfo, ContainerStatus

        mock_info = ContainerInfo(
            container_name="c1",
            api_endpoint="http://localhost:8080",
            codebase_path="/tmp/repo",
            repo_url="https://github.com/test/repo",
            branch="main",
            status=ContainerStatus.RUNNING,
            tenant_id="tenant-1",
        )
        mock_registry = AsyncMock()
        mock_registry.get_container_async = AsyncMock(return_value=mock_info)

        with patch(
            "utils.container_validation.get_container_registry",
            return_value=mock_registry,
        ):
            result = await validate_and_get_container_for_tenant("c1", "tenant-1")
            assert result.container_name == "c1"

    async def test_missing_container_returns_404(self):
        mock_registry = AsyncMock()
        mock_registry.get_container_async = AsyncMock(return_value=None)

        with patch(
            "utils.container_validation.get_container_registry",
            return_value=mock_registry,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await validate_and_get_container_for_tenant("missing", "tenant-1")
            assert exc_info.value.status_code == 404
