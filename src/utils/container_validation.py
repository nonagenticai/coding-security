"""
Container validation utilities and error handlers.

This module provides custom exception classes and error handler functions
for container-related operations.

TENANT ISOLATION:
- validate_and_get_container_for_tenant(): PREFERRED - tenant-aware validation
- validate_and_get_container(): Legacy - NO tenant filtering (use only for internal/admin)
"""

import logging

from fastapi import HTTPException, status

from models.container_models import ContainerInfo
from services.container_registry import get_container_registry

logger = logging.getLogger(__name__)


# Custom Exception Classes


class ContainerNotFoundError(Exception):
    """Exception raised when a container cannot be found."""

    def __init__(self, container_name: str, message: str | None = None):
        self.container_name = container_name
        self.message = message or f"Container '{container_name}' not found"
        super().__init__(self.message)


class ContainerAccessDeniedError(Exception):
    """Exception raised when access to a container is denied due to permission issues."""

    def __init__(self, container_name: str, message: str | None = None):
        self.container_name = container_name
        self.message = message or f"Access denied to container '{container_name}'"
        super().__init__(self.message)


class InvalidContainerStateError(Exception):
    """Exception raised when a container is in an invalid state."""

    def __init__(self, container_name: str, state: str | None = None, message: str | None = None):
        self.container_name = container_name
        self.state = state
        self.message = (
            message
            or f"Container '{container_name}' is in an invalid state{f': {state}' if state else ''}"
        )
        super().__init__(self.message)


# Error Handler Functions


def handle_container_not_found(container_name: str) -> HTTPException:
    """Handle container not found errors."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "ContainerNotFound",
            "message": f"Container '{container_name}' not found",
            "container_name": container_name,
        },
    )


def handle_container_access_denied(container_name: str) -> HTTPException:
    """Handle container access denied errors."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "ContainerAccessDenied",
            "message": f"Access denied to container '{container_name}'. You do not have permission to access this container",
            "container_name": container_name,
        },
    )


def handle_invalid_container_state(container_name: str, state: str) -> HTTPException:
    """Handle invalid container state errors."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "InvalidContainerState",
            "message": f"Container '{container_name}' is in an invalid state: {state}",
            "container_name": container_name,
            "current_state": state,
        },
    )


# Single Container Validation Functions


async def validate_and_get_container(container_name: str) -> ContainerInfo:
    """
    Validate that a container exists and return its information.

    Args:
        container_name: The name of the container to validate and retrieve.

    Returns:
        ContainerInfo: The container information object.

    Raises:
        HTTPException: A 404 error if the container is not found.
    """
    logger.debug(f"Validating container: {container_name}")

    registry = get_container_registry()
    container_info = await registry.get_container_async(container_name)

    if not container_info:
        logger.warning(f"Container '{container_name}' not found")
        raise HTTPException(status_code=404, detail=f"Container '{container_name}' not found")

    logger.debug(
        f"Container '{container_name}' validated successfully with status: {container_info.status}"
    )

    return container_info


async def validate_and_get_container_for_tenant(
    container_name: str,
    tenant_id: str | None = None,
) -> ContainerInfo:
    """
    Validate that a container exists and belongs to the specified tenant.

    This is the PREFERRED validation function for tenant-isolated operations.

    BOLA Protection:
    - Returns 404 if container doesn't exist OR belongs to different tenant
    - This prevents enumeration attacks

    Args:
        container_name: The name of the container to validate and retrieve.
        tenant_id: The tenant ID to validate against.

    Returns:
        ContainerInfo: The container information object.

    Raises:
        HTTPException: A 404 error if container not found or access denied.
    """
    logger.debug(f"Validating container '{container_name}' for tenant_id={tenant_id}")

    registry = get_container_registry()
    container_info = await registry.get_container_async(container_name, tenant_id=tenant_id)

    if not container_info:
        logger.warning(
            f"Container '{container_name}' not found or access denied for tenant_id={tenant_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Container '{container_name}' not found",
        )

    # TODO: Add tenant filtering when tenant metadata is available on ContainerInfo
    logger.debug(f"Container '{container_name}' validated for tenant_id={tenant_id}")
    return container_info
