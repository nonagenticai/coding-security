"""Dependency injection for FastAPI endpoints.

This module provides dependency injection functions for the coding-security service.
It implements the singleton pattern for service instances used across API endpoints.

Usage:
    from fastapi import Depends
    from dependencies import get_security_service

    @router.get("/protected")
    async def protected_endpoint(
        security_service = Depends(get_security_service)
    ):
        pass
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.security_service import SystemSecurityService

logger = logging.getLogger(__name__)


class DependencyContainer:
    """Container for managing singleton service instances.

    This class encapsulates the singleton pattern for dependency injection,
    providing lazy initialization and clean reset for testing.
    """

    _security_service: SystemSecurityService | None = None

    @classmethod
    def get_security_service(cls) -> SystemSecurityService:
        """Get or create SystemSecurityService instance for dependency injection.

        Returns:
            SystemSecurityService: Singleton instance of the security service.
        """
        if cls._security_service is None:
            # Lazy import to avoid circular dependencies
            from app_factory import get_redis
            from services.security_service import RedisCacheManager, create_security_service

            # Try to get the Redis connection; fall back to None if not available
            try:
                redis_client = get_redis()
            except RuntimeError:
                redis_client = None

            cache_manager = RedisCacheManager(redis_client)
            cls._security_service = create_security_service(cache_manager=cache_manager)
            logger.info("Initialized SystemSecurityService for API endpoints")

        return cls._security_service

    @classmethod
    def reset(cls) -> None:
        """Reset all dependencies for testing purposes.

        Clears all cached singleton service instances, forcing them to be
        recreated on next access.
        """
        cls._security_service = None


# Public API functions that delegate to the container
def get_security_service() -> SystemSecurityService:
    """Get or create SystemSecurityService instance for dependency injection.

    This is the public API function that FastAPI will use for dependency
    injection. It delegates to the DependencyContainer.

    Returns:
        SystemSecurityService: Singleton instance of the security service.
    """
    return DependencyContainer.get_security_service()


def reset_dependencies() -> None:
    """Reset all global dependencies for testing purposes."""
    DependencyContainer.reset()


# Re-export database session dependency for convenience
