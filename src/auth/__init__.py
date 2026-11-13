"""Authentication and tenant isolation for the coding-security service."""

from __future__ import annotations

from typing import Any

from auth.tenant import require_tenant

try:
    from coding_client.auth.middleware import AuthMiddleware
except ImportError:
    AuthMiddleware: Any = None

__all__ = [
    "require_tenant",
    "AuthMiddleware",
]
