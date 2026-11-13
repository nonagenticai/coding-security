"""Integration test fixtures for coding-security.

These tests hit a REAL service running at http://localhost:8693.
No mocks, no ASGI transport -- plain HTTP via httpx.
"""

import os

import httpx
import pytest

BASE_URL = os.getenv("E2E_BASE_URL", "http://localhost:8693")


@pytest.fixture(scope="session")
def client():
    """Shared httpx client for all integration tests."""
    with httpx.Client(base_url=BASE_URL, timeout=30) as c:
        yield c
