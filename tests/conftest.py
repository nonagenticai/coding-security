"""Shared test fixtures for coding-security."""

import os
import sys
from pathlib import Path

# ── Auth preconditions, set at IMPORT time (see below for why not a fixture) ──
# coding-client >=1.7.0 (#33) stopped defaulting TRUSTED_CIDRS to a list that
# contained 10.0.0.0/8. That old default covered the k3s pod CIDR
# (10.42.0.0/16), so every pod in the cluster satisfied require_tenant's
# trusted-network bypass. TestClient dispatches from 127.0.0.1 and rode the same
# default, so without this four suites 401 before reaching the handler at all.
# Loopback ONLY: the pod CIDR stays out, so no test can rely on the bypass that
# default was changed to remove.
#
# ⚠️ These MUST be set here rather than in the `test_client` fixture below.
# `coding_client.auth.tenant` resolves both TRUSTED_NETWORKS and
# DEFAULT_TENANT_ID into module-level constants at import time, so the
# `os.environ[...]` assignments inside the fixture land after the value is
# already frozen. That is also why the pre-existing DEFAULT_TENANT_ID line in
# the fixture never actually took effect — until 1.9.0 it was masked by the
# library's built-in "n8n-dev" fallback, which #36 has now removed.
os.environ.setdefault("TRUSTED_CIDRS", "127.0.0.1/32,::1/128")
os.environ.setdefault("DEFAULT_TENANT_ID", "test-tenant")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# Test defaults injected for fields enforced by `_REQUIRED_IN_PRODUCTION`.
# `model_post_init` only runs when ENVIRONMENT == "production"; tests run
# under ENVIRONMENT="testing" so these are belt-and-suspenders for code
# paths that read the URLs directly (e.g. container_registry).
_TEST_URL_DEFAULTS: dict[str, str] = {
    "DATABASE_URL": "postgresql+psycopg://postgres:postgres@postgres:5432/coding_security_test",
    # Loopback port 1: refused at once. A cluster DNS name here cost a ~5 s
    # resolver timeout in EVERY `test_client` lifespan off-cluster, which made
    # test_security_endpoints.py (69 clients) run past 300 s on a dev box.
    "REDIS_URL": "redis://127.0.0.1:1/0",
    "CONTAINERS_SERVICE_URL": "http://coding-containers.coding-containers.svc.cluster.local:8691",
    "DOCKER_REGISTRY_URL": "mirror.example.com",
    "OTEL_ENDPOINT": "http://otel-collector:4318",
}


@pytest.fixture(autouse=True)
def _inject_test_settings_env(monkeypatch):
    """Inject test URLs + non-production env so settings load cleanly in tests."""
    monkeypatch.setenv("ENVIRONMENT", "testing")
    # Bind the dedicated metrics listener to an EPHEMERAL port in tests. Every
    # `test_client` runs the real lifespan, so a fixed 9693 would make the suite
    # fight itself (and any locally running pod) over one port. Tests read the
    # actual port back from `MetricsServer.bound_port`.
    monkeypatch.setenv("METRICS_PORT", "0")
    for key, value in _TEST_URL_DEFAULTS.items():
        monkeypatch.setenv(key, value)

    from config.settings import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def test_client():
    """Create a test client for the FastAPI app."""
    # Set test environment before importing
    os.environ["ENVIRONMENT"] = "testing"
    os.environ["ENABLE_AUTH"] = "false"
    os.environ["ENABLE_DOCS"] = "true"
    os.environ["DEFAULT_TENANT_ID"] = "test-tenant"

    # Clear settings cache
    from config.settings import get_settings

    get_settings.cache_clear()

    from app_factory import create_app

    app = create_app()
    # client=("127.0.0.1", ...) puts requests on the loopback trusted CIDR so
    # the SDK's require_tenant falls back to DEFAULT_TENANT_ID when no header
    # is set (matches production: in-cluster traffic from Istio sidecar /
    # localhost is treated as trusted; external traffic must carry the header).
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        yield client

    # Reset cache
    get_settings.cache_clear()


@pytest.fixture
def tenant_headers():
    """Headers with tenant ID for authenticated requests."""
    return {"X-Tenant-Id": "test-tenant"}


@pytest.fixture
def sample_packages():
    """Sample ExternalPackage list for testing."""
    from models.package_manager_models import ExternalPackage

    return [
        ExternalPackage(name="fastapi", version="0.115.0", ecosystem="pypi", license="MIT"),
        ExternalPackage(
            name="django",
            version="4.2.0",
            ecosystem="pypi",
            license="BSD-3-Clause",
            severity="HIGH",
        ),
        ExternalPackage(
            name="requests",
            version="2.31.0",
            ecosystem="pypi",
            current_version="2.31.0",
            latest_version="2.32.0",
        ),
    ]


@pytest.fixture
def sample_vulnerabilities():
    """Sample Vulnerability list for testing."""
    from models.architecture_models import Vulnerability

    return [
        Vulnerability(
            id="GHSA-1234",
            severity="CRITICAL",
            summary="Critical RCE in django",
            details="",
            affected_versions=[],
            fixed_versions=[],
            references=[],
            published_date="",
            modified_date="",
        ),
        Vulnerability(
            id="GHSA-5678",
            severity="HIGH",
            summary="XSS vulnerability in requests",
            details="",
            affected_versions=[],
            fixed_versions=[],
            references=[],
            published_date="",
            modified_date="",
        ),
        Vulnerability(
            id="GHSA-9012",
            severity="LOW",
            summary="Minor info leak",
            details="",
            affected_versions=[],
            fixed_versions=[],
            references=[],
            published_date="",
            modified_date="",
        ),
    ]
