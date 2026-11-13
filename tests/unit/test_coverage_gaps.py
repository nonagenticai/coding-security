"""Tests to cover remaining gaps in source code coverage.

Targets:
- app_factory.py: get_redis, lifespan (Redis fail), exception handlers
- main.py: import coverage
- models/package_manager_models.py: property methods
- models/common.py: PaginatedResponse validator
- models/errors.py: timestamp serializer
- models/container_models.py: model_validator branch
- dependencies.py: reset path
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


# ---------------------------------------------------------------------------
# main.py -- just import it so the two lines get covered
# ---------------------------------------------------------------------------
class TestMainModule:
    def test_main_imports_app(self):
        """Importing main.py creates a FastAPI app instance."""
        os.environ["ENABLE_AUTH"] = "false"
        os.environ["ENVIRONMENT"] = "testing"
        from config.settings import get_settings

        get_settings.cache_clear()

        import main

        assert isinstance(main.app, FastAPI)
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# app_factory.py -- get_redis when _redis is None
# ---------------------------------------------------------------------------
class TestGetRedis:
    def test_get_redis_raises_when_not_initialised(self):
        """get_redis() raises RuntimeError with specific message when called before lifespan."""
        import app_factory

        original = app_factory._redis
        try:
            app_factory._redis = None
            with pytest.raises(RuntimeError, match="Redis not initialised"):
                app_factory.get_redis()
        finally:
            app_factory._redis = original

    def test_get_redis_returns_client_when_set(self):
        """get_redis() returns the exact Redis client that was set."""
        import app_factory

        original = app_factory._redis
        try:
            fake_redis = MagicMock()
            app_factory._redis = fake_redis
            result = app_factory.get_redis()
            assert result is fake_redis
        finally:
            app_factory._redis = original


# ---------------------------------------------------------------------------
# app_factory.py -- exception handler branches
# ---------------------------------------------------------------------------
class TestExceptionHandlers:
    """Test all branches of the custom exception handlers."""

    @pytest.fixture(autouse=True)
    def _setup_client(self, test_client):
        self.client = test_client

    def test_http_exception_with_string_detail(self):
        """HTTPException with a plain string detail produces the KAG error envelope.

        Starlette's routing layer raises ``starlette.exceptions.HTTPException``
        for 405s. As of coding-client 1.3.1 the KAG handler is registered against
        the starlette base class, so these are wrapped in the standard envelope
        rather than falling through to FastAPI's default ``{"detail": ...}`` shape.
        """
        response = self.client.delete("/health")
        assert response.status_code == 405
        data = response.json()
        assert data["error"]["code"] == "HTTP_405"
        assert data["error"]["message"] == "Method Not Allowed"

    def test_http_exception_with_dict_detail(self):
        """HTTPException with dict detail produces KAG error envelope."""
        response = self.client.get(
            "/api/dependencies/system/detect",
            params={"project_root": "relative/path"},
        )
        assert response.status_code in (400, 422)
        data = response.json()
        assert "error" in data
        assert "code" in data["error"]
        assert "message" in data["error"]

    def test_validation_error_handler(self):
        """RequestValidationError produces 422 with KAG error envelope."""
        response = self.client.post(
            "/api/security/validate",
            json={},  # Missing required fields
        )
        assert response.status_code == 422
        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "HTTP_422"
        assert data["error"]["message"] == "Request validation failed"
        assert "details" in data["error"]
        assert isinstance(data["error"]["details"], list)
        assert len(data["error"]["details"]) > 0
        for err in data["error"]["details"]:
            assert "field" in err
            assert "message" in err
            assert "type" in err


# ---------------------------------------------------------------------------
# app_factory.py -- _add_middlewares with string enable_auth
# ---------------------------------------------------------------------------
class TestMiddlewareAuthString:
    def test_enable_auth_string_true(self):
        """When enable_auth is the string 'true', auth middleware is attempted."""
        os.environ["ENABLE_AUTH"] = "true"
        os.environ["ENVIRONMENT"] = "testing"
        from config.settings import get_settings

        get_settings.cache_clear()

        from app_factory import create_app

        # The app should still create successfully even if coding_client isn't available
        app = create_app()
        assert isinstance(app, FastAPI)
        get_settings.cache_clear()
        os.environ["ENABLE_AUTH"] = "false"
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# models/package_manager_models.py -- property methods
# ---------------------------------------------------------------------------
class TestSystemPackageManagerProperties:
    def test_install_commands_contain_manager_name(self):
        """Each SystemPackageManager install_command contains the manager's binary."""
        from models.package_manager_models import SystemPackageManager

        for pm in SystemPackageManager:
            cmd = pm.install_command
            assert isinstance(cmd, list)
            assert len(cmd) >= 2, f"{pm.name} should have at least a binary and a subcommand"
            # The manager value (e.g. 'apt-get', 'brew') should appear in the command
            assert pm.value in cmd, f"{pm.name} install_command should contain '{pm.value}'"

    def test_update_commands_contain_manager_name(self):
        """Each SystemPackageManager update_command contains the manager's binary."""
        from models.package_manager_models import SystemPackageManager

        for pm in SystemPackageManager:
            cmd = pm.update_command
            assert isinstance(cmd, list)
            assert len(cmd) >= 2, f"{pm.name} should have at least a binary and a subcommand"
            assert pm.value in cmd, f"{pm.name} update_command should contain '{pm.value}'"

    def test_apt_install_uses_apt_get(self):
        """APT install command uses apt-get with install -y flags."""
        from models.package_manager_models import SystemPackageManager

        cmd = SystemPackageManager.APT.install_command
        assert cmd == ["sudo", "apt-get", "install", "-y"]

    def test_brew_install_uses_brew(self):
        """BREW install command uses brew install."""
        from models.package_manager_models import SystemPackageManager

        cmd = SystemPackageManager.BREW.install_command
        assert cmd == ["brew", "install"]


class TestLanguagePackageManagerProperties:
    def test_manifest_files_are_specific(self):
        """Key LanguagePackageManagers return known manifest file names."""
        from models.package_manager_models import LanguagePackageManager

        pip_manifests = LanguagePackageManager.PIP.manifest_files
        assert "requirements.txt" in pip_manifests

        npm_manifests = LanguagePackageManager.NPM.manifest_files
        assert "package.json" in npm_manifests

        cargo_manifests = LanguagePackageManager.CARGO.manifest_files
        assert "Cargo.toml" in cargo_manifests

    def test_install_commands_are_specific(self):
        """Key LanguagePackageManagers return correct install commands."""
        from models.package_manager_models import LanguagePackageManager

        assert LanguagePackageManager.PIP.install_command == ["pip", "install"]
        assert LanguagePackageManager.NPM.install_command == ["npm", "install"]
        assert LanguagePackageManager.CARGO.install_command == ["cargo", "build"]
        assert LanguagePackageManager.UV.install_command == ["uv", "pip", "install"]

    def test_all_managers_have_manifest_files(self):
        """All LanguagePackageManager variants return manifest file lists (possibly empty)."""
        from models.package_manager_models import LanguagePackageManager

        for lpm in LanguagePackageManager:
            files = lpm.manifest_files
            assert isinstance(files, list)


class TestExternalPackageFullSpec:
    def test_full_spec_with_extras(self):
        """full_spec property includes extras in bracket notation."""
        from models.package_manager_models import ExternalPackage

        pkg = ExternalPackage(
            name="fastapi",
            version=">=0.115.0",
            extras=["standard"],
        )
        assert pkg.full_spec == "fastapi[standard]>=0.115.0"

    def test_full_spec_without_extras(self):
        """full_spec property without extras is name+version concatenation."""
        from models.package_manager_models import ExternalPackage

        pkg = ExternalPackage(name="httpx", version="0.28.0")
        assert pkg.full_spec == "httpx0.28.0"

    def test_full_spec_no_version(self):
        """full_spec property without version is just the name."""
        from models.package_manager_models import ExternalPackage

        pkg = ExternalPackage(name="httpx")
        assert pkg.full_spec == "httpx"

    def test_full_spec_with_multiple_extras(self):
        """full_spec property with multiple extras uses comma-separated brackets."""
        from models.package_manager_models import ExternalPackage

        pkg = ExternalPackage(
            name="uvicorn",
            version=">=0.20.0",
            extras=["standard", "httptools"],
        )
        assert pkg.full_spec == "uvicorn[standard,httptools]>=0.20.0"


# ---------------------------------------------------------------------------
# models/common.py -- PaginatedResponse validator
# ---------------------------------------------------------------------------
class TestPaginatedResponse:
    def test_valid_pagination(self):
        """PaginatedResponse accepts valid pagination dict with all required keys."""
        from models.common import PaginatedResponse

        resp = PaginatedResponse(
            message="ok",
            pagination={"page": 1, "limit": 10, "total": 100, "pages": 10},
            items=[1, 2, 3],
        )
        assert resp.pagination["total"] == 100
        assert resp.pagination["page"] == 1
        assert resp.pagination["limit"] == 10
        assert resp.pagination["pages"] == 10
        assert resp.items == [1, 2, 3]

    def test_invalid_pagination_missing_keys(self):
        """PaginatedResponse rejects pagination dict missing required keys with ValidationError."""
        from models.common import PaginatedResponse

        with pytest.raises(ValidationError, match="Pagination must contain"):
            PaginatedResponse(
                message="ok",
                pagination={"page": 1},  # Missing limit, total, pages
                items=[],
            )

    def test_invalid_pagination_missing_total(self):
        """PaginatedResponse rejects pagination missing 'total' key."""
        from models.common import PaginatedResponse

        with pytest.raises(ValidationError, match="Pagination must contain"):
            PaginatedResponse(
                message="ok",
                pagination={"page": 1, "limit": 10, "pages": 5},
                items=[],
            )


# ---------------------------------------------------------------------------
# models/errors.py -- timestamp serializer
# ---------------------------------------------------------------------------
class TestErrorTimestampSerializer:
    def test_naive_timestamp_gets_utc(self):
        """StandardErrorResponse serializes naive timestamps with UTC timezone marker."""
        from datetime import datetime

        from models.errors import StandardErrorResponse

        resp = StandardErrorResponse(
            message="test",
            request_id="req_123",
            path="/test",
            timestamp=datetime(2025, 1, 1, 12, 0, 0),  # naive
        )
        dumped = resp.model_dump()
        # The serializer should add UTC timezone
        assert "+" in dumped["timestamp"] or "Z" in dumped["timestamp"]

    def test_aware_timestamp_preserved(self):
        """StandardErrorResponse preserves aware timestamps with correct date."""
        from datetime import UTC, datetime

        from models.errors import StandardErrorResponse

        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        resp = StandardErrorResponse(
            message="test",
            request_id="req_123",
            path="/test",
            timestamp=ts,
        )
        dumped = resp.model_dump()
        assert "2025-01-01" in dumped["timestamp"]
        assert "12:00:00" in dumped["timestamp"]


# ---------------------------------------------------------------------------
# models/container_models.py -- model_validator branch (line 50)
# ---------------------------------------------------------------------------
class TestContainerInfoValidator:
    def test_sync_endpoint_when_api_endpoint_empty(self):
        """When api_endpoint is empty, it gets filled from public_endpoint."""
        from models.container_models import ContainerInfo, ContainerStatus

        info = ContainerInfo(
            container_name="test",
            api_endpoint="",
            public_endpoint="http://public",
            codebase_path="/tmp",
            repo_url="https://github.com/test",
            branch="main",
            status=ContainerStatus.RUNNING,
        )
        assert info.api_endpoint == "http://public"

    def test_sync_endpoint_when_public_empty(self):
        """When public_endpoint is empty, it gets filled from api_endpoint."""
        from models.container_models import ContainerInfo, ContainerStatus

        info = ContainerInfo(
            container_name="test",
            api_endpoint="http://api",
            codebase_path="/tmp",
            repo_url="https://github.com/test",
            branch="main",
            status=ContainerStatus.RUNNING,
        )
        assert info.public_endpoint == "http://api"

    def test_both_endpoints_set(self):
        """When both endpoints are set, they remain unchanged."""
        from models.container_models import ContainerInfo, ContainerStatus

        info = ContainerInfo(
            container_name="test",
            api_endpoint="http://api",
            public_endpoint="http://public",
            codebase_path="/tmp",
            repo_url="https://github.com/test",
            branch="main",
            status=ContainerStatus.RUNNING,
        )
        assert info.api_endpoint == "http://api"
        assert info.public_endpoint == "http://public"


# ---------------------------------------------------------------------------
# dependencies.py -- DependencyContainer.reset and get_security_service paths
# ---------------------------------------------------------------------------
class TestDependencyContainer:
    def test_reset_clears_security_service(self):
        """reset() sets _security_service back to None."""
        from dependencies import DependencyContainer

        # Set something
        DependencyContainer._security_service = MagicMock()
        assert DependencyContainer._security_service is not None
        DependencyContainer.reset()
        assert DependencyContainer._security_service is None

    def test_reset_dependencies_public_function(self):
        """reset_dependencies() delegates to DependencyContainer.reset()."""
        from dependencies import DependencyContainer, reset_dependencies

        DependencyContainer._security_service = MagicMock()
        reset_dependencies()
        assert DependencyContainer._security_service is None

    def test_get_security_service_fallback_no_redis(self):
        """get_security_service creates service even without Redis."""
        from dependencies import DependencyContainer, get_security_service

        DependencyContainer.reset()

        # Mock get_redis in app_factory where it's actually imported from
        with patch("app_factory.get_redis", side_effect=RuntimeError("no redis")):
            svc = get_security_service()
            assert svc is not None
            # Clean up
            DependencyContainer.reset()


# ---------------------------------------------------------------------------
# auth/tenant.py -- SDK re-export behaviour
# ---------------------------------------------------------------------------
class TestTenantFallback:
    def test_public_health_endpoint_no_tenant_required(self, test_client):
        """/health is a public endpoint and does not exercise require_tenant."""
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "service" in data
        assert "version" in data

    def test_require_tenant_with_header(self, test_client, tenant_headers):
        """Tenant-protected endpoint accepts X-Tenant-Id header."""
        response = test_client.get(
            "/api/dependencies/system/list-known",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_require_tenant_no_header_no_trusted_cidr_raises_401(self):
        """SDK require_tenant raises 401 when no X-Tenant-Id and origin is not trusted.

        This is the deliberate tightening from R-7b: the old local require_tenant
        returned DEFAULT_TENANT_ID unconditionally; the SDK only returns
        DEFAULT_TENANT_ID on trusted-CIDR origins (loopback / RFC1918) and
        otherwise raises 401.
        """
        os.environ["ENVIRONMENT"] = "testing"
        os.environ["ENABLE_AUTH"] = "false"
        os.environ["ENABLE_DOCS"] = "true"
        os.environ["DEFAULT_TENANT_ID"] = "test-tenant"

        from fastapi.testclient import TestClient

        from app_factory import create_app
        from config.settings import get_settings

        get_settings.cache_clear()
        app = create_app()
        # client=("8.8.8.8", ...) is outside TRUSTED_NETWORKS -> SDK raises 401.
        with TestClient(app, client=("8.8.8.8", 12345)) as untrusted_client:
            response = untrusted_client.get("/api/dependencies/system/list-known")
        get_settings.cache_clear()
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# auth/__init__.py -- import coverage
# ---------------------------------------------------------------------------
class TestAuthInit:
    def test_auth_exports(self):
        """auth module exports require_tenant and AuthMiddleware."""
        import auth

        assert hasattr(auth, "require_tenant")
        assert hasattr(auth, "AuthMiddleware")
        assert callable(auth.require_tenant)
