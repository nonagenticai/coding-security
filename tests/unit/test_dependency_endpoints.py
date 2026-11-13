"""Tests for dependency API endpoints."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from models.architecture_models import (
    DependencyRiskReport,
    DependencyRiskSummary,
)
from models.container_models import ContainerInfo, ContainerStatus


def _make_container_info(name="test-container", codebase_path="/tmp/test-codebase"):
    """Helper to build a ContainerInfo for mocking."""
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path=codebase_path,
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _make_risk_report(codebase_id="test-container"):
    """Helper to build a DependencyRiskReport for mocking."""
    return DependencyRiskReport(
        codebase_id=codebase_id,
        generated_at=datetime.now(UTC).isoformat(),
        packages=[],
        vulnerabilities=[],
        risk_score=0.0,
        summary=DependencyRiskSummary(
            total_packages=0,
            vulnerable_packages=0,
            total_vulnerabilities=0,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            moderate_vulnerabilities=0,
            low_vulnerabilities=0,
        ),
    )


def _assert_error_response(data: dict, *, message_contains: str | None = None) -> None:
    """Assert the standardised error envelope from coding_client exception handlers.

    Supports both the legacy format ``{"status": "error", "message": ...}`` and the
    current coding_client format ``{"error": {"code": ..., "message": ...}}``.
    """
    if "error" in data:
        err = data["error"]
        assert "code" in err
        if message_contains:
            assert message_contains.lower() in err["message"].lower()
    else:
        assert data.get("status") == "error"
        if message_contains:
            assert message_contains.lower() in data["message"].lower()


class TestDependencyEndpoints:
    """Tests for error cases when containers don't exist.

    The container registry returns None for unknown containers (HTTP error to
    coding-containers service results in None), which validate_and_get_container_for_tenant
    converts to a 404 HTTPException.
    """

    def test_get_dependencies_not_found(self, test_client, tenant_headers):
        """GET /api/dependencies/{container} returns 404 for nonexistent container."""
        response = test_client.get(
            "/api/dependencies/nonexistent",
            headers=tenant_headers,
        )
        assert response.status_code == 404
        _assert_error_response(response.json(), message_contains="nonexistent")

    def test_scan_dependencies_not_found(self, test_client, tenant_headers):
        """POST scan for a nonexistent container returns 404."""
        response = test_client.post(
            "/api/dependencies/nonexistent/scan",
            headers=tenant_headers,
        )
        assert response.status_code == 404
        _assert_error_response(response.json(), message_contains="nonexistent")

    def test_get_outdated_not_found(self, test_client, tenant_headers):
        """GET /api/dependencies/nonexistent/outdated returns 404."""
        response = test_client.get(
            "/api/dependencies/nonexistent/outdated",
            headers=tenant_headers,
        )
        assert response.status_code == 404
        _assert_error_response(response.json())

    def test_get_vulnerable_not_found(self, test_client, tenant_headers):
        """GET /api/dependencies/nonexistent/vulnerable returns 404."""
        response = test_client.get(
            "/api/dependencies/nonexistent/vulnerable",
            headers=tenant_headers,
        )
        assert response.status_code == 404
        _assert_error_response(response.json())

    def test_get_report_not_found(self, test_client, tenant_headers):
        """GET /api/dependencies/nonexistent/report returns 404."""
        response = test_client.get(
            "/api/dependencies/nonexistent/report",
            headers=tenant_headers,
        )
        assert response.status_code == 404
        _assert_error_response(response.json())


class TestDependencyEndpointsWithMockedContainer:
    """Tests with mocked container registry for successful dependency operations."""

    def test_get_dependencies_success(self, test_client, tenant_headers, tmp_path):
        """GET /{container_name} with mocked container returns full report."""
        container = _make_container_info(codebase_path=str(tmp_path))
        report = _make_risk_report()

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                return_value=report,
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["codebase_id"] == "test-container"
            assert data["risk_score"] == 0.0
            assert "summary" in data
            assert data["summary"]["total_packages"] == 0
            assert data["summary"]["total_vulnerabilities"] == 0
            assert isinstance(data["packages"], list)
            assert isinstance(data["vulnerabilities"], list)

    def test_get_dependencies_path_not_exists(self, test_client, tenant_headers):
        """GET /{container_name} where codebase_path isn't local falls back to remote fetch.

        In k8s mode the container's codebase lives inside its pod at ``/workspace``;
        the endpoint now pulls manifests via the coding-containers exec API. When
        that fetch fails (as in this unit test, where no coding-containers service
        is reachable) we expect a 502 — not a 404.
        """
        container = _make_container_info(codebase_path="/workspace")

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "services.scan_runner.fetch_manifests_to_tempdir",
                new_callable=AsyncMock,
                side_effect=RuntimeError("containers exec failed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container",
                headers=tenant_headers,
            )
            assert response.status_code == 502
            _assert_error_response(response.json(), message_contains="coding-containers")

    def test_get_dependencies_analyzer_exception(self, test_client, tenant_headers, tmp_path):
        """GET /{container_name} with analyzer exception returns 500 with error details."""
        container = _make_container_info(codebase_path=str(tmp_path))

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                side_effect=RuntimeError("analyzer crashed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container",
                headers=tenant_headers,
            )
            assert response.status_code == 500
            _assert_error_response(response.json(), message_contains="analyzer crashed")

    def test_scan_dependencies_success(self, test_client, tenant_headers, tmp_path):
        """POST /{container_name}/scan with mocked container returns report."""
        container = _make_container_info(codebase_path=str(tmp_path))
        report = _make_risk_report()

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                return_value=report,
            ),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["codebase_id"] == "test-container"
            assert data["risk_score"] == 0.0

    def test_scan_dependencies_path_not_exists(self, test_client, tenant_headers):
        """POST scan with remote codebase returns 502 when containers API is unreachable."""
        container = _make_container_info(codebase_path="/workspace")

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "services.scan_runner.fetch_manifests_to_tempdir",
                new_callable=AsyncMock,
                side_effect=RuntimeError("containers exec failed"),
            ),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan",
                headers=tenant_headers,
            )
            assert response.status_code == 502
            _assert_error_response(response.json())

    def test_scan_dependencies_exception(self, test_client, tenant_headers, tmp_path):
        """POST scan with analyzer exception returns 500 with error message."""
        container = _make_container_info(codebase_path=str(tmp_path))

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                side_effect=RuntimeError("scan failed"),
            ),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan",
                headers=tenant_headers,
            )
            assert response.status_code == 500
            _assert_error_response(response.json(), message_contains="scan failed")

    def test_get_outdated_success(self, test_client, tenant_headers, tmp_path):
        """GET /{container_name}/outdated with mocked container returns empty list."""
        container = _make_container_info(codebase_path=str(tmp_path))
        report = _make_risk_report()

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                return_value=report,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.get_outdated_packages",
                return_value=[],
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/outdated",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert data == []

    def test_get_outdated_path_not_exists(self, test_client, tenant_headers):
        """GET outdated with remote codebase returns 502 when containers API is unreachable."""
        container = _make_container_info(codebase_path="/workspace")

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "services.scan_runner.fetch_manifests_to_tempdir",
                new_callable=AsyncMock,
                side_effect=RuntimeError("containers exec failed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/outdated",
                headers=tenant_headers,
            )
            assert response.status_code == 502
            _assert_error_response(response.json())

    def test_get_outdated_exception(self, test_client, tenant_headers, tmp_path):
        """GET outdated with analyzer exception returns 500."""
        container = _make_container_info(codebase_path=str(tmp_path))

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                side_effect=RuntimeError("outdated check failed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/outdated",
                headers=tenant_headers,
            )
            assert response.status_code == 500
            _assert_error_response(response.json(), message_contains="outdated check failed")

    def test_get_vulnerable_success(self, test_client, tenant_headers, tmp_path):
        """GET /{container_name}/vulnerable with mocked container returns empty list."""
        container = _make_container_info(codebase_path=str(tmp_path))
        report = _make_risk_report()

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                return_value=report,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.get_vulnerable_packages",
                return_value=[],
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/vulnerable",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert data == []

    def test_get_vulnerable_path_not_exists(self, test_client, tenant_headers):
        """GET vulnerable with remote codebase returns 502 when containers API is unreachable."""
        container = _make_container_info(codebase_path="/workspace")

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "services.scan_runner.fetch_manifests_to_tempdir",
                new_callable=AsyncMock,
                side_effect=RuntimeError("containers exec failed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/vulnerable",
                headers=tenant_headers,
            )
            assert response.status_code == 502
            _assert_error_response(response.json())

    def test_get_vulnerable_exception(self, test_client, tenant_headers, tmp_path):
        """GET vulnerable with analyzer exception returns 500."""
        container = _make_container_info(codebase_path=str(tmp_path))

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                side_effect=RuntimeError("vulnerable check failed"),
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/vulnerable",
                headers=tenant_headers,
            )
            assert response.status_code == 500
            _assert_error_response(response.json(), message_contains="vulnerable check failed")

    def test_get_report_success(self, test_client, tenant_headers, tmp_path):
        """GET /{container_name}/report with mocked container returns full report."""
        container = _make_container_info(codebase_path=str(tmp_path))
        report = _make_risk_report()

        with (
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
                new_callable=AsyncMock,
                return_value=report,
            ),
        ):
            response = test_client.get(
                "/api/dependencies/test-container/report",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["codebase_id"] == "test-container"
            assert data["risk_score"] == 0.0
            assert "summary" in data
            assert isinstance(data["packages"], list)
