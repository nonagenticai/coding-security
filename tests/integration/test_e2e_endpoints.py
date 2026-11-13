"""Live E2E endpoint tests for coding-security.

Hit the REAL service running at http://localhost:8693 (ENABLE_AUTH=false).
No mocks, no ASGI transport -- plain HTTP via httpx.

Run with:
    uv run pytest tests/integration/test_e2e_endpoints.py -v -m integration
"""

import httpx
import pytest

FAKE_CONTAINER = "nonexistent-e2e-test-container"


# ──────────────────────────────────────────────────────────────────────
# Root & Health
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestRootAndHealth:
    """Tests for the root and health endpoints."""

    def test_root_returns_service_info(self, client: httpx.Client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "coding-security"
        assert "version" in data
        assert data["docs"] == "/docs"
        assert data["health"] == "/health"

    def test_health_returns_ok(self, client: httpx.Client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "coding-security"
        assert "version" in data

    def test_openapi_json_available(self, client: httpx.Client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "paths" in data
        assert "/health" in data["paths"]

    def test_docs_page_available(self, client: httpx.Client):
        resp = client.get("/docs")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/validate
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSecurityValidate:
    """Tests for POST /api/security/validate."""

    def test_validate_safe_python_code(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={
                "code": "x = 1 + 2\nprint(x)",
                "language": "python",
                "security_level": "medium",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "validation" in data
        assert isinstance(data["validation"]["is_safe"], bool)
        assert isinstance(data["validation"]["risk_score"], (int, float))
        assert data["language"] == "python"
        assert "execution_context" in data

    def test_validate_dangerous_python_code(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={
                "code": "import os\nos.system('rm -rf /')",
                "language": "python",
                "security_level": "high",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "validation" in data
        # Dangerous code should have violations or high risk score
        validation = data["validation"]
        assert isinstance(validation["violations"], list)
        assert isinstance(validation["risk_score"], (int, float))

    def test_validate_javascript_code(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={
                "code": "const x = 42; console.log(x);",
                "language": "javascript",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "javascript"

    def test_validate_missing_code_returns_422(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={"language": "python"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_validate_missing_language_returns_422(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={"code": "print('hello')"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_validate_empty_body_returns_422(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={},
        )
        assert resp.status_code == 422

    def test_validate_with_context(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={
                "code": "print('hello')",
                "language": "python",
                "context": {"execution_context": "sandbox"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["execution_context"] == "sandbox"


# ──────────────────────────────────────────────────────────────────────
# GET /api/security/sandbox-config/{language}/{security_level}
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSandboxConfig:
    """Tests for GET /api/security/sandbox-config/{language}/{security_level}."""

    def test_sandbox_config_python_standard(self, client: httpx.Client):
        resp = client.get("/api/security/sandbox-config/python/STANDARD")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["language"] == "python"
        assert data["security_level"] == "STANDARD"
        assert "config" in data
        assert "resource_limits" in data["config"]

    def test_sandbox_config_python_strict(self, client: httpx.Client):
        resp = client.get("/api/security/sandbox-config/python/STRICT")
        assert resp.status_code == 200
        data = resp.json()
        assert data["security_level"] == "STRICT"

    def test_sandbox_config_python_relaxed(self, client: httpx.Client):
        resp = client.get("/api/security/sandbox-config/python/RELAXED")
        assert resp.status_code == 200
        data = resp.json()
        assert data["security_level"] == "RELAXED"

    def test_sandbox_config_javascript(self, client: httpx.Client):
        resp = client.get("/api/security/sandbox-config/javascript/STANDARD")
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "javascript"

    def test_sandbox_config_has_description(self, client: httpx.Client):
        resp = client.get("/api/security/sandbox-config/python/STANDARD")
        data = resp.json()
        assert "description" in data
        assert isinstance(data["description"], str)


# ──────────────────────────────────────────────────────────────────────
# GET /api/security/patterns
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSecurityPatterns:
    """Tests for GET /api/security/patterns."""

    def test_patterns_returns_200(self, client: httpx.Client):
        resp = client.get("/api/security/patterns")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"

    def test_patterns_has_expected_fields(self, client: httpx.Client):
        resp = client.get("/api/security/patterns")
        data = resp.json()
        assert isinstance(data["patterns"], list)
        assert isinstance(data["total_patterns"], int)
        assert data["total_patterns"] > 0
        assert isinstance(data["vulnerability_types"], list)
        assert isinstance(data["severity_levels"], list)
        assert isinstance(data["confidence_levels"], list)
        assert isinstance(data["supported_languages"], list)
        assert isinstance(data["pattern_categories"], dict)
        assert isinstance(data["pattern_distribution"], dict)
        assert isinstance(data["owasp_mapping"], dict)

    def test_patterns_include_known_types(self, client: httpx.Client):
        resp = client.get("/api/security/patterns")
        data = resp.json()
        vuln_types = data["vulnerability_types"]
        assert "sql_injection" in vuln_types
        assert "cross_site_scripting" in vuln_types
        assert "command_injection" in vuln_types

    def test_patterns_include_known_languages(self, client: httpx.Client):
        resp = client.get("/api/security/patterns")
        data = resp.json()
        langs = data["supported_languages"]
        assert "python" in langs
        assert "java" in langs
        assert "javascript" in langs


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/analyze-vulnerabilities
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestAnalyzeVulnerabilities:
    """Tests for POST /api/security/analyze-vulnerabilities."""

    def test_analyze_with_no_inputs_returns_400(self, client: httpx.Client):
        resp = client.post(
            "/api/security/analyze-vulnerabilities",
            json={},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error_code"] == "BAD_REQUEST"

    def test_analyze_nonexistent_container_returns_404(self, client: httpx.Client):
        resp = client.post(
            "/api/security/analyze-vulnerabilities",
            json={"container_name": FAKE_CONTAINER},
        )
        assert resp.status_code == 404

    def test_analyze_pod_paths_without_container_returns_400(self, client: httpx.Client):
        """file_paths are never read from the service's own filesystem."""
        resp = client.post(
            "/api/security/analyze-vulnerabilities",
            json={"file_paths": ["/etc/passwd"]},
        )
        assert resp.status_code == 400
        assert "root:" not in resp.text

    def test_analyze_missing_body_returns_422(self, client: httpx.Client):
        resp = client.post(
            "/api/security/analyze-vulnerabilities",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/scan/{container_name}
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestContainerSecurityScan:
    """Tests for POST /api/security/scan/{container_name}."""

    def test_scan_nonexistent_container_returns_404(self, client: httpx.Client):
        resp = client.post(
            f"/api/security/scan/{FAKE_CONTAINER}",
            json={},
        )
        assert resp.status_code == 404

    def test_scan_container_name_mismatch_returns_400(self, client: httpx.Client):
        resp = client.post(
            f"/api/security/scan/{FAKE_CONTAINER}",
            json={"container_name": "other-container"},
        )
        # Container not found first (404) or mismatch (400) depending on validation order
        assert resp.status_code in (400, 404)


# ──────────────────────────────────────────────────────────────────────
# GET /api/security/report/{container_name}
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestContainerSecurityReport:
    """Tests for GET /api/security/report/{container_name}."""

    def test_report_nonexistent_container_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/security/report/{FAKE_CONTAINER}")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/scan/{container_name}/quick
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestQuickContainerSecurityScan:
    """Tests for POST /api/security/scan/{container_name}/quick."""

    def test_quick_scan_nonexistent_container_returns_404(self, client: httpx.Client):
        resp = client.post(f"/api/security/scan/{FAKE_CONTAINER}/quick")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/scan/{container_name}/image
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestContainerImageScan:
    """Tests for POST /api/security/scan/{container_name}/image."""

    def test_image_scan_nonexistent_container_returns_404(self, client: httpx.Client):
        """Only the caller's workspace is addressable; nothing is scanned."""
        resp = client.post(f"/api/security/scan/{FAKE_CONTAINER}/image")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/sbom/{container_name}
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestContainerSBOM:
    """Tests for POST /api/security/sbom/{container_name}."""

    def test_sbom_nonexistent_container_returns_404(self, client: httpx.Client):
        """Tenant-scoped: an unknown (or another tenant's) name is 404, never inventoried."""
        resp = client.post(f"/api/security/sbom/{FAKE_CONTAINER}")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# POST /api/security/sbom/{container_name}/vulnerabilities
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSBOMVulnerabilities:
    """Tests for POST /api/security/sbom/{container_name}/vulnerabilities."""

    def test_sbom_vulns_nonexistent_container_returns_404(self, client: httpx.Client):
        resp = client.post(f"/api/security/sbom/{FAKE_CONTAINER}/vulnerabilities")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/{container_name}
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDependenciesGet:
    """Tests for GET /api/dependencies/{container_name}."""

    def test_get_dependencies_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/dependencies/{FAKE_CONTAINER}")
        assert resp.status_code == 404

    def test_get_dependencies_404_error_format(self, client: httpx.Client):
        resp = client.get(f"/api/dependencies/{FAKE_CONTAINER}")
        data = resp.json()
        assert data["status"] == "error"
        assert isinstance(data["message"], str)
        assert isinstance(data["error_code"], str)


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/{container_name}/outdated
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDependenciesOutdated:
    """Tests for GET /api/dependencies/{container_name}/outdated."""

    def test_outdated_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/dependencies/{FAKE_CONTAINER}/outdated")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/{container_name}/vulnerable
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDependenciesVulnerable:
    """Tests for GET /api/dependencies/{container_name}/vulnerable."""

    def test_vulnerable_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/dependencies/{FAKE_CONTAINER}/vulnerable")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/{container_name}/report
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDependenciesReport:
    """Tests for GET /api/dependencies/{container_name}/report."""

    def test_report_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/dependencies/{FAKE_CONTAINER}/report")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# POST /api/dependencies/{container_name}/scan
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDependenciesScan:
    """Tests for POST /api/dependencies/{container_name}/scan."""

    def test_scan_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.post(f"/api/dependencies/{FAKE_CONTAINER}/scan")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# GET /api/security/dependencies/{container_name} (alias)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSecurityDependenciesAlias:
    """Tests for /api/security/dependencies/ alias routes."""

    def test_alias_get_dependencies_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/security/dependencies/{FAKE_CONTAINER}")
        assert resp.status_code == 404

    def test_alias_outdated_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/security/dependencies/{FAKE_CONTAINER}/outdated")
        assert resp.status_code == 404

    def test_alias_vulnerable_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/security/dependencies/{FAKE_CONTAINER}/vulnerable")
        assert resp.status_code == 404

    def test_alias_report_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.get(f"/api/security/dependencies/{FAKE_CONTAINER}/report")
        assert resp.status_code == 404

    def test_alias_scan_nonexistent_returns_404(self, client: httpx.Client):
        resp = client.post(f"/api/security/dependencies/{FAKE_CONTAINER}/scan")
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/system/detect
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSystemDependenciesDetect:
    """Tests for GET /api/dependencies/system/detect."""

    def test_detect_returns_200(self, client: httpx.Client):
        resp = client.get("/api/dependencies/system/detect")
        assert resp.status_code == 200
        data = resp.json()
        assert "project_root" in data
        assert "total_dependencies_checked" in data
        assert isinstance(data["missing_dependencies"], list)
        assert isinstance(data["installed_dependencies"], list)

    def test_detect_with_nonexistent_project_root_returns_400(self, client: httpx.Client):
        resp = client.get(
            "/api/dependencies/system/detect",
            params={"project_root": "/nonexistent/path/to/project"},
        )
        assert resp.status_code == 400

    def test_detect_with_fast_mode(self, client: httpx.Client):
        resp = client.get(
            "/api/dependencies/system/detect",
            params={"fast_mode": "true"},
        )
        assert resp.status_code == 200

    def test_detect_unknown_query_param_returns_400(self, client: httpx.Client):
        resp = client.get(
            "/api/dependencies/system/detect",
            params={"unknown_param": "value"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "unknown" in data["message"].lower() or "Unknown" in data["message"]


# ──────────────────────────────────────────────────────────────────────
# POST /api/dependencies/system/generate-script
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSystemDependenciesGenerateScript:
    """Tests for POST /api/dependencies/system/generate-script."""

    def test_generate_script_returns_200_400_or_500(self, client: httpx.Client):
        """May return 400/500 if no package manager detected, or 200 with script."""
        resp = client.post("/api/dependencies/system/generate-script")
        # 200 if package manager detected, 400 if not found, 500 if internal error wrapping 400
        assert resp.status_code in (200, 400, 500)
        if resp.status_code == 200:
            data = resp.json()
            assert "script_content" in data
            assert "package_manager" in data
            assert "dependencies_count" in data

    def test_generate_script_with_specific_deps(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-script",
            json={"dependencies": ["python3-dev", "build-essential"]},
        )
        assert resp.status_code in (200, 400, 500)


# ──────────────────────────────────────────────────────────────────────
# POST /api/dependencies/system/generate-dockerfile
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSystemDependenciesGenerateDockerfile:
    """Tests for POST /api/dependencies/system/generate-dockerfile."""

    def test_generate_dockerfile_returns_200(self, client: httpx.Client):
        resp = client.post("/api/dependencies/system/generate-dockerfile")
        assert resp.status_code == 200
        data = resp.json()
        assert "snippet" in data
        assert "dependencies_included" in data

    def test_generate_dockerfile_include_all(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-dockerfile",
            params={"include_all": "true"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["dependencies_included"], list)
        assert len(data["dependencies_included"]) > 0

    def test_generate_dockerfile_with_specific_deps(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-dockerfile",
            json={"dependencies": ["python3-dev"]},
        )
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────
# POST /api/dependencies/system/generate-ci-config
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSystemDependenciesGenerateCIConfig:
    """Tests for POST /api/dependencies/system/generate-ci-config."""

    def test_generate_ci_config_github(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-ci-config",
            params={"platform": "github"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["platform"] == "github"
        assert "configuration" in data
        assert isinstance(data["dependencies_included"], list)

    def test_generate_ci_config_gitlab(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-ci-config",
            params={"platform": "gitlab"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["platform"] == "gitlab"

    def test_generate_ci_config_missing_platform_returns_422(self, client: httpx.Client):
        resp = client.post("/api/dependencies/system/generate-ci-config")
        assert resp.status_code == 422

    def test_generate_ci_config_invalid_platform_returns_422(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-ci-config",
            params={"platform": "invalid_platform"},
        )
        assert resp.status_code == 422

    def test_generate_ci_config_with_specific_deps(self, client: httpx.Client):
        resp = client.post(
            "/api/dependencies/system/generate-ci-config",
            params={"platform": "github"},
            json={"dependencies": ["python3-dev"]},
        )
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────
# GET /api/dependencies/system/list-known
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSystemDependenciesListKnown:
    """Tests for GET /api/dependencies/system/list-known."""

    def test_list_known_returns_200(self, client: httpx.Client):
        resp = client.get("/api/dependencies/system/list-known")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_list_known_has_expected_fields(self, client: httpx.Client):
        resp = client.get("/api/dependencies/system/list-known")
        data = resp.json()
        for dep in data[:3]:  # Check first 3 entries
            assert "name" in dep
            assert "description" in dep
            assert "dependency_type" in dep
            assert "is_installed" in dep
            assert "system_packages" in dep


# ──────────────────────────────────────────────────────────────────────
# Error Response Format Consistency
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestErrorResponseFormat:
    """Verify error responses follow a consistent structure."""

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", f"/api/dependencies/{FAKE_CONTAINER}"),
            ("GET", f"/api/dependencies/{FAKE_CONTAINER}/outdated"),
            ("GET", f"/api/dependencies/{FAKE_CONTAINER}/vulnerable"),
            ("GET", f"/api/dependencies/{FAKE_CONTAINER}/report"),
            ("GET", f"/api/security/report/{FAKE_CONTAINER}"),
            ("GET", f"/api/security/dependencies/{FAKE_CONTAINER}"),
        ],
    )
    def test_404_error_format(self, client: httpx.Client, method: str, path: str):
        resp = client.request(method, path)
        assert resp.status_code == 404
        data = resp.json()
        assert data["status"] == "error"
        assert isinstance(data["message"], str)
        assert isinstance(data["timestamp"], str)
        assert isinstance(data["request_id"], str)
        assert isinstance(data["path"], str)
        assert isinstance(data["error_code"], str)

    def test_422_error_format(self, client: httpx.Client):
        resp = client.post(
            "/api/security/validate",
            json={},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["status"] == "error"
        assert data["error_code"] == "VALIDATION_ERROR"
        assert "validation_errors" in data
        assert isinstance(data["validation_errors"], list)

    def test_method_not_allowed(self, client: httpx.Client):
        """PATCH on a GET-only endpoint should return 405."""
        resp = client.patch("/api/security/patterns")
        assert resp.status_code == 405
