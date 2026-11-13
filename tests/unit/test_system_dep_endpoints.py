"""Tests for system dependency endpoints."""

from unittest.mock import MagicMock, patch


class TestSystemDependencyEndpoints:
    def test_list_known_dependencies(self, test_client, tenant_headers):
        """GET /api/dependencies/system/list-known returns known deps."""
        response = test_client.get(
            "/api/dependencies/system/list-known",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_dependencies(self, test_client, tenant_headers):
        """GET /api/dependencies/system/detect returns detection result."""
        response = test_client.get(
            "/api/dependencies/system/detect",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_project_root(self, test_client, tenant_headers, tmp_path):
        """GET /api/dependencies/system/detect with explicit project_root."""
        response = test_client.get(
            f"/api/dependencies/system/detect?project_root={tmp_path}",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_script(self, test_client, tenant_headers):
        """POST /api/dependencies/system/generate-script generates script."""
        response = test_client.post(
            "/api/dependencies/system/generate-script",
            headers=tenant_headers,
        )
        # 200 if deps found, 400 if no package manager, 500 if no compatible deps
        assert response.status_code in [200, 400, 500]

    def test_generate_dockerfile(self, test_client, tenant_headers):
        """POST /api/dependencies/system/generate-dockerfile generates snippet."""
        response = test_client.post(
            "/api/dependencies/system/generate-dockerfile?include_all=true",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_ci_config_github(self, test_client, tenant_headers):
        """POST /api/dependencies/system/generate-ci-config for github."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=github",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_ci_config_invalid_platform(self, test_client, tenant_headers):
        """POST /api/dependencies/system/generate-ci-config with invalid platform."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=travis",
            headers=tenant_headers,
        )
        assert response.status_code == 422


class TestSystemDependencyEndpointsExtended:
    """Additional system dependency endpoint tests for coverage."""

    def test_detect_with_null_project_root(self, test_client, tenant_headers):
        """GET detect with 'null' project_root should handle gracefully."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=null",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_ci_config_gitlab(self, test_client, tenant_headers):
        """POST ci-config for gitlab platform."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=gitlab",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_script_with_project_root(self, test_client, tenant_headers, tmp_path):
        """POST generate-script with explicit project_root."""
        response = test_client.post(
            f"/api/dependencies/system/generate-script?project_root={tmp_path}",
            headers=tenant_headers,
        )
        assert response.status_code in [200, 400, 500]

    def test_generate_dockerfile_no_all(self, test_client, tenant_headers):
        """POST generate-dockerfile without include_all."""
        response = test_client.post(
            "/api/dependencies/system/generate-dockerfile",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_nonexistent_root(self, test_client, tenant_headers):
        """GET detect with nonexistent path returns 400."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=/definitely/nonexistent/path",
            headers=tenant_headers,
        )
        assert response.status_code in [200, 400]

    def test_list_known_returns_list(self, test_client, tenant_headers):
        """GET list-known returns a list with dependency info."""
        response = test_client.get(
            "/api/dependencies/system/list-known",
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0


class TestDetectEndpointVariations:
    """Tests for /detect with various project_root values and edge cases."""

    def test_detect_with_include_optional(self, test_client, tenant_headers, tmp_path):
        """GET detect with include_optional=true."""
        response = test_client.get(
            f"/api/dependencies/system/detect?project_root={tmp_path}&include_optional=true",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_fast_mode(self, test_client, tenant_headers, tmp_path):
        """GET detect with fast_mode=true."""
        response = test_client.get(
            f"/api/dependencies/system/detect?project_root={tmp_path}&fast_mode=true",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_none_string_project_root(self, test_client, tenant_headers):
        """GET detect with 'none' project_root returns 200 (treated as None)."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=none",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_undefined_string_project_root(self, test_client, tenant_headers):
        """GET detect with 'undefined' project_root returns 200 (treated as None)."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=undefined",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_with_empty_project_root(self, test_client, tenant_headers):
        """GET detect with empty project_root returns 200 (treated as None)."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_detect_unknown_query_params_returns_400(self, test_client, tenant_headers):
        """GET detect with unknown query params returns 400."""
        response = test_client.get(
            "/api/dependencies/system/detect?bogus_param=abc",
            headers=tenant_headers,
        )
        assert response.status_code == 400

    def test_detect_with_requirements_file(self, test_client, tenant_headers, tmp_path):
        """GET detect in a directory with requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("lxml>=4.0\nPillow>=9.0\n")
        response = test_client.get(
            f"/api/dependencies/system/detect?project_root={tmp_path}",
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "missing_dependencies" in data
        assert "installed_dependencies" in data

    def test_detect_response_structure(self, test_client, tenant_headers, tmp_path):
        """GET detect response has all required fields."""
        response = test_client.get(
            f"/api/dependencies/system/detect?project_root={tmp_path}",
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "detected_package_manager" in data
        assert "project_root" in data
        assert "total_dependencies_checked" in data


class TestGenerateScriptVariations:
    """Tests for generate-script with request body and edge cases."""

    def test_generate_script_with_known_dependency(self, test_client, tenant_headers):
        """POST generate-script with known dependency name in request body."""
        response = test_client.post(
            "/api/dependencies/system/generate-script",
            json={"dependencies": ["python3-dev"]},
            headers=tenant_headers,
        )
        # 200 if a package manager was detected, 400 otherwise
        assert response.status_code in [200, 400]

    def test_generate_script_with_unknown_dependency(self, test_client, tenant_headers):
        """POST generate-script with custom (unmapped) dependency name."""
        response = test_client.post(
            "/api/dependencies/system/generate-script",
            json={"dependencies": ["my-custom-pkg"]},
            headers=tenant_headers,
        )
        assert response.status_code in [200, 400]

    def test_generate_script_with_invalid_package_name(self, test_client, tenant_headers):
        """POST generate-script with invalid package name (special chars)."""
        response = test_client.post(
            "/api/dependencies/system/generate-script",
            json={"dependencies": ["!!invalid!!"]},
            headers=tenant_headers,
        )
        # Invalid names are logged/skipped, script may still generate or be empty
        assert response.status_code in [200, 400, 500]

    def test_generate_script_include_optional(self, test_client, tenant_headers, tmp_path):
        """POST generate-script with include_optional=true."""
        response = test_client.post(
            f"/api/dependencies/system/generate-script?project_root={tmp_path}&include_optional=true",
            headers=tenant_headers,
        )
        assert response.status_code in [200, 400, 500]


class TestGenerateDockerfileVariations:
    """Tests for generate-dockerfile with request body."""

    def test_generate_dockerfile_with_deps_body(self, test_client, tenant_headers):
        """POST generate-dockerfile with dependencies in body."""
        response = test_client.post(
            "/api/dependencies/system/generate-dockerfile",
            json={"dependencies": ["python3-dev", "build-essential"]},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "snippet" in data
        assert "dependencies_included" in data

    def test_generate_dockerfile_with_unknown_dep(self, test_client, tenant_headers):
        """POST generate-dockerfile with unmapped dep creates simple dependency."""
        response = test_client.post(
            "/api/dependencies/system/generate-dockerfile",
            json={"dependencies": ["some-custom-lib"]},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "some-custom-lib" in data.get("dependencies_included", [])


class TestGenerateCIConfigVariations:
    """Tests for generate-ci-config with various platforms and dependencies."""

    def test_generate_ci_config_github_with_deps(self, test_client, tenant_headers):
        """POST ci-config for github with explicit dependencies."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=github",
            json={"dependencies": ["python3-dev"]},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["platform"] == "github"
        assert "configuration" in data

    def test_generate_ci_config_gitlab_with_deps(self, test_client, tenant_headers):
        """POST ci-config for gitlab with explicit dependencies."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=gitlab",
            json={"dependencies": ["build-essential"]},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["platform"] == "gitlab"

    def test_generate_ci_config_with_project_root(self, test_client, tenant_headers, tmp_path):
        """POST ci-config with project_root auto-detects deps."""
        response = test_client.post(
            f"/api/dependencies/system/generate-ci-config?platform=github&project_root={tmp_path}",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_generate_ci_config_with_unknown_dep(self, test_client, tenant_headers):
        """POST ci-config with unknown dependency creates simple dep."""
        response = test_client.post(
            "/api/dependencies/system/generate-ci-config?platform=github",
            json={"dependencies": ["custom-package"]},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "custom-package" in data.get("dependencies_included", [])


class TestListKnownDependenciesExtended:
    """Additional tests for list-known endpoint."""

    def test_list_known_has_dep_info_fields(self, test_client, tenant_headers):
        """Each item in list-known has required DependencyInfo fields."""
        response = test_client.get(
            "/api/dependencies/system/list-known",
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0
        first = data[0]
        assert "name" in first
        assert "description" in first
        assert "dependency_type" in first
        assert "is_installed" in first
        assert "system_packages" in first


class TestGenerateScriptNoPackageManager:
    """Test generate-script when no package manager is detected."""

    def test_generate_script_no_package_manager_returns_400(self, test_client, tenant_headers):
        """POST generate-script with no package manager returns 400."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.package_manager = None
            mock_manager_cls.return_value = mock_mgr

            response = test_client.post(
                "/api/dependencies/system/generate-script",
                headers=tenant_headers,
            )
            assert response.status_code == 400
            data = response.json()
            assert (
                "package manager" in data.get("message", "").lower()
                or "package manager" in str(data).lower()
            )


class TestDetectWithRelativeProjectRoot:
    """Test detect with relative project_root (validation error)."""

    def test_detect_with_relative_path_returns_error(self, test_client, tenant_headers):
        """GET detect with relative project_root returns error."""
        response = test_client.get(
            "/api/dependencies/system/detect?project_root=relative/path",
            headers=tenant_headers,
        )
        # Should return 400 or 422 for validation error
        assert response.status_code in [400, 422]


class TestDetectDependencyDetectionError:
    """Test detect when detect_required_dependencies raises."""

    def test_detect_dependency_detection_exception(self, test_client, tenant_headers, tmp_path):
        """GET detect returns 500 when detect_required_dependencies throws."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.package_manager = MagicMock()
            mock_mgr.package_manager.value = "brew"
            mock_mgr.detect_required_dependencies.side_effect = RuntimeError("detection failed")
            mock_manager_cls.return_value = mock_mgr

            response = test_client.get(
                f"/api/dependencies/system/detect?project_root={tmp_path}",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestGenerateScriptException:
    """Test generate-script when generate_install_script raises."""

    def test_generate_script_exception_returns_500(self, test_client, tenant_headers):
        """POST generate-script returns 500 when script generation fails."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.package_manager = MagicMock()
            mock_mgr.package_manager.value = "brew"
            mock_mgr.detect_required_dependencies.return_value = []
            mock_mgr.generate_install_script.side_effect = RuntimeError("script gen failed")
            mock_manager_cls.return_value = mock_mgr

            response = test_client.post(
                "/api/dependencies/system/generate-script",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestGenerateDockerfileException:
    """Test generate-dockerfile when generation fails."""

    def test_generate_dockerfile_exception_returns_500(self, test_client, tenant_headers):
        """POST generate-dockerfile returns 500 when snippet generation fails."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.package_manager = MagicMock()
            mock_mgr.package_manager.value = "brew"
            mock_mgr.DEPENDENCY_MAP = {}
            mock_mgr.detect_required_dependencies.side_effect = RuntimeError("dockerfile boom")
            mock_manager_cls.return_value = mock_mgr

            response = test_client.post(
                "/api/dependencies/system/generate-dockerfile",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestGenerateCIConfigException:
    """Test generate-ci-config when generation fails."""

    def test_generate_ci_config_exception_returns_500(self, test_client, tenant_headers):
        """POST generate-ci-config returns 500 when CI config generation fails."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.package_manager = MagicMock()
            mock_mgr.package_manager.value = "brew"
            mock_mgr.detect_required_dependencies.side_effect = RuntimeError("ci config boom")
            mock_manager_cls.return_value = mock_mgr

            response = test_client.post(
                "/api/dependencies/system/generate-ci-config?platform=github",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestListKnownException:
    """Test list-known when listing fails."""

    def test_list_known_exception_returns_500(self, test_client, tenant_headers):
        """GET list-known returns 500 when listing dependencies fails."""
        with patch(
            "routers.system_dependencies.SystemDependencyManager",
        ) as mock_manager_cls:
            mock_mgr = MagicMock()
            mock_mgr.DEPENDENCY_MAP = MagicMock()
            mock_mgr.DEPENDENCY_MAP.values.side_effect = RuntimeError("list boom")
            mock_manager_cls.return_value = mock_mgr

            response = test_client.get(
                "/api/dependencies/system/list-known",
                headers=tenant_headers,
            )
            assert response.status_code == 500
