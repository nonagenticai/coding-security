"""Tests for security API endpoints."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.common import ResponseStatus
from models.container_models import ContainerInfo, ContainerStatus
from models.security_api_models import (
    ContainerSecurityReport,
    SecurityScanResult,
    SeverityDistribution,
)
from services.scan_runner import _MaterializeResult


@pytest.fixture(autouse=True)
def _caller_owns_the_workspace():
    """The image/SBOM endpoints first resolve the name as the caller's own
    workspace (404 otherwise; covered in test_image_sbom_workspace_source.py).
    Answer with a local workspace so nothing hits the network or fetches."""
    with (
        patch(
            "routers.security.image_sbom._tenant_workspace",
            AsyncMock(return_value=_make_container_info()),
        ),
        patch(
            "routers.security.image_sbom._materialize_codebase",
            AsyncMock(return_value=_MaterializeResult(temp_dir=None)),
        ),
    ):
        yield


def _make_container_info(name="test-container"):
    """Helper to build a ContainerInfo for mocking."""
    return ContainerInfo(
        container_name=name,
        api_endpoint="http://localhost:8080",
        codebase_path="/tmp/test-codebase",
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


def _make_scan_result(container_name="test-container"):
    """Helper to build a SecurityScanResult for mocking."""
    return SecurityScanResult(
        container_name=container_name,
        scan_timestamp=datetime.now(UTC),
        scan_duration_seconds=1.5,
        total_files_scanned=10,
        total_vulnerabilities=2,
        critical_count=0,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
        overall_risk_score=35.0,
        security_grade="B",
        file_results=[],
        vulnerability_summary={"sql_injection": 1, "xss": 1},
        affected_files=["src/db.py"],
    )


def _make_security_report(container_name="test-container"):
    """Helper to build a ContainerSecurityReport for mocking."""
    scan_result = _make_scan_result(container_name)
    return ContainerSecurityReport(
        container_name=container_name,
        report_generated_at=datetime.now(UTC),
        scan_summary=scan_result,
        severity_distribution=SeverityDistribution(high=1, medium=1),
        vulnerability_types=[],
        security_hotspots=[],
        top_priorities=[],
        security_score=65.0,
        security_grade="B",
        recommendations=["Fix SQL injection"],
        affected_files_count=1,
        clean_files_count=9,
        language_breakdown={"python": 1},
    )


def _own_workspace(tmp_path):
    """/analyze-vulnerabilities reads files only from the caller's workspace.
    A local codebase_path (tmp_path) means nothing is fetched."""
    info = _make_container_info("my-ws")
    info.codebase_path = str(tmp_path)
    return patch(
        "routers.security.vulnerabilities.validate_and_get_container_for_tenant",
        AsyncMock(return_value=info),
    )


class TestSecurityEndpoints:
    def test_validate_code_security(self, test_client, tenant_headers):
        """POST /api/security/validate returns validation result."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "x = 1 + 2", "language": "python"},
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_validate_dangerous_code(self, test_client, tenant_headers):
        """POST /api/security/validate detects dangerous code."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "eval(user_input)", "language": "python"},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "success" or "message" in data

    def test_get_security_patterns(self, test_client, tenant_headers):
        """GET /api/security/patterns returns available patterns."""
        response = test_client.get("/api/security/patterns", headers=tenant_headers)
        assert response.status_code == 200

    def test_get_sandbox_config(self, test_client, tenant_headers):
        """GET /api/security/sandbox-config returns config."""
        response = test_client.get(
            "/api/security/sandbox-config/python/medium",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_validate_unsupported_language(self, test_client, tenant_headers):
        """POST /api/security/validate returns 422 for unsupported language (Pydantic enum validation)."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "x = 1", "language": "brainfuck"},
            headers=tenant_headers,
        )
        assert response.status_code == 422

    def test_validate_empty_code(self, test_client, tenant_headers):
        """POST /api/security/validate with empty code still returns 200."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "", "language": "python"},
            headers=tenant_headers,
        )
        # Empty code is valid input, service handles it
        assert response.status_code == 200

    def test_validate_multiple_languages(self, test_client, tenant_headers):
        """Covered languages answer 200; uncovered ones are refused (422), never 'safe'."""
        for lang in ["python", "javascript", "js"]:
            response = test_client.post(
                "/api/security/validate",
                json={"code": "x = 1", "language": lang},
                headers=tenant_headers,
            )
            assert response.status_code == 200, f"Failed for language: {lang}"
        for lang in ["java", "go", "rust"]:
            response = test_client.post(
                "/api/security/validate",
                json={"code": "x = 1", "language": lang},
                headers=tenant_headers,
            )
            assert response.status_code == 422, f"Not refused for language: {lang}"
            assert "not computed" in response.text

    def test_analyze_vulnerabilities_no_input(self, test_client, tenant_headers):
        """POST /api/security/analyze-vulnerabilities with no container or files returns 400."""
        response = test_client.post(
            "/api/security/analyze-vulnerabilities",
            json={},
            headers=tenant_headers,
        )
        assert response.status_code == 400

    def test_analyze_vulnerabilities_with_file_paths(self, test_client, tenant_headers, tmp_path):
        """POST /api/security/analyze-vulnerabilities with file_paths."""
        # Create a temp Python file to analyze
        test_file = tmp_path / "test_code.py"
        test_file.write_text("import os\nos.system('rm -rf /')\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={"container_name": "my-ws", "file_paths": [test_file.name]},
                headers=tenant_headers,
            )
        assert response.status_code == 200

    def test_analyze_vulnerabilities_pod_paths_without_container_are_400(
        self, test_client, tenant_headers
    ):
        """Bare file_paths used to be opened on the security pod itself
        (arbitrary-file-read). Without container_name: 400, nothing read."""
        response = test_client.post(
            "/api/security/analyze-vulnerabilities",
            json={"file_paths": ["/etc/passwd"]},
            headers=tenant_headers,
        )
        assert response.status_code == 400
        assert "container_name is required" in response.text
        assert "root:" not in response.text

    def test_analyze_vulnerabilities_invalid_severity(self, test_client, tenant_headers, tmp_path):
        """POST /api/security/analyze-vulnerabilities with invalid severity filter."""
        test_file = tmp_path / "test_code.py"
        test_file.write_text("x = 1\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={
                    "container_name": "my-ws",
                    "file_paths": [test_file.name],
                    "severity_filter": ["invalid_severity"],
                },
                headers=tenant_headers,
            )
        assert response.status_code == 400

    def test_analyze_vulnerabilities_valid_severity(self, test_client, tenant_headers, tmp_path):
        """POST /api/security/analyze-vulnerabilities with valid severity filter."""
        test_file = tmp_path / "test_code.py"
        test_file.write_text("x = 1\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={
                    "container_name": "my-ws",
                    "file_paths": [test_file.name],
                    "severity_filter": ["critical", "high"],
                },
                headers=tenant_headers,
            )
        assert response.status_code == 200

    def test_sandbox_config_strict(self, test_client, tenant_headers):
        """GET /api/security/sandbox-config with strict level."""
        response = test_client.get(
            "/api/security/sandbox-config/python/strict",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_sandbox_config_relaxed(self, test_client, tenant_headers):
        """GET /api/security/sandbox-config with relaxed level."""
        response = test_client.get(
            "/api/security/sandbox-config/javascript/relaxed",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_scan_container_nonexistent(self, test_client, tenant_headers):
        """POST /api/security/scan/nonexistent returns 404."""
        response = test_client.post(
            "/api/security/scan/nonexistent",
            json={"container_name": "nonexistent"},
            headers=tenant_headers,
        )
        assert response.status_code == 404

    def test_get_report_nonexistent(self, test_client, tenant_headers):
        """GET /api/security/report/nonexistent returns 404."""
        response = test_client.get(
            "/api/security/report/nonexistent",
            headers=tenant_headers,
        )
        assert response.status_code == 404

    def test_quick_scan_nonexistent(self, test_client, tenant_headers):
        """POST /api/security/scan/nonexistent/quick returns 404."""
        response = test_client.post(
            "/api/security/scan/nonexistent/quick",
            headers=tenant_headers,
        )
        assert response.status_code == 404


class TestSecurityEndpointsExtended:
    """Additional security endpoint tests for coverage."""

    def test_validate_returns_risk_level_fields(self, test_client, tenant_headers):
        """POST /api/security/validate returns risk_score and violations."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "x = 1", "language": "python"},
            headers=tenant_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "data" in data or "validation" in data

    def test_validate_high_risk_code(self, test_client, tenant_headers):
        """Python code with eval+exec+subprocess triggers high risk."""
        response = test_client.post(
            "/api/security/validate",
            json={
                "code": "eval('x')\nexec('y')\nimport subprocess\nsubprocess.call('z')",
                "language": "python",
            },
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_validate_with_context(self, test_client, tenant_headers):
        """POST /api/security/validate with context field."""
        response = test_client.post(
            "/api/security/validate",
            json={
                "code": "x = 1",
                "language": "python",
                "context": {"execution_context": "testing"},
            },
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_sandbox_config_unknown_language(self, test_client, tenant_headers):
        """GET sandbox-config with unknown language returns default config."""
        response = test_client.get(
            "/api/security/sandbox-config/cobol/medium",
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_analyze_vulnerabilities_with_severity_critical(
        self, test_client, tenant_headers, tmp_path
    ):
        """POST analyze-vulnerabilities filters to critical only."""
        test_file = tmp_path / "vuln.py"
        test_file.write_text("eval(user_input)\nos.system('rm -rf /')\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={
                    "container_name": "my-ws",
                    "file_paths": [test_file.name],
                    "severity_filter": ["critical"],
                },
                headers=tenant_headers,
            )
        assert response.status_code == 200

    def test_analyze_vulnerabilities_with_low_confidence(
        self, test_client, tenant_headers, tmp_path
    ):
        """POST analyze-vulnerabilities with include_low_confidence=true."""
        test_file = tmp_path / "code.py"
        test_file.write_text("import os\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={
                    "container_name": "my-ws",
                    "file_paths": [test_file.name],
                    "include_low_confidence": True,
                },
                headers=tenant_headers,
            )
        assert response.status_code == 200

    def test_analyze_vulnerabilities_multiple_files(self, test_client, tenant_headers, tmp_path):
        """POST analyze-vulnerabilities with multiple files."""
        f1 = tmp_path / "a.py"
        f1.write_text("eval('x')\n")
        f2 = tmp_path / "b.py"
        f2.write_text("x = 1\n")
        with _own_workspace(tmp_path):
            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={"container_name": "my-ws", "file_paths": [f1.name, f2.name]},
                headers=tenant_headers,
            )
        assert response.status_code == 200

    def test_security_patterns_returns_list(self, test_client, tenant_headers):
        """GET /api/security/patterns returns pattern categories."""
        response = test_client.get("/api/security/patterns", headers=tenant_headers)
        assert response.status_code == 200
        data = response.json()
        assert "data" in data or "patterns" in data

    def test_validate_javascript_code(self, test_client, tenant_headers):
        """POST /api/security/validate for JavaScript."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "var x = eval('1');", "language": "javascript"},
            headers=tenant_headers,
        )
        assert response.status_code == 200

    def test_validate_java_code(self, test_client, tenant_headers):
        """POST /api/security/validate for Java."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "Runtime.getRuntime().exec(cmd);", "language": "java"},
            headers=tenant_headers,
        )
        assert response.status_code == 422  # no pattern table: not computed, never 'safe'

    def test_validate_cpp_code(self, test_client, tenant_headers):
        """POST /api/security/validate for C++."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "system(user_input);", "language": "cpp"},
            headers=tenant_headers,
        )
        assert response.status_code == 422  # no pattern table: not computed, never 'safe'


class TestSecurityValidateErrorPaths:
    """Tests covering error branches in validate_code_security."""

    def test_validate_value_error_returns_404(self, test_client, tenant_headers):
        """ValueError from security service maps to 404."""
        with patch(
            "routers.security.validation.SystemSecurityService.validate_code_security",
            new_callable=AsyncMock,
            side_effect=ValueError("container xyz not found"),
        ):
            response = test_client.post(
                "/api/security/validate",
                json={"code": "x = 1", "language": "python"},
                headers=tenant_headers,
            )
            assert response.status_code == 404

    def test_validate_generic_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception from security service maps to 500."""
        with patch(
            "routers.security.validation.SystemSecurityService.validate_code_security",
            new_callable=AsyncMock,
            side_effect=RuntimeError("unexpected failure"),
        ):
            response = test_client.post(
                "/api/security/validate",
                json={"code": "x = 1", "language": "python"},
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestSandboxConfigErrorPath:
    """Tests covering error branches in get_sandbox_config."""

    def test_sandbox_config_exception_returns_500(self, test_client, tenant_headers):
        """Exception from generate_sandbox_config maps to 500."""
        with patch(
            "routers.security.validation.SystemSecurityService.generate_sandbox_config",
            new_callable=AsyncMock,
            side_effect=RuntimeError("config generation failed"),
        ):
            response = test_client.get(
                "/api/security/sandbox-config/python/strict",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestContainerScanEndpoints:
    """Tests for scan/{container_name}, report/{container_name}, and quick scan."""

    def test_scan_container_success(self, test_client, tenant_headers):
        """POST /api/security/scan/{name} with mocked container returns 200."""
        container = _make_container_info()
        scan_result = _make_scan_result()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(return_value=scan_result)
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container",
                json={},
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["result"]["total_vulnerabilities"] == 2

    def test_scan_container_degraded_envelope_not_success(self, test_client, tenant_headers):
        """A degraded (timed-out / partial-coverage) scan must NOT report top-level
        status='success' (F5 residual). A consumer keying only on `status` would
        otherwise read a truncated scan as a clean pass."""
        container = _make_container_info()
        scan_result = _make_scan_result()
        scan_result.scan_degraded = True

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(return_value=scan_result)
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container",
                json={},
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "degraded"
            assert "DEGRADED" in data["message"]
            # The findings are still surfaced — degraded, not discarded.
            assert data["result"]["scan_degraded"] is True
            assert data["result"]["total_vulnerabilities"] == 2

    def test_scan_container_remote_bulk_download(self, test_client, tenant_headers):
        """Remote codebase fetch bulk-reads files in one /exec round-trip per
        chunk (a single whitelisted ``python`` reader), NOT a ``cat`` per file
        (E3.16 — the IaC-scan latency fix). Verifies the downloaded files land
        in the temp dir handed to the scan service."""
        container = _make_container_info()
        scan_result = _make_scan_result()

        posted_commands = []
        written_files = {}

        def _record_scan(
            container_info, _request, *, partial=None, deadline=None, force_degraded=False
        ):
            # Capture the materialised codebase before the finally-cleanup runs.
            root = container_info.codebase_path
            for dirpath, _dirs, names in os.walk(root):
                for name in names:
                    fp = os.path.join(dirpath, name)
                    with open(fp) as fh:
                        written_files[os.path.relpath(fp, root)] = fh.read()
            return scan_result

        class _FakeResp:
            def __init__(self, payload):
                self.status_code = 200
                self._payload = payload
                # ServiceClient treats a falsy .content as "no body".
                self.content = b"{}"
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        class _FakeClient:
            # Async client: the workspace fetch goes through
            # CodingWorkspacesClient, which drives httpx.AsyncClient.request()
            # and closes the client itself rather than using `async with`.
            is_closed = False

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def aclose(self):
                return None

            async def request(self, _method, url, **kwargs):
                return await self.post(url, **kwargs)

            async def post(self, _url, **kwargs):
                cmd = kwargs["json"]["command"]
                posted_commands.append(cmd)
                if cmd[0] == "find":
                    return _FakeResp(
                        {"stdout": "/workspace/infra/main.tf\n/workspace/k8s/pod.yaml\n"}
                    )
                if cmd[0] == "python":
                    # cmd = ["python", "-c", reader, str(max_bytes), *paths]
                    paths = cmd[4:]
                    contents = {
                        "/workspace/infra/main.tf": 'resource "x" {}',
                        "/workspace/k8s/pod.yaml": "kind: Pod",
                    }
                    return _FakeResp({"stdout": json.dumps({p: contents[p] for p in paths})})
                raise AssertionError(f"unexpected /exec command: {cmd!r}")

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            patch("services.scan_runner.os.path.isdir", return_value=False),
            patch("httpx.AsyncClient", return_value=_FakeClient()),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(side_effect=_record_scan)
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 200
        # Exactly one find + one bulk python read (two files in one chunk).
        assert [c[0] for c in posted_commands] == ["find", "python"]
        # No per-file `cat` round-trips.
        assert all(c[0] != "cat" for c in posted_commands)
        # Both IaC files materialised for the scanner.
        assert written_files == {
            "infra/main.tf": 'resource "x" {}',
            "k8s/pod.yaml": "kind: Pod",
        }

    def test_scan_container_name_mismatch_returns_400(self, test_client, tenant_headers):
        """Mismatched container_name in body vs path returns 400."""
        container = _make_container_info()

        with patch(
            "routers.security.container_scan.validate_and_get_container_for_tenant",
            new_callable=AsyncMock,
            return_value=container,
        ):
            response = test_client.post(
                "/api/security/scan/test-container",
                json={"container_name": "different-container"},
                headers=tenant_headers,
            )
            assert response.status_code == 400

    def test_scan_container_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception during scan maps to 500."""
        container = _make_container_info()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(side_effect=RuntimeError("scan boom"))
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container",
                json={},
                headers=tenant_headers,
            )
            assert response.status_code == 500

    def test_report_container_success(self, test_client, tenant_headers):
        """GET /api/security/report/{name} with mocked container returns 200."""
        container = _make_container_info()
        scan_result = _make_scan_result()
        report = _make_security_report()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            # Local codebase → the shared _materialize_codebase short-circuits
            # (no remote /workspace fetch). The report path now materialises the
            # codebase too (Defect 2), same as POST /scan.
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(return_value=scan_result)
            mock_svc.generate_security_report = AsyncMock(return_value=report)
            mock_get_svc.return_value = mock_svc

            response = test_client.get(
                "/api/security/report/test-container",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["report"]["security_grade"] == "B"

    def test_report_container_fetches_remote_workspace(self, test_client, tenant_headers):
        """Regression for Defect 2: the report path previously never fetched the
        remote /workspace, so it walked a nonexistent path on the pod and graded
        a fake 'A' on zero files. It must now materialise the remote codebase
        (find + bulk python read) before scanning, exactly like POST /scan."""
        container = _make_container_info()
        scan_result = _make_scan_result()
        report = _make_security_report()

        posted_commands = []
        materialised_root = {}

        class _FakeResp:
            status_code = 200

            def __init__(self, payload):
                self._payload = payload
                # ServiceClient treats a falsy .content as "no body".
                self.content = b"{}"
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        class _FakeAsyncClient:
            # See _FakeClient above: the SDK calls .request()/.aclose().
            is_closed = False

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def aclose(self):
                return None

            async def request(self, _method, url, **kwargs):
                return await self.post(url, **kwargs)

            async def post(self, _url, **kwargs):
                cmd = kwargs["json"]["command"]
                posted_commands.append(cmd[0])
                if cmd[0] == "find":
                    return _FakeResp({"stdout": "/workspace/src/app.py\n"})
                # python bulk reader
                paths = cmd[4:]
                return _FakeResp({"stdout": json.dumps({p: "import os" for p in paths})})

        async def _record_scan(
            container_info, _request, *, partial=None, deadline=None, force_degraded=False
        ):
            root = container_info.codebase_path
            materialised_root["path"] = root
            found = []
            for dirpath, _dirs, names in os.walk(root):
                for name in names:
                    found.append(os.path.relpath(os.path.join(dirpath, name), root))
            materialised_root["files"] = sorted(found)
            return scan_result

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            patch("services.scan_runner.os.path.isdir", return_value=False),
            patch("httpx.AsyncClient", return_value=_FakeAsyncClient()),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(side_effect=_record_scan)
            mock_svc.generate_security_report = AsyncMock(return_value=report)
            mock_get_svc.return_value = mock_svc

            response = test_client.get(
                "/api/security/report/test-container",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        # The report path fetched the workspace (find + python bulk read)...
        assert posted_commands == ["find", "python"]
        # ...and handed the scan service the materialised temp dir, not /workspace.
        assert materialised_root["path"] != "/tmp/test-codebase"
        assert materialised_root["files"] == [os.path.join("src", "app.py")]

    def test_report_container_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception during report generation maps to 500."""
        container = _make_container_info()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            # Local codebase so the failure under test is the scan itself, not
            # the remote fetch.
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(side_effect=RuntimeError("report boom"))
            mock_get_svc.return_value = mock_svc

            response = test_client.get(
                "/api/security/report/test-container",
                headers=tenant_headers,
            )
            assert response.status_code == 500

    def test_quick_scan_container_success(self, test_client, tenant_headers):
        """POST /api/security/scan/{name}/quick with mocked container returns 200."""
        container = _make_container_info()
        scan_result = _make_scan_result()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            # Local codebase → no remote fetch (quick path now materialises too).
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(return_value=scan_result)
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container/quick",
                headers=tenant_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"

    def test_quick_scan_with_max_files(self, test_client, tenant_headers):
        """POST quick scan with max_files query param."""
        container = _make_container_info()
        scan_result = _make_scan_result()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            # Local codebase → no remote fetch (quick path now materialises too).
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(return_value=scan_result)
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container/quick?max_files=50",
                headers=tenant_headers,
            )
            assert response.status_code == 200

    def test_quick_scan_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception during quick scan maps to 500."""
        container = _make_container_info()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_security_scan_service",
            ) as mock_get_svc,
            # Local codebase so the failure under test is the scan itself, not
            # the remote fetch.
            patch("services.scan_runner.os.path.isdir", return_value=True),
        ):
            mock_svc = MagicMock()
            mock_svc.scan_container = AsyncMock(side_effect=RuntimeError("quick boom"))
            mock_get_svc.return_value = mock_svc

            response = test_client.post(
                "/api/security/scan/test-container/quick",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class _FakeRedis:
    """In-memory async stand-in for the redis.asyncio client (tests have no Redis).

    Records the status-record ``set`` (poll store) and the durable ``xadd``
    (enqueue) so a submit test can prove BOTH the queued write and the enqueue
    happened — without a real Redis.
    """

    def __init__(self):
        self.store: dict[str, str] = {}
        self.jobs: list[tuple[str, dict]] = []
        self._seq = 0

    async def set(self, k, v, ex=None):
        self.store[k] = v

    async def get(self, k):
        return self.store.get(k)

    async def xadd(self, stream, fields, maxlen=None, approximate=None):
        self._seq += 1
        msg_id = f"0-{self._seq}"
        self.jobs.append((msg_id, dict(fields)))
        return msg_id


class _RaisingSetRedis(_FakeRedis):
    """FakeRedis whose ``set`` raises ConnectionError — models a store offline
    on the write path (get_redis() itself succeeds, but the SET fails)."""

    async def set(self, k, v, ex=None):
        raise ConnectionError("redis down")


class TestAsyncScanEndpoints:
    """Tests for the additive async (task_id + poll) container-scan HTTP contract:
    POST /scan/{name}/async  +  GET /scan/results/{task_id}.

    The scan itself is executed by the durable Redis-Streams worker (see
    ``test_scan_worker.py``); these tests assert the endpoint contract — submit
    stamps ``queued`` + enqueues a job, and the poll reads the stored record back
    tenant-scoped with staleness derivation.
    """

    def test_async_submit_returns_task_id_and_enqueues(self, test_client, tenant_headers):
        """POST /scan/{name}/async returns 200 + queued and enqueues a durable job
        carrying the full serialised scan request."""
        container = _make_container_info()
        fake = _FakeRedis()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch("routers.security.container_scan.get_redis", return_value=fake),
        ):
            response = test_client.post(
                "/api/security/scan/test-container/async",
                json={"scan_type": "full"},
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert data["container_name"] == "test-container"
        assert data.get("task_id")

        assert any(k.startswith("security_scan_task:") for k in fake.store)
        assert len(fake.jobs) == 1
        _msg_id, fields = fake.jobs[0]
        assert fields["kind"] == "container"
        assert fields["container_name"] == "test-container"
        assert fields["task_id"] == data["task_id"]
        assert fields["tenant_id"] == "test-tenant"
        assert float(fields["budget_seconds"]) > 0
        # The full request round-trips as JSON so the worker rebuilds the exact scan.
        req = json.loads(fields["scan_request"])
        assert req["container_name"] == "test-container"
        assert req["scan_type"] == "full"

    def test_async_submit_redis_down_returns_503(self, test_client, tenant_headers):
        """Redis offline (get_redis raises RuntimeError) → 503, no task enqueued."""
        container = _make_container_info()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_redis",
                side_effect=RuntimeError("Redis not initialised"),
            ),
        ):
            response = test_client.post(
                "/api/security/scan/test-container/async",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 503

    def test_async_submit_name_mismatch_returns_400(self, test_client, tenant_headers):
        """Mismatched container_name in body vs path returns 400 (before enqueue)."""
        container = _make_container_info()
        fake = _FakeRedis()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch("routers.security.container_scan.get_redis", return_value=fake),
        ):
            response = test_client.post(
                "/api/security/scan/test-container/async",
                json={"container_name": "different-container"},
                headers=tenant_headers,
            )

        assert response.status_code == 400
        assert fake.jobs == []

    def test_async_submit_store_fails_returns_503(self, test_client, tenant_headers):
        """get_redis() succeeds but the SET raises → required queued write fails
        → 503 (store offline), no task enqueued."""
        container = _make_container_info()
        fake = _RaisingSetRedis()

        with (
            patch(
                "routers.security.container_scan.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=container,
            ),
            patch(
                "routers.security.container_scan.get_redis",
                return_value=fake,
            ),
        ):
            response = test_client.post(
                "/api/security/scan/test-container/async",
                json={},
                headers=tenant_headers,
            )

        assert response.status_code == 503
        assert fake.jobs == []

    def test_async_poll_pending_for_unknown_task(self, test_client, tenant_headers):
        """Polling a random/unknown task_id returns status pending."""
        fake = _FakeRedis()
        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{uuid.uuid4()}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"

    def test_async_poll_queued_stays_queued(self, test_client, tenant_headers):
        """A queued record with an OLD updated_at must NOT flip to failed: the job
        is durable in the stream (reclaim-guaranteed) until a worker starts it.
        Regression for the staleness fix that dropped queued from stale-eligible."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "queued",
                "updated_at": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert "stale" not in data

    def test_async_poll_cross_tenant_returns_404(self, test_client, tenant_headers):
        """A record owned by another tenant must not be readable → 404."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "other-tenant",
                "status": "completed",
                "scan_degraded": False,
                "result": {},
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 404

    def test_async_poll_null_tenant_record_returns_404(self, test_client, tenant_headers):
        """Strict tenant equality: a legacy record with tenant_id=None is NOT
        readable by any tenant (previously None was allowed through) → 404."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": None,
                "status": "completed",
                "result": {},
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 404

    def test_async_poll_corrupt_record_returns_pending(self, test_client, tenant_headers):
        """A corrupt (non-JSON) stored record is treated as pending, not a 500."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = "{ not json"

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        assert response.json()["status"] == "pending"

    def test_async_poll_stale_running_returns_failed(self, test_client, tenant_headers):
        """A running record whose updated_at is far in the past → failed+stale."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "running",
                "updated_at": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data["stale"] is True
        assert "stalled" in data["error"]
        # pre-existing keys survive the {**record, ...} staleness merge
        assert data["container_name"] == "test-container"

    def test_async_poll_missing_updated_at_running_is_stale(self, test_client, tenant_headers):
        """A running record with NO updated_at (legacy/timeless) is treated as
        stale → failed, so a dead worker's frozen record is observable."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "running",
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data["stale"] is True

    def test_async_poll_fresh_running_stays_running(self, test_client, tenant_headers):
        """A running record with a fresh updated_at is NOT stale → stays running
        (a live-but-slow scan must not be mislabelled failed)."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "running",
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "stale" not in data

    def test_async_poll_completed_with_stale_updated_at_stays_completed(
        self, test_client, tenant_headers
    ):
        """A terminal 'completed' record with an OLD updated_at must be returned
        unchanged — staleness derivation applies ONLY to running, never a
        finished scan."""
        fake = _FakeRedis()
        task_id = str(uuid.uuid4())
        fake.store[f"security_scan_task:{task_id}"] = json.dumps(
            {
                "task_id": task_id,
                "container_name": "test-container",
                "tenant_id": "test-tenant",
                "status": "completed",
                "scan_degraded": False,
                "result": {"security_grade": "B", "total_vulnerabilities": 2},
                "updated_at": (datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),
            }
        )

        with patch("routers.security.container_scan.get_redis", return_value=fake):
            response = test_client.get(
                f"/api/security/scan/results/{task_id}",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "stale" not in data
        assert data["result"]["security_grade"] == "B"


class TestSecurityPatternsErrorPath:
    """Tests for error path in get_security_patterns."""

    def test_patterns_exception_returns_500(self, test_client, tenant_headers):
        """Exception from get_security_detector_async maps to 500."""
        with patch(
            "routers.security.vulnerabilities.get_security_detector_async",
            new_callable=AsyncMock,
            side_effect=RuntimeError("patterns boom"),
        ):
            response = test_client.get(
                "/api/security/patterns",
                headers=tenant_headers,
            )
            assert response.status_code == 500


class TestAnalyzeVulnerabilitiesAdditional:
    """Additional coverage for analyze_security_vulnerabilities."""

    def test_analyze_with_container_name(self, test_client, tenant_headers, tmp_path):
        """POST analyze-vulnerabilities with container_name uses container registry.

        The container lookup is tenant-scoped, so this patches the registry the
        BOLA guard (``validate_and_get_container_for_tenant``) actually calls.
        ``codebase_path`` is a real directory so the local-filesystem branch
        resolves without a remote exec call.
        """
        (tmp_path / "app.py").write_text("x = 1\n")
        mock_container = MagicMock()
        mock_container.codebase_path = str(tmp_path)

        with patch(
            "utils.container_validation.get_container_registry",
        ) as mock_reg_fn:
            mock_reg = MagicMock()
            mock_reg.get_container_async = AsyncMock(return_value=mock_container)
            mock_reg_fn.return_value = mock_reg

            with patch(
                "routers.security.vulnerabilities.get_security_detector_async",
                new_callable=AsyncMock,
            ) as mock_det_fn:
                from services.security_detector import SecurityAnalysisResult

                mock_det = MagicMock()
                mock_det.analyze_security_vulnerabilities = AsyncMock(
                    return_value=SecurityAnalysisResult(
                        total_files_analyzed=0,
                        total_vulnerabilities_found=0,
                        analysis_time_seconds=0.1,
                    )
                )
                mock_det_fn.return_value = mock_det

                response = test_client.post(
                    "/api/security/analyze-vulnerabilities",
                    json={"container_name": "my-container"},
                    headers=tenant_headers,
                )
                # Container exists but has no files, may still return 200
                assert response.status_code == 200

    def test_analyze_exception_returns_500(self, test_client, tenant_headers, tmp_path):
        """Unhandled exception during analysis maps to 500."""
        test_file = tmp_path / "boom.py"
        test_file.write_text("x = 1\n")

        with patch(
            "routers.security.vulnerabilities.get_security_detector_async",
            new_callable=AsyncMock,
        ) as mock_det_fn:
            mock_det = MagicMock()
            mock_det.analyze_security_vulnerabilities = AsyncMock(
                side_effect=RuntimeError("detector crashed"),
            )
            mock_det_fn.return_value = mock_det

            with _own_workspace(tmp_path):
                response = test_client.post(
                    "/api/security/analyze-vulnerabilities",
                    json={"container_name": "my-ws", "file_paths": [test_file.name]},
                    headers=tenant_headers,
                )
            assert response.status_code == 500

    def test_analyze_container_not_found_returns_404(self, test_client, tenant_headers):
        """Container not found *for this tenant* raises 404.

        The tenant-scoped registry returns None both for a missing container and
        for one owned by another tenant (BOLA: no enumeration), so this covers
        both.
        """
        with patch(
            "utils.container_validation.get_container_registry",
        ) as mock_reg_fn:
            mock_reg = MagicMock()
            mock_reg.get_container_async = AsyncMock(return_value=None)
            mock_reg_fn.return_value = mock_reg

            response = test_client.post(
                "/api/security/analyze-vulnerabilities",
                json={"container_name": "missing-container"},
                headers=tenant_headers,
            )
            assert response.status_code == 404


def _make_settings_mock():
    """Return a MagicMock that looks like Settings for image-scanning endpoints."""
    return MagicMock(
        docker_registry_url="mirror.example.com",
        trivy_scan_timeout=300,
        grype_scan_timeout=300,
        syft_scan_timeout=180,
    )


def _make_image_vuln(severity="HIGH"):
    """Create a minimal ImageVulnerability."""
    from models.image_scan_models import ImageVulnerability

    return ImageVulnerability(
        vulnerability_id="CVE-2024-1234",
        package_name="libssl",
        installed_version="1.1.1",
        fixed_version="1.1.2",
        severity=severity,
    )


def _make_sbom_result(container_name="test-container", raw_sbom='{"bomFormat":"CycloneDX"}'):
    """Create a minimal SBOMResult."""
    from datetime import UTC, datetime

    from models.image_scan_models import SBOMPackage, SBOMResult

    return SBOMResult(
        container_name=container_name,
        image_ref=f"mirror.example.com/{container_name}:latest",
        format="cyclonedx-json",
        generated_at=datetime.now(UTC),
        total_packages=2,
        packages_by_type={"python": 2},
        packages=[
            SBOMPackage(name="requests", version="2.31.0", type="python"),
            SBOMPackage(name="fastapi", version="0.115.0", type="python"),
        ],
        raw_sbom=raw_sbom,
    )


def _make_image_scan_response_mock(scanner="trivy", total=1, by_severity=None, errors=None):
    """Build a dict that ImageScanResponse.model_validate can accept (includes status)."""
    from datetime import UTC, datetime

    from models.image_scan_models import ImageScanResult

    result = ImageScanResult(
        container_name="test-container",
        image_ref="mirror.example.com/test-container:latest",
        scanner=scanner,
        scan_timestamp=datetime.now(UTC),
        scan_duration_seconds=0.5,
        total_vulnerabilities=total,
        by_severity=by_severity or {},
        errors=errors or [],
    )
    from models.security_api_models import ImageScanResponse

    return ImageScanResponse(
        status=ResponseStatus.SUCCESS,
        message=f"scan done using {scanner}",
        result=result,
    )


def _make_sbom_response_mock(total_packages=2):
    """Build a SBOMResponse that includes the required status field."""
    sbom = _make_sbom_result()
    from models.security_api_models import SBOMResponse

    return SBOMResponse(
        status=ResponseStatus.SUCCESS,
        message=f"SBOM generated: {total_packages} packages found",
        result=sbom,
    )


class TestImageScanEndpoint:
    """Tests for POST /api/security/scan/{name}/image."""

    def test_image_scan_on_own_workspace_is_not_computed(self, test_client, tenant_headers):
        """A workspace has no built image: degraded with the reason, and no
        image scanner is constructed."""
        with (
            patch("services.trivy_scanner.TrivyScanner") as mock_trivy_cls,
            patch("services.grype_scanner.GrypeScanner") as mock_grype_cls,
        ):
            response = test_client.post(
                "/api/security/scan/test-container/image?tag=v1.0",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert "test-container:v1.0" in body["result"]["image_ref"]
        mock_trivy_cls.assert_not_called()
        mock_grype_cls.assert_not_called()

    def test_image_scan_unknown_name_is_404(self, test_client, tenant_headers):
        from fastapi import HTTPException

        with patch(
            "routers.security.image_sbom._tenant_workspace",
            AsyncMock(side_effect=HTTPException(status_code=404, detail="not found")),
        ):
            response = test_client.post(
                "/api/security/scan/someone-elses/image",
                headers=tenant_headers,
            )

        assert response.status_code == 404


class TestSBOMEndpoint:
    """Tests for POST /api/security/sbom/{name}."""

    def test_sbom_success(self, test_client, tenant_headers):
        """Syft available: generate_sbom called, SBOMResponse returned."""
        sbom = _make_sbom_result()
        mock_response = _make_sbom_response_mock(total_packages=2)

        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("config.settings.get_settings") as mock_settings,
            patch("routers.security.image_sbom.SBOMResponse", return_value=mock_response),
        ):
            mock_settings.return_value = _make_settings_mock()
            syft_instance = mock_syft_cls.return_value
            syft_instance.generate_sbom = AsyncMock(return_value=sbom)

            response = test_client.post(
                "/api/security/sbom/test-container",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        syft_instance.generate_sbom.assert_called_once()

    def test_sbom_with_spdx_format(self, test_client, tenant_headers):
        """sbom_format=spdx-json query param is forwarded to generate_sbom."""
        sbom = _make_sbom_result()
        mock_response = _make_sbom_response_mock()

        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("config.settings.get_settings") as mock_settings,
            patch("routers.security.image_sbom.SBOMResponse", return_value=mock_response),
        ):
            mock_settings.return_value = _make_settings_mock()
            syft_instance = mock_syft_cls.return_value
            syft_instance.generate_sbom = AsyncMock(return_value=sbom)

            response = test_client.post(
                "/api/security/sbom/test-container?sbom_format=spdx-json",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        call_kwargs = syft_instance.generate_sbom.call_args
        assert call_kwargs.kwargs.get("sbom_format") == "spdx-json"

    def test_sbom_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception during SBOM generation returns 500."""
        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("config.settings.get_settings") as mock_settings,
        ):
            mock_settings.return_value = _make_settings_mock()
            mock_syft_cls.return_value.generate_sbom = AsyncMock(
                side_effect=RuntimeError("syft crashed")
            )

            response = test_client.post(
                "/api/security/sbom/test-container",
                headers=tenant_headers,
            )

        assert response.status_code == 500


class TestSBOMVulnerabilitiesEndpoint:
    """Tests for POST /api/security/sbom/{name}/vulnerabilities."""

    def test_sbom_vulns_success(self, test_client, tenant_headers):
        """Syft + Grype both available: scan_sbom called, response returned."""
        sbom = _make_sbom_result()
        mock_response = _make_image_scan_response_mock(
            scanner="grype", total=1, by_severity={"MEDIUM": 1}
        )

        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("services.grype_scanner.GrypeScanner") as mock_grype_cls,
            patch("config.settings.get_settings") as mock_settings,
            patch("routers.security.image_sbom.ImageScanResponse", return_value=mock_response),
        ):
            mock_settings.return_value = _make_settings_mock()

            mock_syft_cls.return_value.is_syft_available.return_value = True
            mock_syft_cls.return_value.generate_sbom = AsyncMock(return_value=sbom)

            mock_grype_cls.return_value.is_grype_available.return_value = True
            mock_grype_cls.return_value.scan_sbom = AsyncMock(
                return_value=[_make_image_vuln("MEDIUM")]
            )

            response = test_client.post(
                "/api/security/sbom/test-container/vulnerabilities",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        mock_grype_cls.return_value.scan_sbom.assert_called_once()

    def test_sbom_vulns_syft_unavailable(self, test_client, tenant_headers):
        """Syft unavailable: early return with 0 vulnerabilities."""
        mock_response = _make_image_scan_response_mock(
            scanner="grype", total=0, errors=["Syft not available for SBOM generation"]
        )

        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("services.grype_scanner.GrypeScanner") as mock_grype_cls,
            patch("config.settings.get_settings") as mock_settings,
            patch("routers.security.image_sbom.ImageScanResponse", return_value=mock_response),
        ):
            mock_settings.return_value = _make_settings_mock()
            mock_syft_cls.return_value.is_syft_available.return_value = False
            mock_grype_cls.return_value.is_grype_available.return_value = True

            response = test_client.post(
                "/api/security/sbom/test-container/vulnerabilities",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        # generate_sbom should NOT have been called
        mock_syft_cls.return_value.generate_sbom.assert_not_called()

    def test_sbom_vulns_grype_unavailable(self, test_client, tenant_headers):
        """Grype unavailable: early return with 0 vulnerabilities."""
        mock_response = _make_image_scan_response_mock(
            scanner="grype", total=0, errors=["Grype not available for SBOM scanning"]
        )

        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("services.grype_scanner.GrypeScanner") as mock_grype_cls,
            patch("config.settings.get_settings") as mock_settings,
            patch("routers.security.image_sbom.ImageScanResponse", return_value=mock_response),
        ):
            mock_settings.return_value = _make_settings_mock()
            mock_syft_cls.return_value.is_syft_available.return_value = True
            mock_grype_cls.return_value.is_grype_available.return_value = False

            response = test_client.post(
                "/api/security/sbom/test-container/vulnerabilities",
                headers=tenant_headers,
            )

        assert response.status_code == 200
        # scan_sbom should NOT have been called
        mock_grype_cls.return_value.scan_sbom.assert_not_called()

    def test_sbom_vulns_exception_returns_500(self, test_client, tenant_headers):
        """Unhandled exception during SBOM vulnerability scan returns 500."""
        with (
            patch("services.syft_scanner.SyftScanner") as mock_syft_cls,
            patch("services.grype_scanner.GrypeScanner"),
            patch("config.settings.get_settings") as mock_settings,
        ):
            mock_settings.return_value = _make_settings_mock()
            mock_syft_cls.return_value.is_syft_available.side_effect = RuntimeError("syft boom")

            response = test_client.post(
                "/api/security/sbom/test-container/vulnerabilities",
                headers=tenant_headers,
            )

        assert response.status_code == 500


class TestContainerScanIaCDownloadFilter:
    """Guard: the container-scan file-download `find` filter must include IaC
    manifest patterns, otherwise the trivy-config iac_scanner never receives any
    IaC file on the container path and is silently inert (E3.15 root cause)."""

    def test_find_filter_includes_iac_patterns(self):
        import inspect

        # The container-scan file-download `find` filter now lives in the
        # relocated scan runner (imported back into container_scan for the sync
        # endpoints); inspect it there.
        from services import scan_runner

        src = inspect.getsource(scan_runner)
        for pattern in ("*.tf", "*.tofu", "*.yaml", "*.yml", "*.dockerfile", "Containerfile"):
            assert f'"{pattern}"' in src, f"IaC download pattern {pattern} missing from find filter"
