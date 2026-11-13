"""Regression: /analyze-vulnerabilities on a workspace read nothing and said success.

Measured live 2026-10-12: ``{"container_name": "cv-m2-hello", "file_paths":
["t4/sqli.py", "t4/secret.py"]}`` answered ``status: success,
total_files_analyzed: 0`` — the paths were joined onto the container-side
``/workspace`` and opened on the coding-security pod, where they do not exist.
Each test pairs a planted defect with a clean control.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from models.container_models import ContainerInfo, ContainerStatus
from routers.security._common import SecurityAnalysisRequest
from routers.security.vulnerabilities import analyze_security_vulnerabilities
from services.scan_runner import _MaterializeResult
from services.security_detector import SecurityVulnerabilityDetector

_FILES = {
    "t4/sqli.py": (
        'def get_user(cur, uid):\n    cur.execute("SELECT * FROM users WHERE id = " + uid)\n'
    ),
    "t4/secret.py": 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY"\n',
    "t4/clean.py": "def add(a, b):\n    return a + b\n",
}


class _CleanEngine:
    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        return []


def _detector() -> SecurityVulnerabilityDetector:
    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_iac", "_semgrep", "_image"):
        setattr(d, name, _CleanEngine())
    return d


@pytest.fixture
def remote_workspace(tmp_path: Path):
    """A workspace whose codebase_path (/workspace) is NOT on this pod's disk;
    materialization fetches it into a tempdir, as in production."""
    container = ContainerInfo(
        container_name="cv-m2-hello",
        api_endpoint="http://x",
        codebase_path="/workspace",
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    fetched = tmp_path / "fetched"

    async def _materialize(info, name, tenant_id):
        for rel, content in _FILES.items():
            target = fetched / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        info.codebase_path = str(fetched)
        return _MaterializeResult(temp_dir=str(fetched))

    detector = _detector()
    with (
        patch(
            "routers.security.vulnerabilities.validate_and_get_container_for_tenant",
            AsyncMock(return_value=container),
        ),
        patch("routers.security.vulnerabilities._materialize_codebase", _materialize),
        patch(
            "routers.security.vulnerabilities.get_security_detector_async",
            AsyncMock(return_value=detector),
        ),
    ):
        yield fetched


async def _analyze(paths: list[str]):
    return await analyze_security_vulnerabilities(
        request=SecurityAnalysisRequest(container_name="cv-m2-hello", file_paths=paths),
        tenant_id="tenant-a",
    )


async def test_workspace_relative_paths_are_read_and_sqli_found(remote_workspace):
    resp = await _analyze(["t4/sqli.py", "t4/secret.py"])

    assert resp.result.total_files_analyzed == 2
    assert "sql_injection" in resp.result.vulnerabilities_by_type
    assert "hardcoded_credentials" in resp.result.vulnerabilities_by_type
    assert resp.status == "success"
    assert resp.result.scan_degraded is False
    # the materialized tempdir is cleaned up
    assert not remote_workspace.exists()


async def test_container_absolute_paths_also_resolve(remote_workspace):
    resp = await _analyze(["/workspace/t4/sqli.py"])
    assert resp.result.total_files_analyzed == 1
    assert "sql_injection" in resp.result.vulnerabilities_by_type


async def test_clean_file_is_clean_and_complete(remote_workspace):
    """Clean control: one clean file, examined, no findings, not degraded."""
    resp = await _analyze(["t4/clean.py"])

    assert resp.result.total_files_analyzed == 1
    assert resp.result.total_vulnerabilities_found == 0
    assert resp.status == "success"
    assert resp.result.scan_degraded is False


async def test_zero_files_analysed_is_degraded_never_success(remote_workspace):
    """Planted defect: nothing could be examined -> degraded with a reason."""
    resp = await _analyze(["t4/does_not_exist.py"])

    assert resp.result.total_files_analyzed == 0
    assert resp.status == "degraded"
    assert resp.result.scan_degraded is True
    assert any("not found" in r for r in resp.result.degraded_reasons)


class _MustNotRead:
    async def analyze_security_vulnerabilities(self, *a, **kw):
        raise AssertionError("a file was handed to the detector")


@pytest.mark.parametrize("paths", [["/etc/passwd"], ["src/routers/security/_common.py"]])
async def test_file_paths_without_container_is_400_and_nothing_is_read(paths):
    """Arbitrary-file-read: bare file_paths used to be opened on THIS pod."""
    with patch(
        "routers.security.vulnerabilities.get_security_detector_async",
        AsyncMock(return_value=_MustNotRead()),
    ):
        with pytest.raises(HTTPException) as exc:
            await analyze_security_vulnerabilities(
                request=SecurityAnalysisRequest(file_paths=paths), tenant_id="tenant-a"
            )
    assert exc.value.status_code == 400
    assert "container_name is required" in str(exc.value.detail)


@pytest.mark.parametrize(
    "path", ["../../etc/passwd", "/workspace/../../etc/passwd", "t4/../../../etc/passwd"]
)
async def test_traversal_path_is_refused_before_anything_runs(remote_workspace, path):
    with patch(
        "routers.security.vulnerabilities.get_security_detector_async",
        AsyncMock(return_value=_MustNotRead()),
    ):
        with pytest.raises(HTTPException) as exc:
            await _analyze([path, "t4/clean.py"])
    assert exc.value.status_code == 400
    assert "etc/passwd" in str(exc.value.detail)


async def test_inner_dotdot_that_stays_inside_is_allowed(remote_workspace):
    """Control: ``t4/../t4/clean.py`` stays in the workspace and is read."""
    resp = await _analyze(["t4/../t4/clean.py"])
    assert resp.result.total_files_analyzed == 1
    assert resp.status == "success"
