"""/outdated resolves latest versions inside the workspace (exec mocked; no PyPI)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clients.containers_client import ContainersClientError
from models.package_manager_models import ExternalPackage
from services.dependency_extraction import DependencyExtractor
from services.workspace_latest_versions import (
    LatestLookupError,
    apply_latest_versions,
    fetch_latest_in_workspace,
    parse_uv_tree_outdated,
)
from tests.unit.test_dependency_endpoints import _make_container_info, _make_risk_report

UV_OUT = """x v0.1
├── httpx v0.24.0 (latest: v0.28.1)
├── ruff v0.1.0 (latest: v0.17.3)
├── typing-extensions v4.0.0
└── pytest v7.0.0 (group: dev) (latest: v9.1.1)
"""


def _client(resp=None, exc=None):
    c = MagicMock()
    c.exec_command = AsyncMock(return_value=resp, side_effect=exc)
    return c


def _pkg(name, version, ecosystem="pypi"):
    return ExternalPackage(name=name, version=version, ecosystem=ecosystem)


def test_parse_uv_tree_outdated():
    assert parse_uv_tree_outdated(UV_OUT) == {
        "httpx": "0.28.1",
        "ruff": "0.17.3",
        "pytest": "9.1.1",
    }


def test_parse_empty_and_up_to_date():
    assert parse_uv_tree_outdated("") == {}
    assert parse_uv_tree_outdated("x v0.1\n└── ruff v0.17.3\n") == {}


async def test_fetch_runs_uv_in_workspace():
    c = _client({"exit_code": 0, "stdout": UV_OUT})
    got = await fetch_latest_in_workspace(c, container_name="repo", tenant_id="t1")
    assert got["ruff"] == "0.17.3"
    kw = c.exec_command.await_args.kwargs
    assert kw["command"][:3] == ["uv", "tree", "--outdated"] and "--frozen" in kw["command"]
    assert kw["workdir"] == "/workspace" and kw["container_name"] == "repo"


async def test_fetch_nonzero_exit_raises():
    c = _client({"exit_code": 2, "stderr": "error: Unable to find lockfile"})
    with pytest.raises(LatestLookupError, match="exited 2"):
        await fetch_latest_in_workspace(c, container_name="repo", tenant_id="t1")


async def test_fetch_transport_error_raises():
    c = _client(exc=ContainersClientError(502, "bad gateway"))
    with pytest.raises(LatestLookupError, match="workspace exec failed"):
        await fetch_latest_in_workspace(c, container_name="repo", tenant_id="t1")


def test_apply_and_filter_pep440():
    pkgs = [
        _pkg("Ruff", "0.1.0"),
        _pkg("httpx", "0.28.1"),
        _pkg("serde", "1.0.0", "crates.io"),
        _pkg("other", "1.0"),
    ]
    out = apply_latest_versions(pkgs, {"ruff": "0.17.3", "httpx": "0.28.1", "serde": "9"})
    assert out[0].current_version == "0.1.0" and out[0].latest_version == "0.17.3"
    assert out[2].latest_version is None and out[3].latest_version is None
    # "0.9" < "0.10" as versions, "0.9" > "0.10" as strings
    assert [p.name for p in DependencyExtractor().get_outdated_packages(out)] == ["Ruff"]
    tricky = apply_latest_versions([_pkg("a", "0.9")], {"a": "0.10"})
    assert len(DependencyExtractor().get_outdated_packages(tricky)) == 1


def _get(test_client, tenant_headers, tmp_path, *, uv_lock, resp=None, exc=None, packages=None):
    if uv_lock:
        (tmp_path / "uv.lock").write_text("")
    report = _make_risk_report()
    report.packages = packages or []
    client = _client(resp, exc)
    with (
        patch(
            "services.scan_runner.validate_and_get_container_for_tenant",
            new_callable=AsyncMock,
            return_value=_make_container_info(codebase_path=str(tmp_path)),
        ),
        patch(
            "routers.dependencies.ArchitectureDependencyAnalyzer.analyze",
            new_callable=AsyncMock,
            return_value=report,
        ),
        patch("routers.dependencies._build_clients", return_value=(client, None)),
    ):
        r = test_client.get("/api/dependencies/test-container/outdated", headers=tenant_headers)
    return r, client


def test_endpoint_returns_outdated_from_workspace(test_client, tenant_headers, tmp_path):
    r, client = _get(
        test_client,
        tenant_headers,
        tmp_path,
        uv_lock=True,
        resp={"exit_code": 0, "stdout": UV_OUT},
        packages=[_pkg("ruff", "0.1.0"), _pkg("typing-extensions", "4.0.0")],
    )
    assert r.status_code == 200
    body = r.json()
    assert [p["name"] for p in body] == ["ruff"] and body[0]["latest_version"] == "0.17.3"
    client.exec_command.assert_awaited_once()


def test_endpoint_503_when_lookup_fails(test_client, tenant_headers, tmp_path):
    r, _ = _get(
        test_client,
        tenant_headers,
        tmp_path,
        uv_lock=True,
        resp={"exit_code": 1, "stderr": "boom"},
        packages=[_pkg("ruff", "0.1.0")],
    )
    assert r.status_code == 503


def test_endpoint_non_uv_unchanged_no_exec(test_client, tenant_headers, tmp_path):
    r, client = _get(
        test_client, tenant_headers, tmp_path, uv_lock=False, packages=[_pkg("ruff", "0.1.0")]
    )
    assert r.status_code == 200 and r.json() == []
    client.exec_command.assert_not_awaited()
