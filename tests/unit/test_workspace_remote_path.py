"""The remote (cluster) path: everything goes through coding-containers' exec.

The workspace is a tmp dir laid out like ``/workspace`` (primary = the cargo
vulnproj fixture, ``.repos/o__src`` = the uv pyproj fixture) and served by the
real local exec server in ``workspace_server.py``; the service's own SDK client,
find / cat / bulk-reader commands and parsers run unmodified.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from fastapi import HTTPException

from models.container_models import ContainerInfo, ContainerStatus

from .workspace_server import REMOTE_CODEBASE_PATH, WorkspaceServer

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    shutil.copytree(FIXTURES / "cargo" / "vulnproj", root)
    shutil.copytree(FIXTURES / "pyproj", root / ".repos" / "o__src")
    return root


@pytest.fixture
def remote_env(monkeypatch, tmp_path: Path, workspace: Path):
    """Point the service at a running exec server over *workspace*; yields a starter."""
    from config.settings import get_settings

    db = tmp_path / "osv-db"  # an offline DB with both ecosystems and no records
    (db / "crates.io").mkdir(parents=True)
    (db / "PyPI").mkdir()

    def start(**kwargs) -> WorkspaceServer:
        server = WorkspaceServer(workspace, **kwargs)
        monkeypatch.setenv("CONTAINERS_SERVICE_URL", server.url)
        monkeypatch.setenv("WORKSPACE_ROOT", str(workspace))
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(db))
        get_settings.cache_clear()
        return server

    return start


def _dependencies(test_client, tenant_headers, params=None) -> dict:
    resp = test_client.post(
        "/api/security/sbom/ws/dependencies", params=params or {}, headers=tenant_headers
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_dependency_list_reads_every_repo_through_exec(test_client, tenant_headers, remote_env):
    with remote_env() as server:
        body = _dependencies(test_client, tenant_headers)
    assert body["status"] == "success", body
    repos = {r["repo"]: r for r in body["result"]["repos"]}
    assert list(repos) == ["primary", ".repos/o__src"]
    # primary: the Rust target only (.repos/ is not part of it)
    assert [e["ecosystem"] for e in repos["primary"]["ecosystems"]] == ["crates.io"]
    crates = {(r["name"], r["version"]) for r in repos["primary"]["ecosystems"][0]["resolved"]}
    assert ("smallvec", "1.6.0") in crates and ("smallvec", "0.6.14") in crates
    # the checkout under .repos/ is fetched (its root is itself a hidden path)
    pypi = repos[".repos/o__src"]["ecosystems"][0]
    assert {r["name"] for r in pypi["resolved"]} == {"python-dateutil", "tzdata", "iniconfig"}
    assert all(r["advisories_checked"] for r in pypi["resolved"])
    assert any(cmd[0] == "find" for cmd in server.commands)  # it really went remote


def test_unreadable_dir_in_the_workspace_does_not_fail_the_listing(
    test_client, tenant_headers, remote_env, workspace
):
    """find exits 1 on a permission-denied dir; the listing it printed is complete."""
    locked = workspace / "locked"
    locked.mkdir()
    (locked / "inner").mkdir()
    locked.chmod(0)
    try:
        with remote_env():
            body = _dependencies(test_client, tenant_headers)
    finally:
        locked.chmod(0o755)
    assert body["result"]["repo_listing_error"] is None
    assert [r["repo"] for r in body["result"]["repos"]] == ["primary", ".repos/o__src"]


def test_truncated_listing_is_reported_not_read_as_complete(
    test_client, tenant_headers, remote_env, workspace
):
    with remote_env(max_output=8):
        body = _dependencies(test_client, tenant_headers)
    result = body["result"]
    assert body["status"] == "degraded"
    assert "truncated" in (result["repo_listing_error"] or "")
    assert [r["repo"] for r in result["repos"]] == ["primary"]
    assert result["incomplete"] is True  # the clipped manifest fetch, too


def _remote_container() -> ContainerInfo:
    return ContainerInfo(
        container_name="ws",
        api_endpoint="http://ws:8080",
        codebase_path=REMOTE_CODEBASE_PATH,
        repo_url="https://github.com/o/target",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


async def test_materialize_fetches_the_selected_checkout(remote_env):
    from services.scan_runner import _materialize_codebase

    with remote_env():
        info = _remote_container()
        result = await _materialize_codebase(info, "ws", "tenant-1", repo="o__src")
    try:
        assert result.incomplete is False
        files = {p.name for p in Path(result.temp_dir).rglob("*") if p.is_file()}
        assert {"pyproject.toml", "uv.lock"} <= files
        assert "Cargo.lock" not in files  # the primary repo's file is not in the checkout
    finally:
        shutil.rmtree(result.temp_dir, ignore_errors=True)


async def test_materialize_primary_excludes_the_checkouts(remote_env):
    from services.scan_runner import _materialize_codebase

    with remote_env():
        result = await _materialize_codebase(_remote_container(), "ws", "tenant-1")
    try:
        rel = {
            os.path.relpath(p, result.temp_dir)
            for p in Path(result.temp_dir).rglob("*")
            if p.is_file()
        }
        assert "Cargo.lock" in rel
        assert not any(r.startswith(".repos") for r in rel)
    finally:
        shutil.rmtree(result.temp_dir, ignore_errors=True)


async def test_materialize_missing_checkout_is_404(remote_env):
    from services.scan_runner import _materialize_codebase

    with remote_env(), pytest.raises(HTTPException) as exc:
        await _materialize_codebase(_remote_container(), "ws", "tenant-1", repo="missing")
    assert exc.value.status_code == 404


def test_unconfirmable_selected_repo_is_500_not_404(test_client, tenant_headers, remote_env):
    """The listing is truncated, so `.repos/o__src` cannot be confirmed to exist."""
    with remote_env(max_output=8):
        resp = test_client.post(
            "/api/security/sbom/ws/dependencies",
            params={"repo": "o__src"},
            headers=tenant_headers,
        )
    assert resp.status_code == 500, resp.text
    assert "truncated" in resp.text


def test_truncated_manifest_is_skipped_and_the_fetch_incomplete(
    test_client, tenant_headers, remote_env, workspace
):
    """uv.lock (> 2000 bytes) comes back clipped: it is not parsed, the repo degrades."""
    assert (workspace / ".repos" / "o__src" / "uv.lock").stat().st_size > 2000
    with remote_env(max_output=2000):
        body = _dependencies(test_client, tenant_headers, {"repo": "o__src"})
    (repo,) = body["result"]["repos"]
    assert "manifest fetch was incomplete" in repo["errors"]
    assert body["result"]["incomplete"] is True and body["status"] == "degraded"
    pypi = repo["ecosystems"][0]
    assert pypi["lock_files"] == [] and pypi["resolved"] == []
    assert "pyproject.toml" in pypi["manifest_files"]  # the small files still arrive


async def test_materialize_truncated_find_listing_is_incomplete(remote_env, workspace):
    """Only the file listing is clipped; every file it does name is read in full."""
    from services.scan_runner import _materialize_codebase

    with remote_env(max_output=40, clip_only="find"):
        result = await _materialize_codebase(_remote_container(), "ws", "tenant-1")
    try:
        assert result.incomplete is True
    finally:
        shutil.rmtree(result.temp_dir, ignore_errors=True)
