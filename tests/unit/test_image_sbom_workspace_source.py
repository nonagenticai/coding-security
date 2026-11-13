"""Regression: SBOM / image ops on a workspace always degraded on a fake image ref.

Measured live 2026-10-12: /sbom/cv-m2-hello ran ``syft
mirror.example.com/cv-m2-hello:latest`` — a workspace has no image — and
syft also logged ``failed to fetch latest version`` (update check, no egress).
Now a workspace is inventoried from its materialized source (``syft dir:``),
and the image op on a workspace says "not computed" with a reason.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from models.container_models import ContainerInfo, ContainerStatus
from models.image_scan_models import SBOMResult
from routers.security import image_sbom
from services.scan_runner import _MaterializeResult

_CYCLONEDX = (
    '{"bomFormat":"CycloneDX","components":['
    '{"name":"requests","version":"2.31.0","type":"library",'
    '"purl":"pkg:pypi/requests@2.31.0"}]}'
)


class _FakeSyft:
    calls: list[str] = []

    def __init__(self) -> None:
        pass

    def is_syft_available(self) -> bool:
        return True

    async def generate_sbom(self, ref, container_name="", sbom_format="cyclonedx-json", timeout=0):
        _FakeSyft.calls.append(ref)
        if ref.startswith("dir:") and (Path(ref[4:]) / "requirements.txt").exists():
            return SBOMResult(
                container_name=container_name,
                image_ref=ref,
                format=sbom_format,
                generated_at=datetime.now(UTC),
                total_packages=1,
                raw_sbom=_CYCLONEDX,
            )
        if ref.startswith("dir:"):  # syft ran fine but cataloged nothing
            return SBOMResult(
                container_name=container_name,
                image_ref=ref,
                format=sbom_format,
                generated_at=datetime.now(UTC),
                total_packages=0,
            )
        return SBOMResult(
            container_name=container_name,
            image_ref=ref,
            format=sbom_format,
            generated_at=datetime.now(UTC),
            total_packages=0,
            errors=[f"Syft exited 1 without a parseable SBOM: could not resolve '{ref}'"],
        )


@pytest.fixture
def workspace(tmp_path: Path):
    info = ContainerInfo(
        container_name="cv-m2-hello",
        api_endpoint="http://x",
        codebase_path="/workspace",
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    fetched = tmp_path / "fetched"

    async def _materialize(ci, name, tenant_id, repo=None):
        fetched.mkdir()
        (fetched / "requirements.txt").write_text("requests==2.31.0\n")
        ci.codebase_path = str(fetched)
        return _MaterializeResult(temp_dir=str(fetched))

    _FakeSyft.calls = []
    with (
        patch.object(image_sbom, "_tenant_workspace", AsyncMock(return_value=info)),
        patch.object(image_sbom, "_materialize_codebase", _materialize),
        patch("services.syft_scanner.SyftScanner", _FakeSyft),
    ):
        yield fetched


async def test_workspace_sbom_inventories_source_dependencies(workspace):
    resp = await image_sbom.generate_container_sbom("cv-m2-hello", tenant_id="t")

    assert _FakeSyft.calls and _FakeSyft.calls[0].startswith("dir:")
    assert resp.status == "success"
    assert resp.result.total_packages == 1
    assert resp.result.image_ref == "workspace:cv-m2-hello"
    assert not workspace.exists()  # materialized tempdir cleaned up


async def test_image_scan_on_workspace_is_not_computed_with_reason(workspace):
    resp = await image_sbom.scan_container_image("cv-m2-hello", tenant_id="t")

    assert resp.status == "degraded"
    assert resp.result.total_vulnerabilities == 0
    assert any("is a workspace, not an image" in e for e in resp.result.errors)


class _MustNotRun:
    """Any scanner/fetch construction on a refused name is the defect."""

    def __init__(self, *a, **kw) -> None:
        raise AssertionError("a tool ran for a name the caller does not own")


@pytest.mark.parametrize(
    "call",
    [
        lambda: image_sbom.generate_container_sbom("other-tenants-ws", tenant_id="t"),
        lambda: image_sbom.scan_sbom_vulnerabilities("other-tenants-ws", tenant_id="t"),
        lambda: image_sbom.scan_container_image("other-tenants-ws", tenant_id="t"),
        # an arbitrary registry image name is not a workspace either
        lambda: image_sbom.generate_container_sbom("coding-security", tenant_id="t"),
    ],
    ids=["sbom", "sbom-vulns", "image-scan", "sbom-platform-image"],
)
async def test_foreign_or_unknown_name_is_404_and_nothing_runs(call):
    """Another tenant's workspace, or any name that is not the caller's
    workspace, is the registry's 404 — before syft/grype/trivy or a fetch run.
    Previously such a name fell through to ``registry/<name>:<tag>`` and was
    inventoried/scanned for any licensed caller."""
    with (
        patch(
            "routers.security.image_sbom.validate_and_get_container_for_tenant",
            AsyncMock(side_effect=HTTPException(status_code=404, detail="not found")),
        ),
        patch.object(image_sbom, "_materialize_codebase", _MustNotRun),
        patch("services.syft_scanner.SyftScanner", _MustNotRun),
        patch("services.grype_scanner.GrypeScanner", _MustNotRun),
        patch("services.trivy_scanner.TrivyScanner", _MustNotRun),
    ):
        with pytest.raises(HTTPException) as exc:
            await call()
    assert exc.value.status_code == 404


async def test_registry_outage_propagates():
    with patch(
        "routers.security.image_sbom.validate_and_get_container_for_tenant",
        AsyncMock(side_effect=HTTPException(status_code=503, detail="down")),
    ):
        with pytest.raises(HTTPException) as exc:
            await image_sbom.generate_container_sbom("cv-m2-hello", tenant_id="t")
    assert exc.value.status_code == 503


class _FakeGrype:
    fail = False

    def __init__(self) -> None:
        pass

    def is_grype_available(self) -> bool:
        return True

    async def scan_sbom(self, path, timeout=0):
        assert Path(path).read_text() == _CYCLONEDX
        if _FakeGrype.fail:
            from services.scanner_errors import ScannerExecutionError

            raise ScannerExecutionError("grype", 1, "failed to load vulnerability db")
        return []


@pytest.mark.parametrize("db_offline", [False, True])
async def test_workspace_sbom_vulnerabilities_scans_source_sbom(workspace, db_offline):
    _FakeGrype.fail = db_offline
    with patch("services.grype_scanner.GrypeScanner", _FakeGrype):
        resp = await image_sbom.scan_sbom_vulnerabilities("cv-m2-hello", tenant_id="t")

    assert _FakeSyft.calls[0].startswith("dir:")
    assert resp.result.image_ref == "workspace:cv-m2-hello"
    if db_offline:
        # grype could not use its DB: degraded with the reason, never clean
        assert resp.status == "degraded"
        assert any("vulnerability db" in e for e in resp.result.errors)
    else:
        assert resp.status == "success"
        assert resp.result.errors == []


def _materialize_files(tmp_path: Path, files: dict[str, str]):
    fetched = tmp_path / "fetched2"

    async def _materialize(ci, name, tenant_id, repo=None):
        fetched.mkdir()
        for rel, content in files.items():
            (fetched / rel).write_text(content)
        ci.codebase_path = str(fetched)
        return _MaterializeResult(temp_dir=str(fetched))

    return _materialize


async def test_zero_packages_with_manifests_present_is_degraded(workspace, tmp_path):
    """Syft without a uv.lock cataloger returns 0 packages for a uv project."""
    files = {"pyproject.toml": "[project]\nname='x'\n", "uv.lock": "version = 1\n"}
    with patch.object(image_sbom, "_materialize_codebase", _materialize_files(tmp_path, files)):
        resp = await image_sbom.generate_container_sbom("cv-m2-hello", tenant_id="t")

    assert resp.result.total_packages == 0
    assert resp.status == "degraded"
    assert "0 packages although dependency manifests are present" in resp.message
    assert any("uv.lock" in e for e in resp.result.errors)


async def test_zero_packages_without_manifests_stays_success(workspace, tmp_path):
    with patch.object(
        image_sbom, "_materialize_codebase", _materialize_files(tmp_path, {"README.md": "hi"})
    ):
        resp = await image_sbom.generate_container_sbom("cv-m2-hello", tenant_id="t")

    assert resp.result.total_packages == 0
    assert resp.status == "success"


def test_manifest_finder_skips_vendored_dirs(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "requirements-dev.txt").write_text("a\n")
    (tmp_path / "go.mod").write_text("module x\n")
    assert image_sbom._find_dependency_manifests(tmp_path) == ["go.mod", "svc/requirements-dev.txt"]
