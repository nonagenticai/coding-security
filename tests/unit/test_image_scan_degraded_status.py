"""A container-image scan that did not run must not report status=success.

All three endpoints in ``routers/security/image_sbom`` return a zero-finding /
zero-package payload when the underlying tool errored, timed out or was not
installed. That payload is byte-identical to a genuinely clean image, so the
envelope ``status`` is the ONLY signal a consumer has. It must be DERIVED from
whether anything actually failed — never a constant.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.common import ResponseStatus
from models.container_models import ContainerInfo, ContainerStatus
from models.image_scan_models import SBOMResult
from routers.security.image_sbom import (
    generate_container_sbom,
    scan_container_image,
    scan_sbom_vulnerabilities,
)
from services.scanner_errors import ScannerExecutionError

TENANT = "tenant-abc"


@pytest.fixture(autouse=True)
def _caller_owns_a_local_workspace(tmp_path):
    """The SBOM endpoints serve only the caller's workspace (tenant 404s are
    covered in test_image_sbom_workspace_source.py). A local codebase_path
    means nothing is fetched."""
    info = ContainerInfo(
        container_name="svc",
        api_endpoint="http://x",
        codebase_path=str(tmp_path),
        repo_url="https://example.invalid/r.git",
        branch="main",
        status=ContainerStatus.RUNNING,
    )
    with patch("routers.security.image_sbom._tenant_workspace", AsyncMock(return_value=info)):
        yield


def _scanner(available: bool, **kw) -> MagicMock:
    m = MagicMock()
    m.is_trivy_available.return_value = available
    m.is_grype_available.return_value = available
    m.is_syft_available.return_value = available
    for k, v in kw.items():
        setattr(m, k, v)
    return m


class TestImageScanOnAWorkspace:
    @pytest.mark.asyncio
    async def test_image_scan_is_not_computed_never_success(self):
        """A workspace has no built image: the answer is degraded with a reason,
        never a zero-vulnerability success."""
        resp = await scan_container_image("svc", tag="latest", tenant_id=TENANT)

        assert resp.status == ResponseStatus.DEGRADED
        assert resp.result is not None
        assert resp.result.total_vulnerabilities == 0
        assert any("is a workspace, not an image" in e for e in resp.result.errors)


class TestSbomStatusIsDerived:
    @pytest.mark.asyncio
    async def test_syft_error_is_degraded(self):
        from datetime import UTC, datetime

        failed = SBOMResult(
            container_name="svc",
            image_ref="r/svc:latest",
            format="cyclonedx-json",
            generated_at=datetime.now(UTC),
            total_packages=0,
            errors=["Syft timed out after 180s"],
        )
        syft = _scanner(True, generate_sbom=AsyncMock(return_value=failed))
        with patch("services.syft_scanner.SyftScanner", return_value=syft):
            resp = await generate_container_sbom("svc", tenant_id=TENANT)

        assert resp.status == ResponseStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_sbom_vuln_scan_grype_error_returns_degraded_not_500(self):
        """`vulns` used to be unbound on this path, so the intended degraded
        response raised NameError and surfaced as an opaque 500."""
        from datetime import UTC, datetime

        sbom = SBOMResult(
            container_name="svc",
            image_ref="r/svc:latest",
            format="cyclonedx-json",
            generated_at=datetime.now(UTC),
            total_packages=3,
            raw_sbom='{"components": []}',
        )
        syft = _scanner(True, generate_sbom=AsyncMock(return_value=sbom))
        grype = _scanner(
            True,
            scan_sbom=AsyncMock(side_effect=ScannerExecutionError("grype", -1, "timed out")),
        )
        with (
            patch("services.syft_scanner.SyftScanner", return_value=syft),
            patch("services.grype_scanner.GrypeScanner", return_value=grype),
        ):
            resp = await scan_sbom_vulnerabilities("svc", tenant_id=TENANT)

        assert resp.status == ResponseStatus.DEGRADED
        assert resp.result is not None
        assert resp.result.total_vulnerabilities == 0
        assert any("grype SBOM scan errored" in e for e in resp.result.errors)

    @pytest.mark.asyncio
    async def test_sbom_vuln_scan_syft_unavailable_is_degraded(self):
        with (
            patch("services.syft_scanner.SyftScanner", return_value=_scanner(False)),
            patch("services.grype_scanner.GrypeScanner", return_value=_scanner(False)),
        ):
            resp = await scan_sbom_vulnerabilities("svc", tenant_id=TENANT)

        assert resp.status == ResponseStatus.DEGRADED
