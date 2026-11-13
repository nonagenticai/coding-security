"""Two honesty/safety regressions.

1. ``sbom_format`` reached ``syft -o`` unchecked. syft's ``-o <format>=<path>``
   writes the SBOM to ``<path>``, so ``?sbom_format=cyclonedx-json=/tmp/x``
   wrote a file of the caller's choosing on the pod. Only the two formats the
   scanner can parse back are accepted; anything else is a 422 and never runs.
2. A SAST engine that is not installed was skipped silently
   (``if not engine.is_available(): continue``) — a scan missing semgrep
   graded exactly like a complete one. It is now degraded, with the reason.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import SecurityLevel, SecurityValidationRequest
from services.scan_runner import _MaterializeResult
from services.security_detector import SecurityVulnerabilityDetector
from services.security_service import SystemSecurityService
from services.syft_scanner import SyftScanner


@pytest.fixture
def _caller_owns_the_workspace():
    from models.container_models import ContainerInfo

    info = ContainerInfo.model_construct(name="test-container", tenant_id="test-tenant")
    with (
        patch("routers.security.image_sbom._tenant_workspace", AsyncMock(return_value=info)),
        patch(
            "routers.security.image_sbom._materialize_codebase",
            AsyncMock(return_value=_MaterializeResult(temp_dir=None)),
        ),
    ):
        yield


@pytest.mark.parametrize(
    "fmt", ["cyclonedx-json=/tmp/pwned", "table", "syft-json", "spdx-json=/etc/x", "../x"]
)
def test_sbom_endpoint_rejects_unlisted_format(
    fmt, test_client, tenant_headers, _caller_owns_the_workspace
):
    with patch("services.syft_scanner.SyftScanner") as syft_cls:
        syft_cls.return_value.generate_sbom = AsyncMock()
        response = test_client.post(
            "/api/security/sbom/test-container",
            params={"sbom_format": fmt},
            headers=tenant_headers,
        )
    assert response.status_code == 422
    syft_cls.return_value.generate_sbom.assert_not_called()


async def test_syft_scanner_refuses_unlisted_format_before_running_syft():
    scanner = SyftScanner.__new__(SyftScanner)
    scanner.syft_available = True
    scanner.syft_version = "syft 1.0"
    with patch("services.syft_scanner.run_subprocess", AsyncMock()) as run:
        with pytest.raises(ValueError, match="unsupported SBOM format"):
            await scanner.generate_sbom("dir:/w", sbom_format="cyclonedx-json=/tmp/pwned")
    run.assert_not_called()


@pytest.mark.parametrize("fmt", ["cyclonedx-json", "spdx-json"])
async def test_syft_scanner_accepts_listed_formats(fmt):
    """Control: the parseable formats still reach syft."""
    scanner = SyftScanner.__new__(SyftScanner)
    scanner.syft_available = True
    scanner.syft_version = "syft 1.0"
    with patch(
        "services.syft_scanner.run_subprocess", AsyncMock(return_value=(0, b"{}", b""))
    ) as run:
        await scanner.generate_sbom("dir:/w", sbom_format=fmt)
    assert run.call_args.args[0] == ["syft", "dir:/w", "-o", fmt]


class _Engine:
    def __init__(self, available: bool) -> None:
        self._available = available

    def is_available(self) -> bool:
        return self._available

    async def scan(self, targets, **_kwargs):
        return []


def _detector(semgrep_installed: bool) -> SecurityVulnerabilityDetector:
    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_iac", "_image"):
        setattr(d, name, _Engine(True))
    d._semgrep = _Engine(semgrep_installed)
    return d


async def test_missing_engine_degrades_the_scan(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n")

    missing = await _detector(semgrep_installed=False).analyze_security_vulnerabilities([str(f)])
    assert missing.scan_degraded is True
    assert any("semgrep" in r for r in missing.degraded_reasons)

    present = await _detector(semgrep_installed=True).analyze_security_vulnerabilities([str(f)])
    assert present.scan_degraded is False
    assert present.degraded_reasons == []


class _ExplodingEngine(_Engine):
    """An engine /validate must never reach: scanning records and raises."""

    def __init__(self) -> None:
        super().__init__(True)
        self.scanned = 0

    async def scan(self, targets, **_kwargs):
        self.scanned += 1
        raise AssertionError("/validate ran an external engine")


@pytest.mark.parametrize("level", list(SecurityLevel))
async def test_missing_engine_degrades_scan_not_validate(level, tmp_path):
    """Design: a missing engine degrades /scan (above); /validate is the
    in-process inline gate and never uses an engine, so a missing one neither
    degrades it nor is consulted. And /validate never spawns a process."""
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    scan = await _detector(semgrep_installed=False).analyze_security_vulnerabilities([str(f)])
    assert scan.scan_degraded is True
    assert any("semgrep" in r for r in scan.degraded_reasons)

    det = _detector(semgrep_installed=False)
    engines = {
        name: _ExplodingEngine() for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image")
    }
    for name, engine in engines.items():
        setattr(det, name, engine)

    def _no_process(*a, **k):
        raise AssertionError("/validate spawned a subprocess")

    with (
        patch("subprocess.Popen.__init__", _no_process),
        patch("asyncio.create_subprocess_exec", _no_process),
        patch("asyncio.create_subprocess_shell", _no_process),
        patch("os.posix_spawn", _no_process),
        patch("os.system", _no_process),
    ):
        svc = SystemSecurityService(SystemSecurityConfig(), None, detector=det)
        clean = await svc.validate_code_security(
            SecurityValidationRequest(code="x = 1\n", language="python", security_level=level)
        )
        dangerous = await svc.validate_code_security(
            SecurityValidationRequest(
                code="import os\nos.system(cmd)\n", language="python", security_level=level
            )
        )
    assert all(e.scanned == 0 for e in engines.values())
    assert clean.analysis_degraded is False
    assert clean.degraded_reasons == []
    assert clean.is_safe is True
    assert dangerous.is_safe is False
