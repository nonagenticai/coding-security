"""Security router package.

Composes the previously 1637-line ``routers/security.py`` god-router from
focused per-resource submodules. The exported ``router`` is unchanged from
the caller's perspective — ``app.include_router(security_router, prefix=...)``
still wires up the same set of URL paths.

Layout:

  security/
    __init__.py       — composes ``router`` + re-exports patch targets
    _common.py        — shared models + path/severity/conversion helpers
    validation.py     — /validate, /sandbox-config/{language}/{security_level}
    vulnerabilities.py — /analyze-vulnerabilities, /patterns (legacy detector)
    container_scan.py — /scan/{container_name}, /scan/.../quick, /report/...
    image_sbom.py     — /scan/.../image, /sbom/..., /sbom/.../vulnerabilities
    dependency_inventory.py — /sbom/.../dependencies (per-repo direct + resolved)

stdlib singletons (``os``) and frequently-patched module-level names are
re-exported here so tests that patch ``routers.security.X`` keep working
where the patched name's binding lives at attribute scope (``os.path.isdir``
patches affect ``os.path`` globally via the shared ``os`` module).

Function-binding patches (``get_security_scan_service``,
``validate_and_get_container_for_tenant``, ``get_security_detector``,
``get_container_registry``, ``ImageScanResponse``, ``SBOMResponse``) must be
rebound to the submodule where the call actually resolves — see the
companion test file. The same pattern as coding-analysis PR #19 (R-6).
"""

from __future__ import annotations

import os  # re-exported for ``patch("routers.security.os.path.isdir", ...)``

from fastapi import APIRouter

# Re-exports for ``patch("routers.security.X", ...)`` patch targets that bind
# at module scope (classes / module-level callables). Function-binding
# patches on these names additionally need to be rebound to the submodule
# where the call resolves.
from models.security_api_models import (
    ImageScanResponse,
    SBOMResponse,
)
from services.container_registry import get_container_registry
from services.security_detector import get_security_detector
from services.security_scan_service import get_security_scan_service
from services.security_service import SystemSecurityService
from utils.container_validation import validate_and_get_container_for_tenant

from . import container_scan, dependency_inventory, image_sbom, validation, vulnerabilities
from ._common import (
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
    SecurityAnalysisResponseModel,
    VulnerabilityMatchModel,
)

# Compose the parent router with NO prefix (the caller — ``app_factory`` —
# applies ``prefix="/api/security"``). Tags are also applied at include time.
router = APIRouter()
router.include_router(validation.router)
router.include_router(vulnerabilities.router)
router.include_router(container_scan.router)
router.include_router(image_sbom.router)
router.include_router(dependency_inventory.router)


__all__ = [
    "ImageScanResponse",
    "SBOMResponse",
    "SecurityAnalysisRequest",
    "SecurityAnalysisResponse",
    "SecurityAnalysisResponseModel",
    "SystemSecurityService",
    "VulnerabilityMatchModel",
    "container_scan",
    "dependency_inventory",
    "get_container_registry",
    "get_security_detector",
    "get_security_scan_service",
    "image_sbom",
    "os",
    "router",
    "validate_and_get_container_for_tenant",
    "validation",
    "vulnerabilities",
]
