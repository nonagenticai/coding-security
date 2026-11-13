"""Syft SBOM Generation Service.

CLI subprocess wrapper following the SafetyScanner pattern.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections import Counter
from datetime import UTC, datetime
from typing import Literal, get_args

from models.image_scan_models import SBOMPackage, SBOMResult
from services.scanner_errors import is_parseable_json
from utils.subprocess_runner import run_subprocess

# The formats this scanner can PARSE back into packages. The value is passed to
# `syft -o`, whose `<format>=<path>` form writes a file wherever the path says —
# so anything outside this list is refused, never handed to syft. Other syft
# formats (table, syft-json, ...) would also parse to 0 packages: a false
# "empty SBOM".
SBOMFormat = Literal["cyclonedx-json", "spdx-json"]
SUPPORTED_SBOM_FORMATS: frozenset[str] = frozenset(get_args(SBOMFormat))

logger = logging.getLogger(__name__)


#: purl type -> the ecosystem names the rest of the service uses.
_PURL_ECOSYSTEMS = {
    "pypi": "pypi",
    "cargo": "crates.io",
    "npm": "npm",
    "golang": "go",
    "maven": "maven",
    "nuget": "nuget",
    "gem": "rubygems",
    "composer": "packagist",
}


def ecosystem_from_purl(purl: str | None) -> str | None:
    """``pkg:cargo/smallvec@1.6.0`` -> ``crates.io``; None when unknown."""
    if not purl or not purl.startswith("pkg:"):
        return None
    purl_type = purl[4:].split("/", 1)[0].lower()
    return _PURL_ECOSYSTEMS.get(purl_type)


class SyftScanner:
    """SBOM generator using Syft CLI."""

    def __init__(self):
        self.syft_available = self._check_syft_available()
        self.syft_version = self._get_syft_version() if self.syft_available else None

    def _check_syft_available(self) -> bool:
        try:
            result = subprocess.run(
                ["syft", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_syft_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["syft", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:
            logger.debug(f"Failed to get syft version: {e}")
        return None

    async def generate_sbom(
        self,
        image_ref: str,
        container_name: str = "",
        sbom_format: str = "cyclonedx-json",
        timeout: int = 180,
    ) -> SBOMResult:
        """Generate SBOM for a container image.

        Args:
            image_ref: Docker image reference
            container_name: Container name for the result
            sbom_format: Output format (cyclonedx-json or spdx-json)
            timeout: Scan timeout in seconds
        """
        errors: list[str] = []

        if sbom_format not in SUPPORTED_SBOM_FORMATS:
            raise ValueError(
                f"unsupported SBOM format {sbom_format!r}; "
                f"expected one of {sorted(SUPPORTED_SBOM_FORMATS)}"
            )

        if not self.syft_available:
            errors.append("Syft not available")
            return SBOMResult(
                container_name=container_name,
                image_ref=image_ref,
                format=sbom_format,
                generated_at=datetime.now(UTC),
                total_packages=0,
                errors=errors,
            )

        try:
            cmd = ["syft", image_ref, "-o", sbom_format]

            logger.debug(f"Running syft command: {' '.join(cmd)}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout)

            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"Syft stderr: {stderr_text}")

            raw_output = stdout.decode("utf-8")

            # A non-zero exit with nothing parseable means syft never produced an
            # SBOM (bad image ref, registry auth, pull failure). Falling through
            # would return a well-formed SBOMResult with 0 packages and NO errors
            # — an empty-but-valid SBOM, indistinguishable from "this image
            # genuinely contains no packages". Record it so the result is degraded.
            if returncode != 0 and not is_parseable_json(raw_output):
                detail = stderr_text.strip()[:300]
                errors.append(
                    f"Syft exited {returncode} without a parseable SBOM"
                    + (f": {detail}" if detail else "")
                )
                logger.error(f"Syft failed for {image_ref}: exit {returncode} {detail}")
                raw_output = ""

            if sbom_format == "spdx-json":
                packages = self._parse_spdx(raw_output)
            else:
                packages = self._parse_cyclonedx(raw_output)

            # Count by type
            type_counter: Counter[str] = Counter()
            for pkg in packages:
                type_counter[pkg.type] += 1

            return SBOMResult(
                container_name=container_name,
                image_ref=image_ref,
                format=sbom_format,
                generated_at=datetime.now(UTC),
                total_packages=len(packages),
                packages_by_type=dict(type_counter),
                packages=packages,
                raw_sbom=raw_output if raw_output.strip() else None,
                errors=errors,
            )

        except TimeoutError:
            errors.append(f"Syft timed out after {timeout}s")
            logger.error(f"Syft timed out for {image_ref}")
        except Exception as e:
            errors.append(f"Syft error: {str(e)}")
            logger.error(f"Error running syft on {image_ref}: {e}")

        return SBOMResult(
            container_name=container_name,
            image_ref=image_ref,
            format=sbom_format,
            generated_at=datetime.now(UTC),
            total_packages=0,
            errors=errors,
        )

    async def generate_sbom_from_source(
        self,
        source_path: str,
        container_name: str = "",
        sbom_format: str = "cyclonedx-json",
        timeout: int = 180,
    ) -> SBOMResult:
        """Generate SBOM from a source directory."""
        return await self.generate_sbom(
            f"dir:{source_path}",
            container_name=container_name,
            sbom_format=sbom_format,
            timeout=timeout,
        )

    def _parse_cyclonedx(self, output: str) -> list[SBOMPackage]:
        """Parse CycloneDX JSON output."""
        packages: list[SBOMPackage] = []

        if not output.strip():
            return packages

        try:
            data = json.loads(output)
            components = data.get("components", [])

            for comp in components:
                if not isinstance(comp, dict):
                    continue

                try:
                    licenses = []
                    for lic in comp.get("licenses", []):
                        if isinstance(lic, dict):
                            license_obj = lic.get("license", {})
                            if isinstance(license_obj, dict):
                                lid = license_obj.get("id") or license_obj.get("name", "")
                                if lid:
                                    licenses.append(lid)

                    packages.append(
                        SBOMPackage(
                            name=comp.get("name", ""),
                            version=comp.get("version", ""),
                            type=comp.get("type", "library"),
                            purl=comp.get("purl"),
                            licenses=licenses,
                            ecosystem=ecosystem_from_purl(comp.get("purl")),
                        )
                    )
                except Exception as e:
                    logger.debug(f"Failed to parse CycloneDX component: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CycloneDX JSON: {e}")
        except Exception as e:
            logger.error(f"Error processing CycloneDX output: {e}")

        return packages

    def _parse_spdx(self, output: str) -> list[SBOMPackage]:
        """Parse SPDX JSON output."""
        packages: list[SBOMPackage] = []

        if not output.strip():
            return packages

        try:
            data = json.loads(output)
            spdx_packages = data.get("packages", [])

            for pkg in spdx_packages:
                if not isinstance(pkg, dict):
                    continue

                try:
                    # Skip the document package itself
                    if pkg.get("SPDXID") == "SPDXRef-DOCUMENT":
                        continue

                    licenses = []
                    declared = pkg.get("licenseDeclared", "")
                    if declared and declared != "NOASSERTION":
                        licenses.append(declared)

                    # Extract purl from external refs
                    purl = None
                    for ref in pkg.get("externalRefs", []):
                        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                            purl = ref.get("referenceLocator")
                            break

                    packages.append(
                        SBOMPackage(
                            name=pkg.get("name", ""),
                            version=pkg.get("versionInfo", ""),
                            type="library",
                            purl=purl,
                            licenses=licenses,
                        )
                    )
                except Exception as e:
                    logger.debug(f"Failed to parse SPDX package: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SPDX JSON: {e}")
        except Exception as e:
            logger.error(f"Error processing SPDX output: {e}")

        return packages

    def is_syft_available(self) -> bool:
        return self.syft_available

    def get_status(self) -> dict:
        return {
            "available": self.syft_available,
            "version": self.syft_version,
            "description": "SBOM generator using Syft CLI",
        }
