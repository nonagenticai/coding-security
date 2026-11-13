"""Grype Container Image Scanner Service.

CLI subprocess wrapper following the SafetyScanner pattern.
Serves as fallback when Trivy is not available.
"""

from __future__ import annotations

import json
import logging
import subprocess

from models.image_scan_models import ImageVulnerability
from services.scanner_errors import ScannerExecutionError, is_parseable_json
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)


class GrypeScanner:
    """Scanner for container image vulnerabilities using Grype CLI."""

    def __init__(self):
        self.grype_available = self._check_grype_available()
        self.grype_version = self._get_grype_version() if self.grype_available else None

    def _check_grype_available(self) -> bool:
        try:
            result = subprocess.run(
                ["grype", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_grype_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["grype", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:
            logger.debug(f"Failed to get grype version: {e}")
        return None

    async def scan_image(self, image_ref: str, timeout: int = 300) -> list[ImageVulnerability]:
        """Scan a container image for vulnerabilities.

        Args:
            image_ref: Docker image reference (e.g. registry/image:tag)
            timeout: Scan timeout in seconds
        """
        if not self.grype_available:
            logger.warning("Grype not available")
            return []

        try:
            cmd = ["grype", image_ref, "-o", "json"]

            logger.debug(f"Running grype command: {' '.join(cmd)}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout)

            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"Grype stderr: {stderr_text}")

            text = stdout.decode("utf-8")
            # A non-zero exit with no parseable JSON means grype errored (we do
            # not pass --fail-on, so a clean run exits 0 with JSON). Surface it
            # so the image-CVE scan is marked degraded rather than read as clean.
            if returncode != 0 and not is_parseable_json(text):
                raise ScannerExecutionError("grype", returncode or -1, stderr_text)

            return self._parse_grype_json(text)

        except TimeoutError as e:
            logger.error(f"Grype scan timed out after {timeout}s for {image_ref}")
            raise ScannerExecutionError("grype", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running grype scan on {image_ref}: {e}")
            return []

    async def scan_sbom(self, sbom_path: str, timeout: int = 300) -> list[ImageVulnerability]:
        """Scan an SBOM file for vulnerabilities.

        Args:
            sbom_path: Path to SBOM file
            timeout: Scan timeout in seconds
        """
        if not self.grype_available:
            logger.warning("Grype not available")
            return []

        try:
            cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]

            logger.debug(f"Running grype SBOM scan: {' '.join(cmd)}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout)

            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"Grype stderr: {stderr_text}")

            text = stdout.decode("utf-8")
            if returncode != 0 and not is_parseable_json(text):
                raise ScannerExecutionError("grype", returncode or -1, stderr_text)

            return self._parse_grype_json(text)

        except TimeoutError as e:
            logger.error(f"Grype SBOM scan timed out after {timeout}s")
            raise ScannerExecutionError("grype", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running grype SBOM scan: {e}")
            return []

    def _parse_grype_json(self, output: str) -> list[ImageVulnerability]:
        """Parse Grype JSON output.

        Grype format: {"matches": [{"vulnerability": {...}, "artifact": {...}}]}
        """
        vulnerabilities: list[ImageVulnerability] = []

        if not output.strip():
            return vulnerabilities

        try:
            data = json.loads(output)

            if not isinstance(data, dict):
                logger.warning(f"Unexpected grype JSON format: {type(data)}")
                return vulnerabilities

            matches = data.get("matches", [])

            for match in matches:
                if not isinstance(match, dict):
                    continue

                vuln_data = match.get("vulnerability", {})
                artifact = match.get("artifact", {})

                try:
                    vulnerabilities.append(
                        ImageVulnerability(
                            vulnerability_id=vuln_data.get("id", "UNKNOWN"),
                            package_name=artifact.get("name", ""),
                            installed_version=artifact.get("version", ""),
                            fixed_version=(
                                vuln_data.get("fix", {}).get("versions", [None])[0]
                                if vuln_data.get("fix", {}).get("versions")
                                else None
                            ),
                            severity=vuln_data.get("severity", "UNKNOWN"),
                            title=vuln_data.get("id", ""),
                            description=vuln_data.get("description", ""),
                            target=artifact.get("type", ""),
                        )
                    )
                except Exception as e:
                    logger.debug(f"Failed to parse grype vulnerability: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse grype JSON output: {e}")
        except Exception as e:
            logger.error(f"Error processing grype vulnerabilities: {e}")

        return vulnerabilities

    def is_grype_available(self) -> bool:
        return self.grype_available

    def get_status(self) -> dict:
        return {
            "available": self.grype_available,
            "version": self.grype_version,
            "description": "Container image vulnerability scanner using Grype CLI (fallback)",
        }
