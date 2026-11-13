"""Trivy Container Image Scanner Service.

CLI subprocess wrapper following the SafetyScanner pattern.
"""

from __future__ import annotations

import json
import logging
import subprocess

from models.image_scan_models import ImageVulnerability
from services.scanner_errors import ScannerExecutionError, is_parseable_json
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)


class TrivyScanner:
    """Scanner for container image vulnerabilities using Trivy CLI."""

    def __init__(self):
        self.trivy_available = self._check_trivy_available()
        self.trivy_version = self._get_trivy_version() if self.trivy_available else None

    def _check_trivy_available(self) -> bool:
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_trivy_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:
            logger.debug(f"Failed to get trivy version: {e}")
        return None

    async def scan_image(self, image_ref: str, timeout: int = 300) -> list[ImageVulnerability]:
        """Scan a container image for vulnerabilities.

        Args:
            image_ref: Docker image reference (e.g. registry/image:tag)
            timeout: Scan timeout in seconds

        Raises:
            ScannerExecutionError: trivy ran but exited abnormally, or timed out.
                An incomplete scan MUST NOT be reported as an empty (clean)
                finding list — the caller marks the result degraded instead.
        """
        if not self.trivy_available:
            logger.warning("Trivy not available")
            return []

        try:
            cmd = [
                "trivy",
                "image",
                "--format",
                "json",
                "--severity",
                "CRITICAL,HIGH,MEDIUM,LOW",
                "--timeout",
                f"{timeout}s",
                image_ref,
            ]

            logger.debug(f"Running trivy command: {' '.join(cmd)}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=timeout + 30)

            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"Trivy stderr: {stderr_text}")

            text = stdout.decode("utf-8")
            # Mirrors GrypeScanner. We do not pass --exit-code, so a clean trivy
            # run exits 0 with JSON on stdout; a non-zero exit with nothing
            # parseable means the scan did not happen (bad image ref, registry
            # auth failure, DB download failure, OOM). Returning [] there is
            # indistinguishable from "image is clean", so raise and let the
            # router mark the result degraded.
            if returncode != 0 and not is_parseable_json(text):
                raise ScannerExecutionError("trivy", returncode or -1, stderr_text)

            return self._parse_trivy_json(text)

        except TimeoutError as e:
            logger.error(f"Trivy scan timed out after {timeout}s for {image_ref}")
            raise ScannerExecutionError("trivy", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running trivy scan on {image_ref}: {e}")
            return []

    def _parse_trivy_json(self, output: str) -> list[ImageVulnerability]:
        """Parse Trivy JSON output.

        Trivy format: {"Results": [{"Target": "...", "Vulnerabilities": [{...}]}]}
        """
        vulnerabilities: list[ImageVulnerability] = []

        if not output.strip():
            return vulnerabilities

        try:
            data = json.loads(output)

            if not isinstance(data, dict):
                logger.warning(f"Unexpected trivy JSON format: {type(data)}")
                return vulnerabilities

            results = data.get("Results", [])

            for result in results:
                if not isinstance(result, dict):
                    continue

                target = result.get("Target", "")
                vulns = result.get("Vulnerabilities") or []

                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue

                    try:
                        vulnerabilities.append(
                            ImageVulnerability(
                                vulnerability_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                                package_name=vuln.get("PkgName", ""),
                                installed_version=vuln.get("InstalledVersion", ""),
                                fixed_version=vuln.get("FixedVersion"),
                                severity=vuln.get("Severity", "UNKNOWN"),
                                title=vuln.get("Title", ""),
                                description=vuln.get("Description", ""),
                                target=target,
                            )
                        )
                    except Exception as e:
                        logger.debug(f"Failed to parse trivy vulnerability: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse trivy JSON output: {e}")
        except Exception as e:
            logger.error(f"Error processing trivy vulnerabilities: {e}")

        return vulnerabilities

    def is_trivy_available(self) -> bool:
        return self.trivy_available

    def get_status(self) -> dict:
        return {
            "available": self.trivy_available,
            "version": self.trivy_version,
            "description": "Container image vulnerability scanner using Trivy CLI",
        }
