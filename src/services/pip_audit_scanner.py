"""pip-audit Scanner Service for Python Dependency Vulnerability Detection.

CLI subprocess wrapper following the SafetyScanner pattern.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from services.scanner_errors import ScannerExecutionError, is_parseable_json
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)


class PipAuditVulnerability(BaseModel):
    """Vulnerability detected by pip-audit."""

    package_name: str = Field(..., description="Name of vulnerable package")
    installed_version: str = Field(..., description="Currently installed version")
    vulnerability_id: str = Field(..., description="PYSEC or CVE identifier")
    fix_versions: list[str] = Field(default_factory=list, description="Versions that fix the issue")
    description: str = Field("", description="Vulnerability description")
    aliases: list[str] = Field(default_factory=list, description="CVE/GHSA cross-references")
    severity: str | None = Field(None, description="Severity if available")


class PipAuditScanner:
    """Scanner for Python package vulnerabilities using pip-audit CLI."""

    def __init__(self):
        self.pip_audit_available = self._check_pip_audit_available()
        self.pip_audit_version = self._get_pip_audit_version() if self.pip_audit_available else None

    def _check_pip_audit_available(self) -> bool:
        try:
            result = subprocess.run(
                ["pip-audit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_pip_audit_version(self) -> str | None:
        try:
            result = subprocess.run(
                ["pip-audit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"Failed to get pip-audit version: {e}")
        return None

    async def scan_requirements(self, requirements_path: str) -> list[PipAuditVulnerability]:
        """Scan a requirements.txt file for known vulnerabilities."""
        if not self.pip_audit_available:
            logger.warning("pip-audit not available")
            return []

        req_file = Path(requirements_path)
        if not req_file.exists():
            raise ValueError(f"Requirements file not found: {requirements_path}")

        try:
            return await self._run_pip_audit(
                ["--requirement", str(requirements_path), "--format", "json", "--output", "-"]
            )
        except ScannerExecutionError:
            # The tool ran but errored — let it propagate so the unified scan
            # marks the report degraded instead of recording a clean result.
            raise
        except Exception as e:
            logger.error(f"Error scanning requirements file {requirements_path}: {e}")
            return []

    async def scan_installed_packages(self) -> list[PipAuditVulnerability]:
        """Scan currently installed packages for vulnerabilities."""
        if not self.pip_audit_available:
            logger.warning("pip-audit not available")
            return []

        try:
            return await self._run_pip_audit(["--format", "json", "--output", "-"])
        except Exception as e:
            logger.error(f"Error scanning installed packages: {e}")
            return []

    async def check_package(self, package: str, version: str) -> list[PipAuditVulnerability]:
        """Check a specific package and version for vulnerabilities."""
        if not self.pip_audit_available:
            logger.warning("pip-audit not available")
            return []

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_file:
                tmp_file.write(f"{package}=={version}\n")
                tmp_path = tmp_file.name

            try:
                return await self._run_pip_audit(
                    ["--requirement", tmp_path, "--format", "json", "--output", "-"]
                )
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        except Exception as e:
            logger.error(f"Error checking package {package}=={version}: {e}")
            return []

    async def _run_pip_audit(self, args: list[str]) -> list[PipAuditVulnerability]:
        """Execute pip-audit and parse JSON output."""
        try:
            cmd = ["pip-audit"] + args
            logger.debug(f"Running pip-audit command: {' '.join(cmd)}")

            returncode, stdout, stderr = await run_subprocess(cmd, timeout=60)

            stderr_text = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"pip-audit stderr: {stderr_text}")

            text = stdout.decode("utf-8")
            # pip-audit exits non-zero when it FINDS vulnerabilities (valid JSON
            # on stdout). A non-zero exit with no parseable JSON means it errored
            # (network, resolver failure) — surface it so the Python-dependency
            # scan is marked degraded rather than read as clean.
            if returncode != 0 and not is_parseable_json(text):
                raise ScannerExecutionError("pip-audit", returncode or -1, stderr_text)

            return self._parse_pip_audit_json(text)

        except TimeoutError as e:
            logger.error("pip-audit timed out after 60 seconds")
            raise ScannerExecutionError("pip-audit", -1, "timed out") from e
        except ScannerExecutionError:
            raise
        except Exception as e:
            logger.error(f"Error running pip-audit: {e}")
            return []

    def _parse_pip_audit_json(self, output: str) -> list[PipAuditVulnerability]:
        """Parse pip-audit JSON output.

        pip-audit JSON format:
        {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [
            {"id": "PYSEC-...", "fix_versions": ["1.1"], "aliases": ["CVE-..."], "description": "..."}
        ]}]}
        """
        vulnerabilities: list[PipAuditVulnerability] = []

        if not output.strip():
            return vulnerabilities

        try:
            data = json.loads(output)

            if not isinstance(data, dict):
                logger.warning(f"Unexpected pip-audit JSON format: {type(data)}")
                return vulnerabilities

            dependencies = data.get("dependencies", [])

            for dep in dependencies:
                if not isinstance(dep, dict):
                    continue

                pkg_name = dep.get("name", "")
                pkg_version = dep.get("version", "")
                vulns = dep.get("vulns", [])

                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue

                    try:
                        vulnerabilities.append(
                            PipAuditVulnerability(
                                package_name=pkg_name,
                                installed_version=pkg_version,
                                vulnerability_id=vuln.get("id", "UNKNOWN"),
                                fix_versions=vuln.get("fix_versions", []),
                                description=vuln.get("description", ""),
                                aliases=vuln.get("aliases", []),
                                severity=None,
                            )
                        )
                    except Exception as e:
                        logger.debug(f"Failed to parse pip-audit vulnerability: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse pip-audit JSON output: {e}")
        except Exception as e:
            logger.error(f"Error processing pip-audit vulnerabilities: {e}")

        return vulnerabilities

    def is_pip_audit_available(self) -> bool:
        return self.pip_audit_available

    def get_status(self) -> dict:
        return {
            "available": self.pip_audit_available,
            "version": self.pip_audit_version,
            "description": "Python package vulnerability scanner using pip-audit CLI",
        }
