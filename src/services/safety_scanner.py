"""Safety Scanner Service for Python Dependency Vulnerability Detection.

This module provides a comprehensive dependency vulnerability scanner that integrates
with the safety CLI tool to detect security vulnerabilities in Python packages.

The SafetyScanner service enables:
- Scanning requirements.txt files for known vulnerabilities
- Checking currently installed packages in the environment
- Individual package vulnerability checks with version specifications
- JSON parsing of safety CLI output
- Graceful error handling when safety is not available
- Async execution using asyncio for non-blocking operations

Key Features:
    - Integration with safety CLI (https://github.com/pyunsafe/safety)
    - Support for multiple scanning modes (requirements, installed, individual package)
    - CVE identifier extraction and severity mapping
    - Comprehensive error handling and graceful degradation
    - Async/await support for long-running operations
    - JSON output parsing with structured results

Example:
    ```python
    from safety_scanner import SafetyScanner

    scanner = SafetyScanner()

    # Scan requirements.txt file
    vulns = await scanner.scan_requirements("requirements.txt")
    for vuln in vulns:
        print(f"CVE: {vuln.cve_id}, Severity: {vuln.severity}")

    # Scan installed packages
    installed_vulns = await scanner.scan_installed_packages()

    # Check specific package
    package_vulns = await scanner.check_package("django", "2.2.0")
    ```
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from services.scanner_errors import ScannerExecutionError, is_parseable_json
from utils.subprocess_runner import run_subprocess

logger = logging.getLogger(__name__)


class SafetyVulnerability(BaseModel):
    """Model representing a vulnerability detected by safety.

    Represents a specific security vulnerability found in a Python package,
    including CVE details, severity information, affected versions, and
    remediation guidance.

    Attributes:
        package_name (str): The name of the vulnerable package.
        installed_version (str): The currently installed version of the package.
        vulnerable_spec (str): The version specification that is vulnerable
            (e.g., "<=2.2.0").
        cve_id (Optional[str]): The CVE identifier if available (e.g., "CVE-2021-12345").
        advisory_id (Optional[str]): The safety database advisory ID.
        severity (str): Severity level ("critical", "high", "medium", "low").
        description (str): Human-readable description of the vulnerability.
        remediation (Optional[str]): Suggested fix or version to update to.
        affected_versions (Optional[List[str]]): List of affected versions.
        safe_version (Optional[str]): A safe version to update to.
        published_date (Optional[str]): Date when the vulnerability was published.
    """

    package_name: str = Field(..., description="Name of vulnerable package")
    installed_version: str = Field(..., description="Currently installed version")
    vulnerable_spec: str = Field(..., description="Version spec that is vulnerable (e.g., <=2.2.0)")
    cve_id: str | None = Field(
        None, description="CVE identifier if available (e.g., CVE-2021-12345)"
    )
    advisory_id: str | None = Field(None, description="Safety database advisory ID")
    severity: str = Field(default="medium", description="Severity: critical/high/medium/low")
    description: str = Field(..., description="Vulnerability description")
    remediation: str | None = Field(None, description="Suggested fix or version")
    affected_versions: list[str] | None = Field(None, description="List of affected versions")
    safe_version: str | None = Field(None, description="Safe version to upgrade to")
    published_date: str | None = Field(None, description="Date vulnerability was published")


class SafetyScanner:
    """Scanner for detecting Python package vulnerabilities using safety CLI.

    Provides comprehensive dependency vulnerability detection by integrating with
    the safety CLI tool. Supports multiple scanning modes and provides structured
    output with severity assessment and remediation guidance.

    The scanner gracefully handles cases where safety is not installed, providing
    helpful error messages while allowing the application to continue functioning.

    Attributes:
        safety_available (bool): Whether the safety CLI tool is available.
        safety_version (Optional[str]): Version of installed safety tool.
    """

    def __init__(self):
        """Initialize the SafetyScanner service.

        Checks if safety is available in the environment and caches the result
        for performance optimization.
        """
        self.safety_available = self._check_safety_available()
        self.safety_version = self._get_safety_version() if self.safety_available else None

    def _check_safety_available(self) -> bool:
        """Check if safety CLI tool is available.

        Returns:
            bool: True if safety is installed and executable, False otherwise.
        """
        try:
            result = subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _get_safety_version(self) -> str | None:
        """Get the version of installed safety tool.

        Returns:
            Optional[str]: Version string if available, None otherwise.
        """
        try:
            result = subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Output is typically "Safety, version X.Y.Z"
                version_line = result.stdout.strip()
                return version_line
        except Exception as e:
            logger.debug(f"Failed to get safety version: {e}")
        return None

    async def scan_requirements(self, requirements_path: str) -> list[SafetyVulnerability]:
        """Scan a requirements.txt file for known vulnerabilities.

        Executes safety check on the specified requirements file and parses
        the JSON output to extract vulnerability information.

        Args:
            requirements_path (str): Path to the requirements.txt file to scan.

        Returns:
            List[SafetyVulnerability]: List of detected vulnerabilities, empty
                list if none found or if safety is not available.

        Raises:
            ValueError: If the requirements file does not exist.
            Exception: For other errors during scanning (logged but not raised).
        """
        if not self.safety_available:
            logger.warning("Safety tool not available. Install it with: pip install safety")
            return []

        req_file = Path(requirements_path)
        if not req_file.exists():
            raise ValueError(f"Requirements file not found: {requirements_path}")

        try:
            return await self._run_safety_check(["--file", str(requirements_path)])
        except ScannerExecutionError:
            # An incomplete scan must not be flattened into "no vulnerabilities".
            raise
        except Exception as e:
            logger.error(f"Error scanning requirements file {requirements_path}: {e}")
            return []

    async def scan_installed_packages(self) -> list[SafetyVulnerability]:
        """Scan currently installed packages for vulnerabilities.

        Executes safety check on the currently installed environment,
        scanning all packages and their versions.

        Returns:
            List[SafetyVulnerability]: List of detected vulnerabilities, empty
                list if none found or if safety is not available.
        """
        if not self.safety_available:
            logger.warning("Safety tool not available. Install it with: pip install safety")
            return []

        try:
            return await self._run_safety_check([])
        except ScannerExecutionError:
            # An incomplete scan must not be flattened into "no vulnerabilities".
            raise
        except Exception as e:
            logger.error(f"Error scanning installed packages: {e}")
            return []

    async def check_package(self, package: str, version: str) -> list[SafetyVulnerability]:
        """Check a specific package and version for vulnerabilities.

        Scans a single package specification to determine if any known
        vulnerabilities exist for that version.

        Args:
            package (str): The package name (e.g., "django").
            version (str): The version to check (e.g., "2.2.0").

        Returns:
            List[SafetyVulnerability]: List of vulnerabilities affecting this
                package version, empty list if none found or if safety is not available.
        """
        if not self.safety_available:
            logger.warning("Safety tool not available. Install it with: pip install safety")
            return []

        try:
            # Create a temporary requirement string
            requirement = f"{package}=={version}"

            # Safety expects input via stdin or file, so we'll create a temporary file
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp_file:
                tmp_file.write(requirement)
                tmp_path = tmp_file.name

            try:
                result = await self._run_safety_check(["--file", tmp_path])
                return result
            finally:
                # Clean up temporary file
                Path(tmp_path).unlink(missing_ok=True)

        except Exception as e:
            logger.error(f"Error checking package {package}=={version}: {e}")
            return []

    async def _run_safety_check(self, args: list[str]) -> list[SafetyVulnerability]:
        """Execute safety check command and parse JSON output.

        Internal method that runs the safety CLI with JSON output and parses
        the results into SafetyVulnerability objects.

        Args:
            args (List[str]): Additional arguments to pass to safety command
                (e.g., ["--file", "requirements.txt"]).

        Returns:
            List[SafetyVulnerability]: Parsed vulnerability list.

        Raises:
            Exception: If safety command execution or JSON parsing fails.
        """
        try:
            # Build the full command with JSON output flag
            cmd = ["safety", "check", "--json"] + args

            logger.debug(f"Running safety command: {' '.join(cmd)}")

            # Run safety check asynchronously
            returncode, stdout, stderr = await run_subprocess(cmd, timeout=30)

            error_output = stderr.decode("utf-8", errors="ignore")
            if stderr:
                logger.debug(f"Safety stderr: {error_output}")

            text = stdout.decode("utf-8")
            # safety exits non-zero when it FINDS vulnerabilities, so a non-zero
            # exit alone is not an error — but non-zero WITH nothing parseable
            # means the check did not run (missing DB, auth failure, bad file).
            # Returning [] there would report an unchecked dependency set as
            # vulnerability-free.
            if returncode != 0 and not is_parseable_json(text):
                raise ScannerExecutionError("safety", returncode or -1, error_output)

            # Parse JSON output
            return self._parse_safety_json(text)

        except ScannerExecutionError:
            raise
        except TimeoutError as e:
            logger.error("Safety check timed out after 30 seconds")
            raise ScannerExecutionError("safety", -1, "timed out") from e
        except Exception as e:
            logger.error(f"Error running safety check: {e}")
            return []

    def _parse_safety_json(self, json_output: str) -> list[SafetyVulnerability]:
        """Parse safety JSON output into SafetyVulnerability objects.

        Handles the JSON format output from safety CLI and extracts
        relevant vulnerability information.

        Args:
            json_output (str): JSON string output from safety check.

        Returns:
            List[SafetyVulnerability]: List of parsed vulnerabilities.
        """
        vulnerabilities: list[SafetyVulnerability] = []

        if not json_output.strip():
            return vulnerabilities

        try:
            # Safety JSON output is typically a list of vulnerability lists or dict
            data = json.loads(json_output)

            # Handle different safety output formats
            if isinstance(data, dict):
                # Format: {"key": [[vuln_data], ...]}
                vuln_lists = data.values()
            elif isinstance(data, list):
                # Format: [[vuln_data], [vuln_data], ...]
                vuln_lists = [data]
            else:
                logger.warning(f"Unexpected safety JSON format: {type(data)}")
                return vulnerabilities

            # Flatten the vulnerability lists
            for vuln_list in vuln_lists:
                if isinstance(vuln_list, list):
                    for vuln_item in vuln_list:
                        parsed = self._parse_vulnerability_item(vuln_item)
                        if parsed:
                            vulnerabilities.append(parsed)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse safety JSON output: {e}")
            logger.debug(f"JSON output: {json_output}")
        except Exception as e:
            logger.error(f"Error processing safety vulnerabilities: {e}")

        return vulnerabilities

    def _parse_vulnerability_item(self, item: Any) -> SafetyVulnerability | None:
        """Parse a single vulnerability item from safety output.

        Extracts relevant fields from safety's vulnerability report and
        maps them to the SafetyVulnerability model.

        Args:
            item (dict): Single vulnerability item from safety output.

        Returns:
            Optional[SafetyVulnerability]: Parsed vulnerability or None if parsing fails.
        """
        try:
            # Safety output format (as of recent versions):
            # [package_name, installed_version, vulnerability_spec, cve_or_id, description]
            # or dict format with keys: package, installed_version, affected_versions, etc.

            if isinstance(item, (list, tuple)) and len(item) >= 4:
                # List format: [package, version, spec, cve/advisory, description]
                package_name = str(item[0])
                installed_version = str(item[1])
                vulnerable_spec = str(item[2])
                cve_id = str(item[3]) if item[3] else None
                description = str(item[4]) if len(item) > 4 else "Known vulnerability"

                # Extract CVE from the advisory/cve field if it's a CVE
                if cve_id and not cve_id.startswith("CVE"):
                    # It might be a safety advisory ID
                    advisory_id = cve_id
                    cve_id = None
                else:
                    advisory_id = None

                return SafetyVulnerability(
                    package_name=package_name,
                    installed_version=installed_version,
                    vulnerable_spec=vulnerable_spec,
                    cve_id=cve_id,
                    advisory_id=advisory_id,
                    severity=self._determine_severity(description),
                    description=description,
                    remediation=self._extract_remediation(description),
                )

            elif isinstance(item, dict):
                # Dict format
                package_name = item.get("package") or item.get("name") or ""
                installed_version = item.get("installed_version") or ""
                vulnerable_spec = item.get("affected_versions") or item.get("vulnerable_spec") or ""

                if not package_name or not installed_version:
                    return None

                cve_id = item.get("cve") or item.get("cve_id")
                advisory_id = item.get("advisory") or item.get("advisory_id")
                description = item.get("description") or item.get("vulnerability") or ""
                remediation = item.get("fixed_in") or item.get("remediation")

                return SafetyVulnerability(
                    package_name=package_name,
                    installed_version=installed_version,
                    vulnerable_spec=vulnerable_spec,
                    cve_id=cve_id,
                    advisory_id=advisory_id,
                    severity=self._determine_severity(description),
                    description=description,
                    remediation=remediation,
                    affected_versions=item.get("affected_versions"),
                    safe_version=item.get("fixed_in"),
                )

            return None

        except Exception as e:
            logger.debug(f"Failed to parse vulnerability item {item}: {e}")
            return None

    def _determine_severity(self, description: str) -> str:
        """Determine severity level from description.

        Uses keyword matching in the vulnerability description to estimate
        the severity level when explicit severity data is not available.

        Args:
            description (str): Vulnerability description text.

        Returns:
            str: Severity level (critical, high, medium, or low).
        """
        description_lower = description.lower()

        critical_keywords = [
            "remote code execution",
            "critical",
            "rce",
            "arbitrary code execution",
            "privilege escalation",
        ]
        high_keywords = [
            "sql injection",
            "xss",
            "cross-site",
            "authentication",
            "high",
        ]
        medium_keywords = [
            "information disclosure",
            "medium",
            "denial of service",
            "dos",
        ]

        for keyword in critical_keywords:
            if keyword in description_lower:
                return "critical"

        for keyword in high_keywords:
            if keyword in description_lower:
                return "high"

        for keyword in medium_keywords:
            if keyword in description_lower:
                return "medium"

        return "low"

    def _extract_remediation(self, description: str) -> str | None:
        """Extract remediation advice from description.

        Attempts to extract version update recommendations from the
        vulnerability description text.

        Args:
            description (str): Vulnerability description text.

        Returns:
            Optional[str]: Remediation advice if found, None otherwise.
        """
        # Look for common patterns like "upgrade to X.Y.Z" or "use version >= X.Y.Z"
        patterns = [
            r"upgrade to [\d.]+",
            r"update to [\d.]+",
            r"use [\d.]+",
            r">= [\d.]+",
        ]

        for pattern in patterns:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                return match.group(0)

        return None

    def is_safety_available(self) -> bool:
        """Check if safety tool is available.

        Returns:
            bool: True if safety is installed and usable, False otherwise.
        """
        return self.safety_available

    def get_status(self) -> dict:
        """Get scanner status and capabilities.

        Returns:
            dict: Status information including availability and version.
        """
        return {
            "available": self.safety_available,
            "version": self.safety_version,
            "description": "Python package vulnerability scanner using safety CLI",
        }
