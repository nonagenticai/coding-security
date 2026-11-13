"""OSV.dev API integration service for vulnerability scanning.

This module provides integration with OSV.dev API for querying vulnerabilities
in package dependencies. It supports multiple ecosystems including npm, PyPI,
crates.io, Go, and Maven.

Features:
    - Lockfile parsing (package-lock.json, requirements.txt, Cargo.lock, go.mod)
    - Single package vulnerability checking
    - Batch vulnerability queries
    - Rate limiting with exponential backoff retry logic
    - Result caching to avoid duplicate queries
    - Support for multiple package ecosystems

Classes:
    OSVScanner: Main service for vulnerability scanning via OSV.dev

Example:
    >>> scanner = OSVScanner()
    >>> vulnerabilities = await scanner.scan_lockfile("package-lock.json")
    >>> print(f"Found {len(vulnerabilities)} vulnerabilities")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from models.security_models import OSVVulnerability, PackageInfo

logger = logging.getLogger(__name__)

# OSV.dev API endpoint
OSV_API_ENDPOINT = "https://api.osv.dev/v1/query"

# Ecosystem mapping from file types to OSV ecosystem names
ECOSYSTEM_MAPPING = {
    "package-lock.json": "npm",
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "poetry.lock": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "Cargo.lock": "crates.io",
    "Cargo.toml": "crates.io",
    "go.mod": "Go",
    "go.sum": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
}

# Rate limiting configuration
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1
MAX_BACKOFF_SECONDS = 10
REQUESTS_PER_SECOND = 10
CACHE_DURATION_HOURS = 24


class OSVScanner:
    """Service for scanning vulnerabilities using OSV.dev API.

    Provides methods for detecting and querying vulnerabilities in package
    dependencies across multiple programming language ecosystems.
    """

    def __init__(self) -> None:
        """Initialize the OSV Scanner."""
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[list[OSVVulnerability], datetime]] = {}
        self._rate_limit_semaphore = asyncio.Semaphore(REQUESTS_PER_SECOND)

    async def __aenter__(self) -> OSVScanner:
        """Async context manager entry."""
        self._client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    async def scan_lockfile(self, lockfile_path: str) -> list[OSVVulnerability]:
        """Scan a lockfile for vulnerabilities.

        Detects lockfile type, parses dependencies, and queries OSV.dev API
        for vulnerabilities.

        Args:
            lockfile_path: Path to the lockfile to scan.

        Returns:
            List of found vulnerabilities.

        Raises:
            FileNotFoundError: If lockfile doesn't exist.
            ValueError: If lockfile type is not supported.
        """
        path = Path(lockfile_path)

        if not path.exists():
            raise FileNotFoundError(f"Lockfile not found: {lockfile_path}")

        logger.info(f"Scanning lockfile: {lockfile_path}")

        # Detect ecosystem from filename
        filename = path.name
        ecosystem = self._detect_ecosystem(filename)

        if not ecosystem:
            raise ValueError(
                f"Unsupported lockfile type: {filename}. "
                f"Supported: {', '.join(ECOSYSTEM_MAPPING.keys())}"
            )

        logger.debug(f"Detected ecosystem: {ecosystem} for {filename}")

        # Parse dependencies from lockfile
        packages = await self._parse_lockfile(path, ecosystem)
        logger.info(f"Found {len(packages)} packages in {filename}")

        # Query vulnerabilities for all packages
        vulnerabilities = await self.batch_query(packages)

        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {len(packages)} packages")

        return vulnerabilities

    async def check_package(
        self, ecosystem: str, package: str, version: str
    ) -> list[OSVVulnerability]:
        """Check a single package for vulnerabilities.

        Args:
            ecosystem: Package ecosystem (npm, PyPI, crates.io, Go, Maven).
            package: Package name.
            version: Package version.

        Returns:
            List of vulnerabilities for the package.
        """
        logger.debug(f"Checking {ecosystem}/{package}@{version}")

        # Check cache first
        cache_key = f"{ecosystem}:{package}:{version}"
        if self._is_cached(cache_key):
            logger.debug(f"Cache hit for {cache_key}")
            return self._get_from_cache(cache_key)

        # Query OSV API
        vulnerabilities = await self._query_osv_api(ecosystem, package, version)

        # Cache result
        self._cache[cache_key] = (vulnerabilities, datetime.now(UTC))

        return vulnerabilities

    async def batch_query(self, packages: list[PackageInfo]) -> list[OSVVulnerability]:
        """Batch query multiple packages for vulnerabilities.

        Handles rate limiting to avoid overwhelming the OSV.dev API.

        Args:
            packages: List of packages to query.

        Returns:
            Combined list of vulnerabilities from all packages.
        """
        logger.info(f"Batch querying {len(packages)} packages")

        all_vulnerabilities: list[OSVVulnerability] = []
        seen_vuln_ids: set[str] = set()  # Dedup by vulnerability ID

        # Create tasks with rate limiting
        tasks = [self._rate_limited_check(pkg.ecosystem, pkg.name, pkg.version) for pkg in packages]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                logger.warning(f"Error during batch query: {result}")
                continue

            for vuln in result:
                if vuln.id not in seen_vuln_ids:
                    all_vulnerabilities.append(vuln)
                    seen_vuln_ids.add(vuln.id)

        logger.info(
            f"Batch query complete. Found {len(all_vulnerabilities)} unique vulnerabilities"
        )

        return all_vulnerabilities

    async def _rate_limited_check(
        self, ecosystem: str, package: str, version: str
    ) -> list[OSVVulnerability]:
        """Check package with rate limiting.

        Args:
            ecosystem: Package ecosystem.
            package: Package name.
            version: Package version.

        Returns:
            List of vulnerabilities.
        """
        async with self._rate_limit_semaphore:
            await asyncio.sleep(1 / REQUESTS_PER_SECOND)
            return await self.check_package(ecosystem, package, version)

    async def _query_osv_api(
        self, ecosystem: str, package: str, version: str
    ) -> list[OSVVulnerability]:
        """Query OSV.dev API for vulnerabilities.

        Implements exponential backoff retry logic for rate limiting.

        Args:
            ecosystem: Package ecosystem.
            package: Package name.
            version: Package version.

        Returns:
            List of vulnerabilities from OSV.dev.
        """
        payload = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }

        for attempt in range(MAX_RETRIES):
            try:
                if not self._client:
                    self._client = httpx.AsyncClient()

                response = await self._client.post(
                    OSV_API_ENDPOINT,
                    json=payload,
                    timeout=httpx.Timeout(30),
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_osv_response(data, ecosystem, package)

                elif response.status_code == 429:
                    # Rate limited, apply exponential backoff
                    wait_time = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                    logger.warning(
                        f"Rate limited. Waiting {wait_time}s before retry "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                elif response.status_code == 404:
                    logger.debug(f"Package not found in OSV.dev: {ecosystem}/{package}")
                    return []

                else:
                    logger.error(f"OSV API error: {response.status_code} - {response.text}")
                    return []

            except TimeoutError:
                logger.warning(
                    f"Timeout querying OSV API for {ecosystem}/{package} "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})"
                )
                if attempt < MAX_RETRIES - 1:
                    wait_time = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                    await asyncio.sleep(wait_time)

            except Exception as e:
                logger.exception(f"Error querying OSV API for {ecosystem}/{package}: {e}")
                return []

        logger.error(
            f"Failed to query OSV API for {ecosystem}/{package} after {MAX_RETRIES} attempts"
        )
        return []

    def _parse_osv_response(
        self, data: dict, ecosystem: str, package: str
    ) -> list[OSVVulnerability]:
        """Parse OSV.dev API response into vulnerability objects.

        Args:
            data: Response data from OSV.dev API.
            ecosystem: Package ecosystem.
            package: Package name.

        Returns:
            List of parsed vulnerabilities.
        """
        vulnerabilities: list[OSVVulnerability] = []
        vulns = data.get("vulns", [])

        for vuln_data in vulns:
            try:
                # Extract CVE IDs from references
                cve_ids = []
                references = []

                for ref in vuln_data.get("references", []):
                    url = ref.get("url", "")
                    references.append(url)

                    if "cve.mitre.org" in url or "nvd.nist.gov" in url:
                        # Extract CVE ID from URL
                        cve_match = re.search(r"(CVE-\d{4}-\d{4,})", url)
                        if cve_match:
                            cve_ids.append(cve_match.group(1))

                # Parse affected/fixed versions
                affected_versions: list[str] = []
                fixed_versions: list[str] | None = None

                affected = vuln_data.get("affected", [])
                if affected:
                    for aff in affected:
                        if aff.get("package", {}).get("name") == package:
                            ranges = aff.get("ranges", [])
                            for range_item in ranges:
                                events = range_item.get("events", [])
                                for event in events:
                                    if "introduced" in event:
                                        affected_versions.append(event.get("introduced", ""))
                                    if "fixed" in event:
                                        if fixed_versions is None:
                                            fixed_versions = []
                                        fixed_versions.append(event.get("fixed", ""))

                vuln = OSVVulnerability(
                    id=vuln_data.get("id", "UNKNOWN"),
                    summary=vuln_data.get("summary", ""),
                    details=vuln_data.get("details"),
                    severity=self._extract_severity(vuln_data),
                    affected_versions=affected_versions or ["*"],
                    fixed_versions=fixed_versions,
                    cve_ids=cve_ids,
                    references=references,
                    published_date=vuln_data.get("published"),
                    package_name=package,
                    ecosystem=ecosystem,
                )
                vulnerabilities.append(vuln)

            except Exception as e:
                logger.warning(f"Error parsing vulnerability {vuln_data.get('id')}: {e}")
                continue

        return vulnerabilities

    def _extract_severity(self, vuln_data: dict) -> str | None:
        """Extract severity from vulnerability data.

        Args:
            vuln_data: Vulnerability data from OSV API.

        Returns:
            Severity level or None.
        """
        severity = vuln_data.get("severity")
        if severity:
            if isinstance(severity, list) and severity:
                return severity[0].get("rating")
            elif isinstance(severity, str):
                return severity

        return None

    async def _parse_lockfile(self, lockfile_path: Path, ecosystem: str) -> list[PackageInfo]:
        """Parse lockfile and extract package information.

        Args:
            lockfile_path: Path to lockfile.
            ecosystem: Detected package ecosystem.

        Returns:
            List of packages found in lockfile.
        """
        filename = lockfile_path.name

        try:
            if filename == "package-lock.json":
                return await self._parse_npm_lockfile(lockfile_path)

            elif filename == "package.json":
                return await self._parse_package_json(lockfile_path)

            elif filename == "requirements.txt":
                return await self._parse_requirements_txt(lockfile_path)

            elif filename in ("Cargo.lock", "Cargo.toml"):
                return await self._parse_cargo_lock(lockfile_path)

            elif filename in ("go.mod", "go.sum"):
                return await self._parse_go_mod(lockfile_path)

            elif filename == "pom.xml":
                return await self._parse_pom_xml(lockfile_path)

            else:
                logger.warning(f"Unsupported lockfile format: {filename}")
                return []

        except Exception as e:
            logger.error(f"Error parsing lockfile {filename}: {e}")
            return []

    async def _parse_npm_lockfile(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse npm package-lock.json file.

        Args:
            lockfile_path: Path to package-lock.json.

        Returns:
            List of npm packages with versions.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                data = json.load(f)

            dependencies = data.get("packages", {})

            for dep_key, dep_info in dependencies.items():
                if not dep_key or dep_key == "":
                    continue

                # Extract package name and version from key format: "node_modules/pkg-name"
                name_match = re.search(r"node_modules/(.+?)(?:/node_modules/|$)", dep_key)
                if not name_match:
                    name_match = re.search(r"^(.+?)$", dep_key)

                if name_match:
                    name = name_match.group(1).split("/")[-1]
                    version = dep_info.get("version", "unknown")

                    if name and version:
                        packages.append(PackageInfo(name=name, version=version, ecosystem="npm"))

            logger.debug(f"Parsed {len(packages)} npm packages from {lockfile_path.name}")

        except Exception as e:
            logger.error(f"Error parsing npm lockfile: {e}")

        return packages

    async def _parse_package_json(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse package.json file.

        Args:
            lockfile_path: Path to package.json.

        Returns:
            List of npm packages.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                data = json.load(f)

            for deps in [
                data.get("dependencies", {}),
                data.get("devDependencies", {}),
            ]:
                for name, version in deps.items():
                    if name and version:
                        # Remove version specifiers (^, ~, etc.)
                        clean_version = re.sub(r"^[\^~>=<]", "", version).split()[0]
                        packages.append(
                            PackageInfo(name=name, version=clean_version, ecosystem="npm")
                        )

            logger.debug(f"Parsed {len(packages)} npm packages from package.json")

        except Exception as e:
            logger.error(f"Error parsing package.json: {e}")

        return packages

    async def _parse_requirements_txt(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse Python requirements.txt file.

        Args:
            lockfile_path: Path to requirements.txt.

        Returns:
            List of Python packages.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse requirement line (e.g., "package==1.0.0")
                match = re.match(r"([a-zA-Z0-9_\-\.]+)(?:[=><~!]+(.+))?", line)
                if match:
                    name = match.group(1)
                    version = match.group(2) or "unknown"

                    if name:
                        packages.append(PackageInfo(name=name, version=version, ecosystem="PyPI"))

            logger.debug(f"Parsed {len(packages)} Python packages from requirements.txt")

        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {e}")

        return packages

    async def _parse_cargo_lock(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse Rust Cargo.lock file.

        Args:
            lockfile_path: Path to Cargo.lock.

        Returns:
            List of Rust packages.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                content = f.read()

            # Parse TOML format (simple regex approach for Cargo.lock)
            package_matches = re.finditer(r'name = "([^"]+)"\nversion = "([^"]+)"', content)

            for match in package_matches:
                name = match.group(1)
                version = match.group(2)

                if name:
                    packages.append(PackageInfo(name=name, version=version, ecosystem="crates.io"))

            logger.debug(f"Parsed {len(packages)} Rust packages from Cargo.lock")

        except Exception as e:
            logger.error(f"Error parsing Cargo.lock: {e}")

        return packages

    async def _parse_go_mod(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse Go go.mod or go.sum file.

        Args:
            lockfile_path: Path to go.mod or go.sum.

        Returns:
            List of Go packages.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("//"):
                    continue

                # Parse require/replace statements from go.mod
                if "require" in line or line.startswith("replace"):
                    continue

                # Parse format: "module-path version"
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]

                    if name and version:
                        packages.append(PackageInfo(name=name, version=version, ecosystem="Go"))

            # Deduplicate packages
            seen: set[str] = set()
            unique_packages: list[PackageInfo] = []
            for pkg in packages:
                key = f"{pkg.name}:{pkg.version}"
                if key not in seen:
                    unique_packages.append(pkg)
                    seen.add(key)

            logger.debug(f"Parsed {len(unique_packages)} Go packages from go.mod/go.sum")

            return unique_packages

        except Exception as e:
            logger.error(f"Error parsing go.mod: {e}")

        return packages

    async def _parse_pom_xml(self, lockfile_path: Path) -> list[PackageInfo]:
        """Parse Maven pom.xml file.

        Args:
            lockfile_path: Path to pom.xml.

        Returns:
            List of Maven packages.
        """
        packages: list[PackageInfo] = []

        try:
            with open(lockfile_path, encoding="utf-8") as f:
                content = f.read()

            # Simple regex-based XML parsing for dependencies
            # Match <artifactId>name</artifactId> and <version>version</version>
            artifact_matches = re.finditer(r"<artifactId>([^<]+)</artifactId>", content)
            version_matches = list(re.finditer(r"<version>([^<]+)</version>", content))

            for i, artifact_match in enumerate(artifact_matches):
                name = artifact_match.group(1)

                if i < len(version_matches):
                    version = version_matches[i].group(1)
                else:
                    version = "unknown"

                if name:
                    packages.append(PackageInfo(name=name, version=version, ecosystem="Maven"))

            logger.debug(f"Parsed {len(packages)} Maven packages from pom.xml")

        except Exception as e:
            logger.error(f"Error parsing pom.xml: {e}")

        return packages

    def _detect_ecosystem(self, filename: str) -> str | None:
        """Detect package ecosystem from lockfile name.

        Args:
            filename: Name of the lockfile.

        Returns:
            Ecosystem name or None if not supported.
        """
        return ECOSYSTEM_MAPPING.get(filename)

    def _is_cached(self, cache_key: str) -> bool:
        """Check if result is cached and not expired.

        Args:
            cache_key: Cache key to check.

        Returns:
            True if cached and not expired.
        """
        if cache_key not in self._cache:
            return False

        cached_result, timestamp = self._cache[cache_key]
        age = datetime.now(UTC) - timestamp
        expiration = timedelta(hours=CACHE_DURATION_HOURS)

        return age < expiration

    def _get_from_cache(self, cache_key: str) -> list[OSVVulnerability]:
        """Get cached result.

        Args:
            cache_key: Cache key.

        Returns:
            Cached vulnerabilities or empty list.
        """
        if not self._is_cached(cache_key):
            return []

        result, _ = self._cache[cache_key]
        return result

    async def close(self) -> None:
        """Close the httpx client."""
        if self._client:
            await self._client.aclose()
