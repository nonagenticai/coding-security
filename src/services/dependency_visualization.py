"""Dependency Visualization Utilities Module.

Handles OSV vulnerability scanning, caching, batch processing,
and vulnerability data management for dependency analysis.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from models.architecture_models import Vulnerability
from models.package_manager_models import ExternalPackage, normalize_package_name

logger = logging.getLogger(__name__)

# Defensive upper bound on the request-scoped vulnerability cache. The scanner is
# built per request (FastAPI ``Depends``) and GC'd with it, so this is not a leak
# fix — just a bound against a single pathological request enumerating an
# unbounded package set. LRU eviction (oldest insertion first) via OrderedDict.
_CACHE_MAXSIZE = 4096

# Bound on concurrent GET /v1/vulns/{id} follow-ups per scan. ``querybatch``
# returns only ``{id, modified}`` per advisory, so every distinct id needs one
# follow-up to learn its severity and fixed-in versions.
_OSV_RECORD_FETCH_CONCURRENCY = 8

# Bounds on that fan-out per scan: at most this many DISTINCT ids are fetched,
# and all fetches must finish inside this many seconds. Exceeding either leaves
# the remaining advisories as unhydrated stubs (severity UNKNOWN, no fix) and
# records a lookup error, so the scan reads degraded — never silently truncated.
_OSV_MAX_RECORD_FETCHES_PER_SCAN = 500
_OSV_RECORD_FETCH_BUDGET_SECONDS = 60.0

# OSV range types whose events are package versions. ``None`` covers records
# that omit the type. GIT ranges (commit hashes) are deliberately excluded.
_VERSION_RANGE_TYPES = frozenset({None, "ECOSYSTEM", "SEMVER"})


@dataclass
class PartialDependencyState:
    """Caller-held accumulator so completed OSV work survives a scan timeout.

    The dependency analog of ``PartialAnalysisState`` on the container path
    (``security_detector.py``): the analyzer aliases ``packages`` and extends
    ``vulnerabilities`` *live*, so an ``asyncio.wait_for`` cancellation mid-scan
    leaves already-finished work recorded instead of discarding it. Consumed only
    on the timeout branch — the success path uses the analyzer's normal
    deduplicated return value.

    Incremental (mid-scan) partials only accrue on the **online** batched path
    (``_query_osv_batched``), which deposits after each awaited batch. The
    **offline** DB path (``_query_offline``, used in prod where OSV egress is
    blocked) is synchronous and cannot be cancelled mid-loop, so there the
    accumulator is effectively all-or-nothing for vulnerabilities — but the
    resolved ``packages`` set is still recorded before the scan, so a timeout
    yields an honest degraded report rather than a bare failure.
    """

    packages: list[ExternalPackage] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


def _version_of(package: ExternalPackage) -> str:
    """The version a package's records are matched against ("" when unpinned)."""
    return package.version or package.current_version or ""


# Characters that make a version string a constraint, not one exact version.
# Any whitespace, `|` (npm `||`), `,` or `*` also makes it a range.
_CONSTRAINT_CHARS = frozenset("^~<>=*!,|")
# Fully anchored (used with ``fullmatch``); prerelease/build restricted to the
# SemVer charset so nothing range-like (``1.2.3-beta||9.9.9``) can hide in it.
_STRICT_SEMVER_RE = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.]+)?")
_FLOATING_VERSIONS = frozenset({"x", "latest", "next", "stable", "current", "any"})


def _exact_version(package: ExternalPackage) -> str | None:
    """The package's version when it is ONE exact version, else None.

    Only an exact pin may be sent to OSV as ``version`` (and used to drop
    online records): OSV evaluates the string as a single version, so a range
    such as ``^4.17.0`` sent as ``4.17.0`` would hide every advisory for the
    versions the range really admits. ``version`` is stored operator-free, so
    the manifest ``specifier`` decides when there is one: PyPI ``==X`` and a
    bare/``=`` npm version are pins; a bare Cargo.toml version is a caret range.
    Lockfile packages carry no specifier and their resolved version is exact.
    """
    ecosystem = (package.ecosystem or "").lower()
    if package.specifier is not None:
        spec = package.specifier.strip()
        if ecosystem == "pypi":
            pin = (
                spec[3:] if spec.startswith("===") else spec[2:] if spec.startswith("==") else None
            )
        elif ecosystem == "crates.io":
            pin = spec[1:] if spec.startswith("=") and not spec.startswith("==") else None
        else:
            pin = spec[1:] if spec.startswith("=") and not spec.startswith("==") else spec
        if pin is None:
            return None
        candidate = pin.strip()
    else:
        candidate = _version_of(package).strip()
    if not candidate or candidate.lower() in _FLOATING_VERSIONS:
        return None
    if any(ch in _CONSTRAINT_CHARS or ch.isspace() for ch in candidate):
        return None
    if ecosystem == "pypi":
        try:
            Version(candidate)
        except InvalidVersion:
            return None
        return candidate
    return candidate if _STRICT_SEMVER_RE.fullmatch(candidate) else None


class DependencyVulnerabilityScanner:
    """Handles vulnerability scanning using OSV.dev API with caching and batching.

    Provides efficient vulnerability detection with rate limiting,
    caching, and batch processing capabilities.
    """

    # The canonical OSV ecosystem names, keyed by our extractor's lower-cased
    # ids. Used for BOTH the offline DB subdir AND the ``ecosystem`` field of
    # every online query: OSV is case-sensitive and answers ``"pypi"`` with a
    # 400. A miss here would make every offline lookup silently read 0.
    _ECOSYSTEM_DIR_MAP = {
        "pypi": "PyPI",
        "npm": "npm",
        "crates.io": "crates.io",
        "go": "Go",
        "maven": "Maven",
        "nuget": "NuGet",
        "packagist": "Packagist",
        "rubygems": "RubyGems",
    }

    def __init__(
        self,
        timeout: int = 30,
        enable_cache: bool = True,
        cache_ttl_hours: int = 24,
        batch_size: int = 10,
        max_concurrent_batches: int = 5,
        offline_db_dir: str | None = None,
        cache_maxsize: int = _CACHE_MAXSIZE,
    ) -> None:
        """Initialize the vulnerability scanner.

        Args:
            timeout: HTTP timeout for vulnerability scanning in seconds
            enable_cache: Whether to enable vulnerability result caching
            cache_ttl_hours: Time-to-live for cached vulnerability results in hours
            batch_size: Number of packages to batch together
            max_concurrent_batches: Maximum concurrent batch requests
            offline_db_dir: Path to a baked per-package OSV database. When set
                (or ``OSV_OFFLINE_DB_DIR`` is in the env), scanning reads CVEs
                from this local DB instead of api.osv.dev — required because the
                pod's egress to OSV is blocked by the ambient-mesh policy. The
                offline path is also version-aware (the online path is not), so
                an upgrade actually drops the count for the delta gate.
        """
        self.timeout = timeout
        self.osv_api_url = "https://api.osv.dev/v1/query"
        self.osv_batch_url = "https://api.osv.dev/v1/querybatch"
        self.osv_vuln_url = "https://api.osv.dev/v1/vulns/{vuln_id}"

        # Offline DB: explicit arg wins, else env. Empty/missing => online path,
        # so every test that constructs the scanner without it stays unchanged.
        self._offline_db_dir = offline_db_dir or os.environ.get("OSV_OFFLINE_DB_DIR") or None

        # Cache configuration
        self.enable_cache = enable_cache
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache_maxsize = cache_maxsize
        self.vulnerability_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

        # Batching configuration
        self.batch_size = batch_size
        self.max_concurrent_batches = max_concurrent_batches

        # Per-scan outcome, reset at the start of every ``scan_vulnerabilities``.
        # ``lookup_errors``: one entry per package/batch whose OSV lookup FAILED
        # (HTTP error, non-200, rate-limit skip, unreadable offline record, missing
        # offline DB). The lookup paths below are fail-soft and keep scanning, so
        # without this an outage is indistinguishable from "no vulnerabilities" —
        # callers MUST check it before reading an empty result as clean.
        # ``package_vulnerabilities``: package name -> its vulnerabilities, built
        # BEFORE the by-id dedup (which keeps only the first package of an advisory
        # shared by two packages), so every affected package can be enriched.
        self.lookup_errors: list[str] = []
        self.package_vulnerabilities: dict[str, list[Vulnerability]] = {}
        # Per-scan dedup of the GET /v1/vulns/{id} follow-ups: one fetch per id
        # even when several packages / concurrent batches share an advisory.
        self._record_fetches: dict[str, asyncio.Task[dict[str, Any] | None]] = {}
        self._record_fetch_semaphore: asyncio.Semaphore | None = None
        # Fan-out bounds (see the module constants); instance attributes so a
        # caller or test can tighten them. The deadline is armed by the first
        # fetch of a scan and shared by every later fetch in it.
        self.max_record_fetches = _OSV_MAX_RECORD_FETCHES_PER_SCAN
        self.record_fetch_budget_seconds = _OSV_RECORD_FETCH_BUDGET_SECONDS
        self._record_fetch_deadline: float | None = None
        self._record_fetch_limits_hit: set[str] = set()

        logger.info(
            "DependencyVulnerabilityScanner initialized (cache: %s, batch_size: %d, offline: %s)",
            enable_cache,
            batch_size,
            bool(self._offline_db_dir),
        )

    async def scan_vulnerabilities(
        self,
        packages: list[ExternalPackage],
        partial: PartialDependencyState | None = None,
    ) -> list[Vulnerability]:
        """Scan packages for vulnerabilities using OSV.dev API with batching and caching.

        Args:
            packages: List of packages to check for vulnerabilities
            partial: Optional caller-held accumulator. When provided, cache hits
                are deposited up front and each online OSV batch is deposited as
                it completes, so a scan-timeout cancellation on the batched path
                preserves partial findings instead of discarding them. (The
                synchronous offline path can't be cancelled mid-loop — see
                ``PartialDependencyState``.)

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities: list[Vulnerability] = []
        self.lookup_errors = []
        self.package_vulnerabilities = {}
        self._record_fetches = {}
        self._record_fetch_semaphore = None
        self._record_fetch_deadline = None
        self._record_fetch_limits_hit = set()

        if not packages:
            return vulnerabilities

        # Separate cached and uncached packages
        cached_packages, uncached_packages = self._separate_cached_packages(packages)

        # Get vulnerabilities from cache
        for package in cached_packages:
            cache_key = self._get_cache_key(package)
            cached_vulns = self.vulnerability_cache[cache_key]["data"]
            vulnerabilities.extend(cached_vulns)
            if partial is not None:
                partial.vulnerabilities.extend(cached_vulns)

        logger.info(
            "Retrieved %d cached vulnerability results, querying %d packages",
            len(cached_packages),
            len(uncached_packages),
        )

        # Query uncached packages — offline DB when configured, else OSV API.
        if uncached_packages:
            if self._offline_db_dir:
                queried = self._query_offline(uncached_packages, partial=partial)
            else:
                queried = await self._query_osv_batched(uncached_packages, partial=partial)
            vulnerabilities.extend(queried)

        for vuln in vulnerabilities:
            if not vuln.package_name:
                continue
            owned = self.package_vulnerabilities.setdefault(vuln.package_name, [])
            if all(
                (existing.id, existing.package_version) != (vuln.id, vuln.package_version)
                for existing in owned
            ):
                owned.append(vuln)

        if self.lookup_errors:
            logger.error(
                "OSV lookup failed for %d package(s)/batch(es); result is INCOMPLETE: %s",
                len(self.lookup_errors),
                "; ".join(self.lookup_errors[:5]),
            )

        # Remove duplicate vulnerabilities based on ID
        unique_vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        logger.info(
            "Found %d total vulnerabilities across %d packages",
            len(unique_vulnerabilities),
            len(packages),
        )
        return unique_vulnerabilities

    def _separate_cached_packages(
        self, packages: list[ExternalPackage]
    ) -> tuple[list[ExternalPackage], list[ExternalPackage]]:
        """Separate packages into cached and uncached lists."""
        cached: list[ExternalPackage] = []
        uncached: list[ExternalPackage] = []

        if not self.enable_cache:
            return cached, packages

        current_time = datetime.now(UTC)

        for package in packages:
            cache_key = self._get_cache_key(package)

            if cache_key in self.vulnerability_cache:
                cached_data = self.vulnerability_cache[cache_key]
                cache_time = cached_data["timestamp"]

                # Check if cache is still valid
                if current_time - cache_time < self.cache_ttl:
                    cached.append(package)
                else:
                    # Cache expired, remove and query again
                    del self.vulnerability_cache[cache_key]
                    uncached.append(package)
            else:
                uncached.append(package)

        return cached, uncached

    def _get_cache_key(self, package: ExternalPackage) -> str:
        """Generate a cache key for a package."""
        # The version is part of the key: online queries are version-filtered by
        # OSV, so a result for one version must never replay for another.
        key_data = f"{package.name}:{package.ecosystem}:{_version_of(package)}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    async def _query_osv_batched(
        self,
        packages: list[ExternalPackage],
        partial: PartialDependencyState | None = None,
    ) -> list[Vulnerability]:
        """Query OSV API using batched requests with concurrency control."""
        vulnerabilities: list[Vulnerability] = []

        # Split packages into batches
        batches = [
            packages[i : i + self.batch_size] for i in range(0, len(packages), self.batch_size)
        ]

        # Use semaphore to limit concurrent batches
        semaphore = asyncio.Semaphore(self.max_concurrent_batches)

        async def process_batch(
            batch: list[ExternalPackage],
        ) -> list[Vulnerability]:
            async with semaphore:
                result = await self._query_single_batch(batch)
                # Deposit the instant this batch completes — BEFORE the outer
                # asyncio.gather returns — so a wait_for cancellation still
                # leaves the finished batches in the caller-held accumulator.
                if partial is not None:
                    partial.vulnerabilities.extend(result)
                return result

        # Process all batches concurrently
        batch_results = await asyncio.gather(
            *[process_batch(batch) for batch in batches],
            return_exceptions=True,
        )

        # Collect results and handle exceptions
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                logger.error("Batch %d failed: %s", i, result)
                self.lookup_errors.append(f"batch {i}: {result}")
            elif isinstance(result, list):
                vulnerabilities.extend(result)

        return vulnerabilities

    async def _query_single_batch(self, packages: list[ExternalPackage]) -> list[Vulnerability]:
        """Query a single batch of packages."""
        vulnerabilities: list[Vulnerability] = []

        try:
            # Prepare batch payload
            batch_payload = {"queries": [self._osv_query(pkg) for pkg in packages]}

            async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client:
                response = await client.post(self.osv_batch_url, json=batch_payload)
                if response.status_code == 200:
                    # Process each result and cache it
                    response_data = response.json()
                    for i, result in enumerate(response_data.get("results", [])):
                        if i >= len(packages):
                            continue

                        # querybatch returns only {id, modified} per advisory:
                        # fetch each full record (severity + fixed-in versions).
                        records, complete = await self._hydrate_records(
                            client, result.get("vulns") or []
                        )
                        if result.get("next_page_token"):
                            complete = False
                            self.lookup_errors.append(
                                f"{packages[i].name}: OSV results paginated (not followed)"
                            )

                        package_vulnerabilities = []
                        for vuln_data in self._records_affecting(records, packages[i]):
                            if vulnerability := self._parse_osv_vulnerability(
                                vuln_data, package_name=packages[i].name
                            ):
                                # Stamp the owning package on every vuln (mirrors
                                # the individual-fallback and offline paths) so
                                # correlation can join on exact package identity
                                # instead of substring-matching free text.
                                vulnerability = vulnerability.model_copy(
                                    update={
                                        "package_name": packages[i].name,
                                        "package_version": _version_of(packages[i]),
                                    }
                                )
                                package_vulnerabilities.append(vulnerability)
                                vulnerabilities.append(vulnerability)

                        # Cache only a COMPLETE result: a cached incomplete one
                        # would replay as clean, with no lookup error, next scan.
                        self._cache_package_vulnerabilities(
                            packages[i], package_vulnerabilities, complete=complete
                        )

                elif response.status_code == 429:
                    logger.warning("Rate limited by OSV.dev API, implementing backoff")
                    # Longer backoff for batch requests
                    await asyncio.sleep(2)
                    # Retry with individual requests as fallback
                    return await self._query_individual_fallback(packages)
                else:
                    logger.warning(
                        "OSV API returned status %d for batch request",
                        response.status_code,
                    )
                    self.lookup_errors.append(
                        f"batch of {len(packages)}: OSV status {response.status_code}"
                    )

        except TimeoutError:
            logger.warning("Timeout during batch vulnerability query")
            self.lookup_errors.append(f"batch of {len(packages)}: timeout")
        except Exception as e:
            logger.warning("Error during batch vulnerability query: %s", e)
            # Fallback to individual requests
            return await self._query_individual_fallback(packages)

        return vulnerabilities

    async def _query_individual_fallback(
        self, packages: list[ExternalPackage]
    ) -> list[Vulnerability]:
        """Fallback to individual requests when batch request fails."""
        vulnerabilities: list[Vulnerability] = []

        logger.info(
            "Falling back to individual requests for %d packages",
            len(packages),
        )

        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client:
            for package in packages:
                try:
                    payload = self._osv_query(package)

                    response = await client.post(self.osv_api_url, json=payload)
                    if response.status_code == 200:
                        data = response.json()
                        vulns, complete = await self._hydrate_records(
                            client, data.get("vulns") or []
                        )
                        if data.get("next_page_token"):
                            complete = False
                            self.lookup_errors.append(
                                f"{package.name}: OSV results paginated (not followed)"
                            )
                        package_vulnerabilities = []

                        for vuln_data in self._records_affecting(vulns, package):
                            vulnerability = self._parse_osv_vulnerability(
                                vuln_data, package_name=package.name
                            )
                            if vulnerability:
                                # Stamp the owning package on every vuln so
                                # the CVE-driven upgrade route can join back
                                # to ExternalPackage without re-querying.
                                vulnerability = vulnerability.model_copy(
                                    update={
                                        "package_name": package.name,
                                        "package_version": _version_of(package),
                                    }
                                )
                                package_vulnerabilities.append(vulnerability)
                                vulnerabilities.append(vulnerability)

                        # Cache only a complete result (see _query_single_batch).
                        self._cache_package_vulnerabilities(
                            package, package_vulnerabilities, complete=complete
                        )

                    elif response.status_code == 429:
                        logger.warning(
                            "Rate limited by OSV.dev API, skipping package %s",
                            package.name,
                        )
                        self.lookup_errors.append(f"{package.name}: OSV rate-limited (429)")
                        await asyncio.sleep(1)
                    else:
                        logger.warning(
                            "OSV API returned status %d for package %s",
                            response.status_code,
                            package.name,
                        )
                        self.lookup_errors.append(
                            f"{package.name}: OSV status {response.status_code}"
                        )

                    # Add small delay between individual requests to be respectful
                    await asyncio.sleep(0.1)

                except (TimeoutError, Exception, ValueError, KeyError) as e:
                    logger.warning(
                        "Error querying vulnerabilities for package %s: %s",
                        package.name,
                        e,
                    )
                    self.lookup_errors.append(f"{package.name}: {type(e).__name__}: {e}")

        return vulnerabilities

    def _osv_query(self, package: ExternalPackage) -> dict[str, Any]:
        """One OSV query for ``package``, version-scoped when the version is known.

        With ``version`` OSV returns only the advisories affecting that version;
        without it, every advisory ever published for the package (all of them
        false positives once the package is past the fix). A package without
        an exact pin (see ``_exact_version``) stays name-only — the
        conservative "report everything" fallback.
        """
        query: dict[str, Any] = {
            "package": {"name": package.name, "ecosystem": self._osv_ecosystem(package)}
        }
        if version := _exact_version(package):
            query["version"] = version
        return query

    def _records_affecting(
        self, records: list[Any], package: ExternalPackage
    ) -> list[dict[str, Any]]:
        """The online records that affect ``package``'s installed version.

        Belt-and-braces over OSV's server-side version filter: a record whose
        ranges for this package exclude the installed version is dropped. A
        record with nothing to evaluate (an unhydrated stub, no version ranges)
        is kept — OSV matched it, and dropping it would fail open. A package
        without an exact version (a range, ``*``, ``latest``) was queried by
        name only, and every record is kept.
        """
        installed = _exact_version(package)
        return [
            record
            for record in records
            if isinstance(record, dict)
            and not record.get("withdrawn")
            and (
                installed is None
                or self._affects_installed_version(
                    record, installed, package_name=package.name, when_unevaluable=True
                )
            )
        ]

    @classmethod
    def _osv_ecosystem(cls, package: ExternalPackage) -> str:
        """The canonical OSV ecosystem name for ``package`` (``pypi`` -> ``PyPI``).

        Unmapped ecosystems pass through unchanged. Defaults to PyPI, as the
        offline path does.
        """
        raw = package.ecosystem or "pypi"
        return cls._ECOSYSTEM_DIR_MAP.get(raw.lower(), raw)

    @staticmethod
    def _is_record_stub(record: Any) -> bool:
        """True for a ``querybatch`` entry: ``{id, modified}`` and nothing else."""
        return (
            isinstance(record, dict)
            and bool(record.get("id"))
            and set(record)
            <= {
                "id",
                "modified",
            }
        )

    async def _hydrate_records(
        self, client: httpx.AsyncClient, records: list[Any]
    ) -> tuple[list[Any], bool]:
        """Replace ``querybatch`` stubs with full OSV records.

        Returns ``(records, complete)``. A stub whose fetch failed is kept as-is:
        it still parses (severity UNKNOWN, no fixed-in version) so the package is
        not reported clean, and the failure is in ``lookup_errors`` so the scan
        reads degraded. Full records pass through untouched.
        """
        stub_ids = list(dict.fromkeys(r["id"] for r in records if self._is_record_stub(r)))
        if not stub_ids:
            return records, True
        fetched = await asyncio.gather(*(self._fetch_record(client, vid) for vid in stub_ids))
        by_id = dict(zip(stub_ids, fetched, strict=True))
        complete = all(full is not None for full in fetched)
        hydrated = [(by_id.get(r["id"]) or r) if self._is_record_stub(r) else r for r in records]
        return hydrated, complete

    async def _fetch_record(self, client: httpx.AsyncClient, vuln_id: str) -> dict[str, Any] | None:
        """GET /v1/vulns/{id}, at most once per id per scan (shared across batches)."""
        task = self._record_fetches.get(vuln_id)
        if task is None:
            if len(self._record_fetches) >= self.max_record_fetches:
                self._record_fetch_limit_hit(
                    "cap",
                    f"OSV record fetch cap of {self.max_record_fetches} distinct ids per "
                    "scan exceeded; remaining advisories not hydrated",
                )
                return None
            task = asyncio.ensure_future(self._fetch_record_uncached(client, vuln_id))
            self._record_fetches[vuln_id] = task
        return await task

    def _record_fetch_limit_hit(self, kind: str, message: str) -> None:
        """Record a fan-out bound being exceeded, once per kind per scan."""
        if kind not in self._record_fetch_limits_hit:
            self._record_fetch_limits_hit.add(kind)
            logger.error("%s", message)
            self.lookup_errors.append(message)

    async def _fetch_record_uncached(
        self, client: httpx.AsyncClient, vuln_id: str
    ) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()
        if self._record_fetch_deadline is None:
            self._record_fetch_deadline = loop.time() + self.record_fetch_budget_seconds
        if self._record_fetch_semaphore is None:
            self._record_fetch_semaphore = asyncio.Semaphore(_OSV_RECORD_FETCH_CONCURRENCY)
        # The budget covers queueing on the semaphore as well as the GET.
        budget = asyncio.timeout_at(self._record_fetch_deadline)
        try:
            async with budget:
                async with self._record_fetch_semaphore:
                    response = await client.get(self.osv_vuln_url.format(vuln_id=vuln_id))
        except TimeoutError as exc:
            if not budget.expired():  # the GET itself timed out, not the budget
                self.lookup_errors.append(f"{vuln_id}: OSV record fetch failed: timeout: {exc}")
                return None
            self._record_fetch_limit_hit(
                "budget",
                f"OSV record fetch budget of {self.record_fetch_budget_seconds:g}s per scan "
                "exceeded; remaining advisories not hydrated",
            )
            return None
        except Exception as exc:  # connect error, read error, ...
            self.lookup_errors.append(
                f"{vuln_id}: OSV record fetch failed: {type(exc).__name__}: {exc}"
            )
            return None
        if response.status_code != 200:
            self.lookup_errors.append(f"{vuln_id}: OSV record fetch status {response.status_code}")
            return None
        try:
            data = response.json()
        except ValueError as exc:
            self.lookup_errors.append(f"{vuln_id}: OSV record unreadable: {exc}")
            return None
        if not isinstance(data, dict) or data.get("id") != vuln_id:
            self.lookup_errors.append(f"{vuln_id}: OSV record malformed")
            return None
        return data

    @staticmethod
    def _normalize_pkg_name(name: str) -> str:
        """Normalise a package name to match the baked offline-DB filenames.

        Delegates to the one shared definition so the extractor's duplicate
        check (lockfile-resolved vs manifest) can never diverge from the
        lookup's, which would let a phantom row through.
        """
        return normalize_package_name(name)

    @classmethod
    def _record_filename(cls, name: str) -> str:
        """The baked record's filename for ``name``.

        Scoped npm names (``@scope/pkg``) contain a path separator that the
        builder replaces with ``_`` when it writes ``<ecosystem>/<name>.json``.
        Mirroring only ``normalize_name`` here left every scoped package looking
        up ``npm/@scope/pkg.json`` — a nested path that never exists, so it read
        as "no advisories" instead of being checked. Keep this in lockstep with
        the builder's ``safe`` step.
        """
        safe = cls._normalize_pkg_name(name).replace("/", "_").replace("\\", "_")
        return f"{safe}.json"

    def _query_offline(
        self,
        packages: list[ExternalPackage],
        partial: PartialDependencyState | None = None,
    ) -> list[Vulnerability]:
        """Resolve CVEs from the baked per-package OSV DB (no network).

        Mirrors the online path's output (reuses ``_parse_osv_vulnerability``
        and stamps ``package_name``) but is **version-aware** for an exact pin
        (``_exact_version``): a record is only reported when that version falls
        in an affected range. Any other version reports every non-withdrawn
        record, exactly like the online name-only query. That is what lets an upgrade actually drop the count for the
        delta gate — the online name-only query never could.
        """
        db_root = Path(self._offline_db_dir) if self._offline_db_dir else None
        vulnerabilities: list[Vulnerability] = []
        if db_root is None:
            return vulnerabilities
        if not db_root.is_dir():
            # Every per-package lookup below would read "no record" and report the
            # repo clean. A missing DB is an outage, not an absence of CVEs.
            self.lookup_errors.append(f"offline OSV DB not found at {db_root}")
            return vulnerabilities

        # Ecosystems the baked DB does not cover (the image bakes PyPI,
        # crates.io and npm), mapped to the packages we could not check. A
        # package in one of these is UNCHECKED, not clean: reading it as clean
        # is the fail-open this guards.
        uncovered: dict[str, list[str]] = {}
        for package in packages:
            ecosystem = (package.ecosystem or "pypi").lower()
            osv_dir = self._ECOSYSTEM_DIR_MAP.get(ecosystem)
            if osv_dir is None or not (db_root / osv_dir).is_dir():
                uncovered.setdefault(ecosystem, []).append(package.name)
                continue

            record_file = db_root / osv_dir / self._record_filename(package.name)
            if not record_file.is_file():
                continue

            try:
                records = json.loads(record_file.read_text())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.warning("Failed to read offline OSV record %s: %s", record_file, exc)
                self.lookup_errors.append(f"{package.name}: unreadable offline OSV record")
                continue

            # Same exact-pin decision as the online path: only an exact version
            # may drop a record; a range (or no version) reports every record.
            installed = _exact_version(package)
            package_vulnerabilities: list[Vulnerability] = []
            for record in records:
                if not isinstance(record, dict) or record.get("withdrawn"):
                    continue
                if installed is not None and not self._affects_installed_version(
                    record, installed, package_name=package.name
                ):
                    continue
                vulnerability = self._parse_osv_vulnerability(record, package_name=package.name)
                if vulnerability:
                    # Stamp the owning package so the CVE-driven upgrade route
                    # can join back to ExternalPackage (mirrors the online
                    # individual-fallback path).
                    vulnerability = vulnerability.model_copy(
                        update={
                            "package_name": package.name,
                            "package_version": _version_of(package),
                        }
                    )
                    package_vulnerabilities.append(vulnerability)
                    vulnerabilities.append(vulnerability)

            # Reached only after the record file was read and every record
            # evaluated; unreadable/uncovered packages `continue` above.
            self._cache_package_vulnerabilities(package, package_vulnerabilities, complete=True)
            if partial is not None:
                partial.vulnerabilities.extend(package_vulnerabilities)

        # One error per ecosystem (not per package) so the route's 503 detail,
        # which shows the first few errors, names every uncovered ecosystem.
        self.lookup_errors[:0] = [
            f"no offline OSV DB for ecosystem '{ecosystem}': "
            f"{len(names)} package(s) unchecked ({', '.join(names[:3])})"
            for ecosystem, names in uncovered.items()
        ]

        return vulnerabilities

    def _affects_installed_version(
        self,
        record: dict[str, Any],
        installed_version: str | None,
        *,
        package_name: str | None = None,
        when_unevaluable: bool = False,
    ) -> bool:
        """Return True iff ``installed_version`` falls in an affected range.

        Conservative on ambiguity: an unparseable / unpinned (``*`` / None)
        version reports ALL non-withdrawn records for the package (preserves
        the online path's "report everything" behaviour for unpinned deps).

        With ``package_name``, only the ``affected`` entries naming that package
        are evaluated (all of them when none does), so another package's range
        in a shared advisory cannot decide this package's verdict.
        ``when_unevaluable`` is returned when those entries carry no enumerated
        versions and no version-typed range (e.g. GIT-only, or none at all).
        """
        cleaned = self._clean_version(installed_version)
        if cleaned is None:
            return True
        try:
            installed = Version(cleaned)
        except InvalidVersion:
            return True

        entries = [a for a in record.get("affected", []) or [] if isinstance(a, dict)]
        if package_name:
            wanted = self._normalize_pkg_name(package_name)
            own = [
                a
                for a in entries
                if self._normalize_pkg_name(str((a.get("package") or {}).get("name") or ""))
                == wanted
            ]
            entries = own or entries

        evaluable = any(
            (a.get("versions") or [])
            or any(r.get("type") in _VERSION_RANGE_TYPES for r in (a.get("ranges") or []))
            for a in entries
        )
        if not evaluable:
            return when_unevaluable

        for affected in entries:
            # Explicit enumerated versions.
            for ver in affected.get("versions", []) or []:
                try:
                    if Version(str(ver)) == installed:
                        return True
                except InvalidVersion:
                    continue

            for range_info in affected.get("ranges", []) or []:
                if range_info.get("type") not in _VERSION_RANGE_TYPES:
                    continue
                if self._installed_in_range(range_info, installed, affected):
                    return True

        return False

    @staticmethod
    def _installed_in_range(
        range_info: dict[str, Any], installed: Version, affected: dict[str, Any]
    ) -> bool:
        """Evaluate one OSV range over its ordered events.

        An ``introduced`` opens an interval; it is closed by ``fixed`` or
        ``limit`` (exclusive: introduced <= installed < X) or by
        ``last_affected`` (inclusive: introduced <= installed <= X). A lone
        ``introduced`` means affected through latest, unless a
        ``database_specific.last_affected`` closes the interval.
        """
        introduced: Version | None = None
        for event in range_info.get("events", []) or []:
            if "introduced" in event:
                raw = event["introduced"]
                # "0" means "from the very first version".
                try:
                    introduced = Version("0") if raw == "0" else Version(str(raw))
                except InvalidVersion:
                    introduced = Version("0")
                continue
            if "last_affected" in event:
                key, inclusive = "last_affected", True
            elif "fixed" in event:
                key, inclusive = "fixed", False
            elif "limit" in event:
                key, inclusive = "limit", False
            else:
                continue
            if introduced is None:
                continue
            try:
                bound = Version(str(event[key]))
            except InvalidVersion:
                # An unparseable upper bound: conservative, the interval stays open.
                continue
            if introduced <= installed and (installed <= bound if inclusive else installed < bound):
                return True
            introduced = None  # interval closed; await the next introduced

        # Open interval (introduced with no fixed) still pending.
        if introduced is not None and introduced <= installed:
            last_affected = affected.get("database_specific", {}).get("last_affected")
            if last_affected:
                try:
                    return installed <= Version(str(last_affected))
                except InvalidVersion:
                    return True
            return True
        return False

    @staticmethod
    def _clean_version(version: str | None) -> str | None:
        """Strip manifest constraint operators to a bare version, or None.

        Mirrors ``DependencyExtractor.clean_version_for_osv``; returns None for
        unpinned/empty so the caller falls back to the conservative include.
        """
        if not version:
            return None
        cleaned = version
        for op in ("==", ">=", "<=", "~=", "!=", ">", "<", "^"):
            cleaned = cleaned.replace(op, "")
        cleaned = cleaned.strip()
        if not cleaned or cleaned == "*":
            return None
        return cleaned

    def _cache_package_vulnerabilities(
        self,
        package: ExternalPackage,
        vulnerabilities: list[Vulnerability],
        *,
        complete: bool,
    ) -> None:
        """Cache a package's vulnerability result — only when it is COMPLETE.

        ``complete`` is required so every lookup path must declare it: an
        incomplete result (a failed record fetch, pagination not followed, a
        fan-out cap/budget hit) cached here would replay next scan as a clean
        cache hit with no lookup error, i.e. a silent fail-open.
        """
        if not self.enable_cache or not complete:
            return

        cache_key = self._get_cache_key(package)
        self.vulnerability_cache[cache_key] = {
            "data": vulnerabilities,
            "timestamp": datetime.now(UTC),
        }
        # Mark as most-recently-used, then evict oldest entries past the cap.
        self.vulnerability_cache.move_to_end(cache_key)
        while len(self.vulnerability_cache) > self._cache_maxsize:
            self.vulnerability_cache.popitem(last=False)

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[Vulnerability]:
        """Remove duplicate rows, keyed by (id, package, version).

        An OSV advisory is NOT unique per ID: one record can list several
        affected packages (560 npm records do; one spans 42 packages), and an
        npm install can carry several versions of the same package. Keying on
        the ID alone kept whichever row came first, so the advisory was
        attributed to one package and the other affected package read as
        clean — a false negative on the package that needs the upgrade.
        Identical rows (same id, package and version) still collapse.
        """
        seen: set[tuple[str, str | None, str | None]] = set()
        unique_vulnerabilities = []

        for vuln in vulnerabilities:
            key = (vuln.id, vuln.package_name, vuln.package_version)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)

        return unique_vulnerabilities

    def _parse_osv_vulnerability(
        self, vuln_data: dict[str, Any], package_name: str | None = None
    ) -> Vulnerability | None:
        """Parse OSV vulnerability data into our Vulnerability model.

        Args:
            vuln_data: Raw vulnerability data from OSV.dev API
            package_name: The package being scanned. An advisory can affect
                several packages with different fixes; when given, only its
                ``affected`` entries for this package feed the version ranges.

        Returns:
            Parsed Vulnerability object or None if parsing fails
        """
        try:
            if not (vuln_id := vuln_data.get("id", "")):
                return None

            # Extract version ranges
            affected_versions, fixed_versions = self._extract_version_ranges(
                vuln_data, package_name=package_name
            )

            return Vulnerability(
                id=vuln_id,
                severity=self._extract_severity_from_osv(vuln_data),
                summary=vuln_data.get("summary", ""),
                details=vuln_data.get("details", ""),
                affected_versions=affected_versions,
                fixed_versions=fixed_versions,
                references=[
                    ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")
                ],
                published_date=vuln_data.get("published", ""),
                modified_date=vuln_data.get("modified", ""),
            )

        except (KeyError, ValueError, TypeError) as e:
            logger.warning("Failed to parse OSV vulnerability data: %s", e)
            return None

    def _extract_version_ranges(
        self, vuln_data: dict[str, Any], package_name: str | None = None
    ) -> tuple[list[str], list[str]]:
        """Extract affected and fixed versions from vulnerability data.

        With ``package_name``, only the ``affected`` entries naming that package
        count (all of them when none does), so another package's fix in a shared
        advisory is never reported as this package's fix.
        """
        affected_versions: list[str] = []
        fixed_versions: list[str] = []

        entries = vuln_data.get("affected", []) or []
        if package_name:
            wanted = self._normalize_pkg_name(package_name)
            own = [
                a
                for a in entries
                if self._normalize_pkg_name(str((a.get("package") or {}).get("name") or ""))
                == wanted
            ]
            entries = own or entries

        for affected in entries:
            for range_info in affected.get("ranges", []) or []:
                # Only version-space ranges carry installable versions. A GIT
                # range's events are commit hashes (PYSEC records ship one next
                # to the ECOSYSTEM range), and a hash in fixed_versions poisons
                # every downstream "upgrade to X" comparison.
                if range_info.get("type") not in _VERSION_RANGE_TYPES:
                    continue
                for event in range_info.get("events", []) or []:
                    if "introduced" in event:
                        affected_versions.append(event["introduced"])
                    elif "fixed" in event:
                        fixed_versions.append(event["fixed"])

        return affected_versions, fixed_versions

    # Qualitative severity labels OSV publishes under database_specific.severity.
    _SEVERITY_LABELS = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MODERATE",
        "MEDIUM": "MODERATE",
        "LOW": "LOW",
    }

    def _extract_severity_from_osv(self, vuln_data: dict[str, Any]) -> str:
        """Extract severity from OSV vulnerability data.

        Real OSV records carry severity two ways and BOTH must be handled or
        the most severe records get mis-scored (or, before this, dropped):
        - ``database_specific.severity`` — a qualitative label (GHSA records),
          which we trust as the published rating.
        - ``severity[].score`` — a **CVSS vector string** (e.g.
          ``CVSS:3.1/AV:N/...``), NOT a bare number. ``float()`` on a vector
          raises, which previously bubbled up and made ``_parse_osv_vulnerability``
          drop the whole record. We compute the base score from the vector.
        """
        # 1) Qualitative label, when present (GHSA).
        label = str(vuln_data.get("database_specific", {}).get("severity") or "").upper()
        if label in self._SEVERITY_LABELS:
            return self._SEVERITY_LABELS[label]

        # 2) CVSS metric(s): numeric score (legacy/api shape) or a vector string.
        best_score: float | None = None
        severity_info = vuln_data.get("severity", [])
        if isinstance(severity_info, list):
            for sev in severity_info:
                if not str(sev.get("type", "")).startswith("CVSS"):
                    continue
                score = sev.get("score")
                value: float | None = None
                if isinstance(score, int | float):
                    value = float(score)
                elif isinstance(score, str):
                    try:
                        value = float(score)
                    except ValueError:
                        value = self._cvss_vector_to_score(score)
                if value is not None:
                    best_score = value if best_score is None else max(best_score, value)

        if best_score is not None:
            return self._cvss_to_severity(best_score)

        return "UNKNOWN"

    @staticmethod
    def _cvss_vector_to_score(vector: str) -> float | None:
        """Compute a CVSS v3.0/3.1 base score from a vector string.

        Returns None for non-v3 vectors (e.g. CVSS:4.0) or malformed input —
        those records typically also carry a v3 entry or a qualitative label,
        so the caller falls back. The v3 base-score formula is deterministic.
        """
        if not vector.startswith("CVSS:3"):
            return None
        try:
            metrics = dict(
                part.split(":", 1)
                for part in vector.split("/")
                if ":" in part and not part.startswith("CVSS")
            )
        except ValueError:
            return None

        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
        ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
        ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
        scope_changed = metrics.get("S") == "C"
        pr_table = (
            {"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_table.get(metrics.get("PR", ""))
        impact_metric = {"H": 0.56, "L": 0.22, "N": 0.0}
        c = impact_metric.get(metrics.get("C", ""))
        i = impact_metric.get(metrics.get("I", ""))
        a = impact_metric.get(metrics.get("A", ""))
        if (
            av is None
            or ac is None
            or ui is None
            or pr is None
            or c is None
            or i is None
            or a is None
        ):
            return None

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
        # CVSS roundup: ceil to one decimal place; cap at 10.0.
        return min(math.ceil(raw * 10) / 10, 10.0)

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MODERATE"
        return "LOW"

    def clear_cache(self) -> None:
        """Clear the vulnerability cache."""
        self.vulnerability_cache.clear()
        logger.info("Vulnerability cache cleared")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        current_time = datetime.now(UTC)
        valid_entries = 0
        expired_entries = 0

        for cache_data in self.vulnerability_cache.values():
            cache_time = cache_data["timestamp"]
            if current_time - cache_time < self.cache_ttl:
                valid_entries += 1
            else:
                expired_entries += 1

        return {
            "total_entries": len(self.vulnerability_cache),
            "valid_entries": valid_entries,
            "expired_entries": expired_entries,
            "cache_hit_potential": f"{(valid_entries / max(1, len(self.vulnerability_cache))) * 100:.1f}%",
        }


class DependencyVisualizer:
    """Provides visualization utilities for dependency graphs and analysis results.

    Generates textual representations and data structures suitable for
    various visualization tools and reporting.
    """

    def __init__(self) -> None:
        """Initialize the dependency visualizer."""
        logger.info("DependencyVisualizer initialized")

    def generate_dependency_tree_text(
        self, packages: list[ExternalPackage], max_depth: int = 3
    ) -> str:
        """Generate a text-based tree representation of dependencies.

        Args:
            packages: List of packages to visualize
            max_depth: Maximum depth to display

        Returns:
            Text representation of the dependency tree
        """
        if not packages:
            return "No dependencies found."

        tree_lines = ["Dependency Tree:", "=" * 50]

        for package in packages[:20]:  # Limit to first 20 packages
            tree_lines.append(f"├── {package.name} ({package.version})")
            tree_lines.append(f"│   ├── Ecosystem: {package.ecosystem}")
            tree_lines.append(f"│   ├── License: {package.license or 'Unknown'}")
            if package.severity:
                tree_lines.append(f"│   └── Security: {package.severity}")
            tree_lines.append("│")

        if len(packages) > 20:
            tree_lines.append(f"... and {len(packages) - 20} more packages")

        return "\n".join(tree_lines)

    def generate_vulnerability_summary_text(self, vulnerabilities: list[Vulnerability]) -> str:
        """Generate a text summary of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Text summary of vulnerabilities
        """
        if not vulnerabilities:
            return "No vulnerabilities found."

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

        summary_lines = [
            "Vulnerability Summary:",
            "=" * 50,
            f"Total Vulnerabilities: {len(vulnerabilities)}",
            f"Critical: {severity_counts['CRITICAL']}",
            f"High: {severity_counts['HIGH']}",
            f"Moderate: {severity_counts['MODERATE']}",
            f"Low: {severity_counts['LOW']}",
            "",
            "Top Vulnerabilities:",
            "-" * 30,
        ]

        # Show top 10 vulnerabilities
        for i, vuln in enumerate(vulnerabilities[:10]):
            summary_lines.append(f"{i + 1}. {vuln.id} ({vuln.severity}) - {vuln.summary[:80]}...")

        return "\n".join(summary_lines)
