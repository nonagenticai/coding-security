"""Tests for DependencyVulnerabilityScanner (dependency_visualization.py)."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from models.architecture_models import Vulnerability
from models.package_manager_models import ExternalPackage
from services.dependency_visualization import (
    _CACHE_MAXSIZE,
    _OSV_MAX_RECORD_FETCHES_PER_SCAN,
    _OSV_RECORD_FETCH_CONCURRENCY,
    DependencyVulnerabilityScanner,
    PartialDependencyState,
)

# Public psf/requests fix commit from OSV PYSEC-2023-74 (a GIT range event, not a secret).
_REQUESTS_FIX_COMMIT = "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"  # pragma: allowlist secret


def make_package(
    name: str = "requests",
    version: str = "2.31.0",
    ecosystem: str = "pypi",
) -> ExternalPackage:
    return ExternalPackage(name=name, version=version, ecosystem=ecosystem)


def make_vuln(
    vuln_id: str = "GHSA-0001",
    severity: str = "HIGH",
    summary: str = "A vulnerability",
    package_name: str = "",
    package_version: str = "",
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary=summary,
        details="",
        affected_versions=[],
        fixed_versions=[],
        references=[],
        published_date="",
        modified_date="",
        package_name=package_name,
        package_version=package_version,
    )


@pytest.fixture
def scanner():
    return DependencyVulnerabilityScanner(
        timeout=5,
        enable_cache=True,
        cache_ttl_hours=1,
        batch_size=3,
    )


class TestScanVulnerabilities:
    async def test_empty_packages(self, scanner):
        result = await scanner.scan_vulnerabilities([])
        assert result == []

    async def test_cached_packages_skip_query(self, scanner):
        pkg = make_package(name="cached-pkg")
        cache_key = scanner._get_cache_key(pkg)
        scanner.vulnerability_cache[cache_key] = {
            "data": [make_vuln(vuln_id="cached-vuln")],
            "timestamp": datetime.now(UTC),
        }

        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = []
            result = await scanner.scan_vulnerabilities([pkg])

        assert len(result) == 1
        assert result[0].id == "cached-vuln"
        mock_query.assert_not_called()

    async def test_uncached_packages_queried(self, scanner):
        pkg = make_package(name="uncached-pkg")
        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_query:
            mock_query.return_value = [make_vuln(vuln_id="new-vuln")]
            result = await scanner.scan_vulnerabilities([pkg])

        assert len(result) == 1
        assert result[0].id == "new-vuln"
        mock_query.assert_called_once()


class TestQueryOsvBatched:
    async def test_correct_batching(self, scanner):
        # batch_size=3, so 5 packages => 2 batches
        packages = [make_package(name=f"pkg-{i}") for i in range(5)]

        with patch.object(scanner, "_query_single_batch", new_callable=AsyncMock) as mock_batch:
            mock_batch.return_value = []
            await scanner._query_osv_batched(packages)

        assert mock_batch.call_count == 2
        # First batch: 3 packages, second batch: 2 packages
        assert len(mock_batch.call_args_list[0][0][0]) == 3
        assert len(mock_batch.call_args_list[1][0][0]) == 2

    async def test_batch_error_handled(self, scanner):
        packages = [make_package(name="fail-pkg")]

        with patch.object(scanner, "_query_single_batch", new_callable=AsyncMock) as mock_batch:
            mock_batch.side_effect = RuntimeError("API down")
            # gather with return_exceptions=True should capture the exception
            result = await scanner._query_osv_batched(packages)

        assert result == []

    async def test_completed_batch_deposits_before_gather_cancels(self, scanner):
        """A finished batch deposits into the caller-held accumulator the instant
        it completes — BEFORE the outer gather returns — so a ``wait_for``
        cancellation still leaves the completed batch recorded. This is the basis
        for the runner's partial-findings-on-timeout recovery."""
        scanner.batch_size = 1  # one package per batch → independent completion
        fast_pkg = make_package(name="fast-pkg")
        slow_pkg = make_package(name="slow-pkg")

        async def fake_single_batch(batch):
            if batch[0].name == "fast-pkg":
                return [make_vuln(vuln_id="CVE-FAST")]
            await asyncio.sleep(10)  # never completes within the deadline
            return [make_vuln(vuln_id="CVE-SLOW")]

        partial = PartialDependencyState()
        with patch.object(scanner, "_query_single_batch", side_effect=fake_single_batch):
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await asyncio.wait_for(
                    scanner._query_osv_batched([fast_pkg, slow_pkg], partial=partial),
                    timeout=0.1,
                )

        ids = [v.id for v in partial.vulnerabilities]
        assert "CVE-FAST" in ids  # the finished batch survived the cancellation
        assert "CVE-SLOW" not in ids  # the hung batch deposited nothing


class TestParseOsvVulnerability:
    def test_correct_field_mapping(self, scanner):
        vuln_data = {
            "id": "GHSA-1234",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "severity": [{"type": "CVSS_V3", "score": "9.5"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0.0"},
                            ]
                        }
                    ]
                }
            ],
            "references": [{"url": "https://example.com"}],
            "published": "2024-01-01",
            "modified": "2024-01-15",
        }
        vuln = scanner._parse_osv_vulnerability(vuln_data)
        assert isinstance(vuln, Vulnerability), "Valid vuln data should parse to Vulnerability"
        assert vuln.id == "GHSA-1234"
        assert vuln.summary == "Test vulnerability"
        assert vuln.severity == "CRITICAL"  # 9.5 CVSS => CRITICAL
        assert "0" in vuln.affected_versions
        assert "2.0.0" in vuln.fixed_versions
        assert "https://example.com" in vuln.references

    def test_missing_id_returns_none(self, scanner):
        vuln = scanner._parse_osv_vulnerability({})
        assert vuln is None

    def test_unparseable_returns_none(self, scanner):
        vuln = scanner._parse_osv_vulnerability({"id": ""})
        assert vuln is None


class TestCacheOperations:
    def test_clear_cache(self, scanner):
        scanner.vulnerability_cache["key1"] = {"data": [], "timestamp": datetime.now(UTC)}
        scanner.clear_cache()
        assert len(scanner.vulnerability_cache) == 0

    def test_get_cache_stats_empty(self, scanner):
        stats = scanner.get_cache_stats()
        assert stats["total_entries"] == 0
        assert stats["valid_entries"] == 0
        assert stats["expired_entries"] == 0

    def test_get_cache_stats_with_entries(self, scanner):
        scanner.vulnerability_cache["valid"] = {
            "data": [],
            "timestamp": datetime.now(UTC),
        }
        scanner.vulnerability_cache["expired"] = {
            "data": [],
            "timestamp": datetime.now(UTC) - timedelta(hours=2),
        }
        stats = scanner.get_cache_stats()
        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 1
        assert stats["expired_entries"] == 1


class TestScanVulnerabilitiesExtended:
    """Extended tests for scan_vulnerabilities flow."""

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_empty_packages(self, scanner):
        """Empty package list returns empty vulnerability list immediately."""
        result = await scanner.scan_vulnerabilities([])
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_cache_hit(self, scanner):
        """Packages with valid cache entries are not queried via OSV."""
        pkg = make_package(name="cached-lib")
        cache_key = scanner._get_cache_key(pkg)
        cached_vuln = make_vuln(vuln_id="CACHED-001", severity="LOW")
        scanner.vulnerability_cache[cache_key] = {
            "data": [cached_vuln],
            "timestamp": datetime.now(UTC),
        }

        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_q:
            mock_q.return_value = []
            result = await scanner.scan_vulnerabilities([pkg])

        # Should get cached vuln without calling _query_osv_batched
        assert len(result) == 1
        assert result[0].id == "CACHED-001"
        mock_q.assert_not_called()

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_cache_miss_queries_osv(self, scanner):
        """Uncached packages trigger OSV batch query."""
        pkg = make_package(name="fresh-lib")

        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_q:
            osv_vuln = make_vuln(vuln_id="OSV-001", severity="HIGH")
            mock_q.return_value = [osv_vuln]
            result = await scanner.scan_vulnerabilities([pkg])

        assert len(result) == 1
        assert result[0].id == "OSV-001"
        mock_q.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities_multiple_ecosystems(self, scanner):
        """Packages from different ecosystems are scanned together."""
        pkgs = [
            make_package(name="pypi-pkg", ecosystem="pypi"),
            make_package(name="npm-pkg", ecosystem="npm"),
        ]

        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_q:
            mock_q.return_value = [
                make_vuln(vuln_id="V-PY", severity="HIGH"),
                make_vuln(vuln_id="V-NPM", severity="MODERATE"),
            ]
            result = await scanner.scan_vulnerabilities(pkgs)

        assert len(result) == 2
        vuln_ids = {v.id for v in result}
        assert "V-PY" in vuln_ids
        assert "V-NPM" in vuln_ids


class TestQueryOsvBatchedExtended:
    """Extended tests for _query_osv_batched partial failure handling."""

    @pytest.mark.asyncio
    async def test_query_osv_batched_partial_failure(self, scanner):
        """When one batch fails, results from other batches are still returned."""
        # batch_size=3, 6 packages => 2 batches
        packages = [make_package(name=f"pkg-{i}") for i in range(6)]

        call_count = 0

        async def side_effect(batch):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First batch succeeds
                return [make_vuln(vuln_id="BATCH1-V1")]
            else:
                # Second batch fails
                raise RuntimeError("Batch 2 network error")

        with patch.object(scanner, "_query_single_batch", new_callable=AsyncMock) as mock_batch:
            mock_batch.side_effect = side_effect
            result = await scanner._query_osv_batched(packages)

        # First batch returns 1 vuln, second batch raises (caught by gather)
        assert len(result) == 1
        assert result[0].id == "BATCH1-V1"


class TestSeparateCachedPackages:
    """Tests for _separate_cached_packages."""

    def test_separate_cached_packages_splits_correctly(self, scanner):
        """Cached and uncached packages are correctly separated."""
        cached_pkg = make_package(name="cached")
        uncached_pkg = make_package(name="uncached")

        cache_key = scanner._get_cache_key(cached_pkg)
        scanner.vulnerability_cache[cache_key] = {
            "data": [],
            "timestamp": datetime.now(UTC),
        }

        cached, uncached = scanner._separate_cached_packages([cached_pkg, uncached_pkg])
        assert len(cached) == 1
        assert cached[0].name == "cached"
        assert len(uncached) == 1
        assert uncached[0].name == "uncached"

    def test_cache_expired_entry_treated_as_miss(self, scanner):
        """Expired cache entries are treated as uncached and removed from cache."""
        pkg = make_package(name="expired-pkg")
        cache_key = scanner._get_cache_key(pkg)
        scanner.vulnerability_cache[cache_key] = {
            "data": [make_vuln(vuln_id="old-vuln")],
            "timestamp": datetime.now(UTC) - timedelta(hours=2),  # TTL is 1 hour
        }

        cached, uncached = scanner._separate_cached_packages([pkg])
        assert len(cached) == 0
        assert len(uncached) == 1
        assert uncached[0].name == "expired-pkg"
        # Expired entry should be removed from cache
        assert cache_key not in scanner.vulnerability_cache


class TestDeduplicateVulnerabilities:
    """Tests for _deduplicate_vulnerabilities."""

    def test_deduplicate_vulnerabilities_same_id(self, scanner):
        """Duplicate vulnerability IDs are removed, keeping the first occurrence."""
        vulns = [
            make_vuln(vuln_id="GHSA-DUP", severity="HIGH", summary="First"),
            make_vuln(vuln_id="GHSA-DUP", severity="HIGH", summary="Second"),
            make_vuln(vuln_id="GHSA-UNIQUE", severity="LOW", summary="Unique"),
        ]
        result = scanner._deduplicate_vulnerabilities(vulns)
        assert len(result) == 2
        ids = [v.id for v in result]
        assert ids == ["GHSA-DUP", "GHSA-UNIQUE"]
        # First occurrence is kept
        assert result[0].summary == "First"

    def test_deduplicate_keeps_one_row_per_affected_package(self, scanner):
        """An advisory that hits several packages must be reported for EACH one.

        Regression (2026-11-04): keying on the ID alone kept only the first
        package's row, so the second affected package read as clean. Measured
        live: astro + @astrojs/node sharing GHSA-xf8x-j4p2-f749 reported only
        astro.
        """
        vulns = [
            make_vuln(vuln_id="GHSA-SHARED", package_name="astro", package_version="5.13.0"),
            make_vuln(vuln_id="GHSA-SHARED", package_name="@astrojs/node", package_version="9.1.0"),
        ]
        result = scanner._deduplicate_vulnerabilities(vulns)
        assert [(v.package_name, v.id) for v in result] == [
            ("astro", "GHSA-SHARED"),
            ("@astrojs/node", "GHSA-SHARED"),
        ]

    def test_deduplicate_keeps_one_row_per_affected_version(self, scanner):
        """npm installs can carry two versions of one package; both rows stay."""
        vulns = [
            make_vuln(vuln_id="GHSA-V", package_name="lodash", package_version="4.17.20"),
            make_vuln(vuln_id="GHSA-V", package_name="lodash", package_version="4.17.21"),
        ]
        result = scanner._deduplicate_vulnerabilities(vulns)
        assert [v.package_version for v in result] == ["4.17.20", "4.17.21"]

    def test_deduplicate_empty_list(self, scanner):
        """Deduplicating an empty list returns an empty list."""
        result = scanner._deduplicate_vulnerabilities([])
        assert result == []

    def test_deduplicate_all_unique(self, scanner):
        """All unique IDs are preserved in order."""
        vulns = [
            make_vuln(vuln_id="A"),
            make_vuln(vuln_id="B"),
            make_vuln(vuln_id="C"),
        ]
        result = scanner._deduplicate_vulnerabilities(vulns)
        assert len(result) == 3
        assert [v.id for v in result] == ["A", "B", "C"]


class TestCacheDisabled:
    """Tests for scanner with cache disabled."""

    @pytest.fixture
    def no_cache_scanner(self):
        return DependencyVulnerabilityScanner(
            timeout=5,
            enable_cache=False,
            batch_size=3,
        )

    def test_separate_cached_packages_cache_disabled(self, no_cache_scanner):
        """When cache is disabled, all packages go to uncached."""
        pkgs = [make_package(name="a"), make_package(name="b")]
        cached, uncached = no_cache_scanner._separate_cached_packages(pkgs)
        assert len(cached) == 0
        assert len(uncached) == 2

    def test_cache_package_vulnerabilities_noop_when_disabled(self, no_cache_scanner):
        """Caching is a no-op when cache is disabled."""
        pkg = make_package(name="pkg")
        no_cache_scanner._cache_package_vulnerabilities(pkg, [make_vuln()], complete=True)
        assert len(no_cache_scanner.vulnerability_cache) == 0

    async def test_scan_all_uncached_when_disabled(self, no_cache_scanner):
        """With cache disabled, all packages are queried via batch."""
        pkgs = [make_package(name="x"), make_package(name="y")]
        with patch.object(no_cache_scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_q:
            mock_q.return_value = []
            await no_cache_scanner.scan_vulnerabilities(pkgs)
        mock_q.assert_called_once()


class TestCachePackageVulnerabilities:
    """Tests for _cache_package_vulnerabilities."""

    def test_caches_result_with_timestamp(self, scanner):
        """Caching stores data and a timestamp."""
        pkg = make_package(name="cached-test")
        vulns = [make_vuln(vuln_id="V1")]
        scanner._cache_package_vulnerabilities(pkg, vulns, complete=True)
        cache_key = scanner._get_cache_key(pkg)
        assert cache_key in scanner.vulnerability_cache
        entry = scanner.vulnerability_cache[cache_key]
        assert entry["data"] == vulns
        assert isinstance(entry["timestamp"], datetime)

    def test_cache_evicts_oldest_past_maxsize(self, scanner):
        """Inserting past _CACHE_MAXSIZE bounds the cache and evicts the oldest (LRU)."""
        first_pkg = make_package(name="pkg-000000")
        first_key = scanner._get_cache_key(first_pkg)
        scanner._cache_package_vulnerabilities(
            first_pkg, [make_vuln(vuln_id="first")], complete=True
        )

        for i in range(1, _CACHE_MAXSIZE + 50):
            pkg = make_package(name=f"pkg-{i:06d}")
            scanner._cache_package_vulnerabilities(
                pkg, [make_vuln(vuln_id=f"v-{i}")], complete=True
            )

        assert len(scanner.vulnerability_cache) == _CACHE_MAXSIZE
        # The very first (oldest) insertion has been evicted.
        assert first_key not in scanner.vulnerability_cache


class TestQuerySingleBatch:
    """Tests for _query_single_batch covering HTTP responses."""

    async def test_success_200_parses_vulns(self, scanner):
        """200 response parses vulnerabilities and caches them."""
        pkg = make_package(name="test-pkg")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-ABCD",
                            "summary": "Test vuln",
                            "details": "",
                            "affected": [],
                            "references": [],
                        }
                    ]
                }
            ]
        }

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            result = await scanner._query_single_batch([pkg])

        assert len(result) == 1
        assert result[0].id == "GHSA-ABCD"
        # Should also be cached
        cache_key = scanner._get_cache_key(pkg)
        assert cache_key in scanner.vulnerability_cache

    async def test_429_rate_limit_triggers_fallback(self, scanner):
        """429 response triggers individual fallback after sleep."""
        pkg = make_package(name="rate-limited")
        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            with patch.object(
                scanner, "_query_individual_fallback", new_callable=AsyncMock
            ) as mock_fallback:
                mock_fallback.return_value = [make_vuln(vuln_id="FALLBACK-V")]
                with patch(
                    "services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock
                ):
                    result = await scanner._query_single_batch([pkg])

        assert len(result) == 1
        assert result[0].id == "FALLBACK-V"
        mock_fallback.assert_called_once()

    async def test_non_200_status_returns_empty(self, scanner):
        """Non-200/429 status returns empty list."""
        pkg = make_package(name="server-error")
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            result = await scanner._query_single_batch([pkg])

        assert result == []

    async def test_timeout_returns_empty(self, scanner):
        """TimeoutError returns empty list."""
        pkg = make_package(name="timeout-pkg")

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=TimeoutError("timed out"))
            mock_cls.return_value = mock_client

            result = await scanner._query_single_batch([pkg])

        assert result == []

    async def test_generic_exception_triggers_fallback(self, scanner):
        """Generic exception triggers individual fallback."""
        pkg = make_package(name="error-pkg")

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=ConnectionError("refused"))
            mock_cls.return_value = mock_client

            with patch.object(
                scanner, "_query_individual_fallback", new_callable=AsyncMock
            ) as mock_fallback:
                mock_fallback.return_value = []
                result = await scanner._query_single_batch([pkg])

        assert result == []
        mock_fallback.assert_called_once()

    async def test_200_with_more_results_than_packages(self, scanner):
        """If API returns more results than packages, extras are skipped."""
        pkg = make_package(name="only-pkg")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"vulns": []},
                {
                    "vulns": [
                        {
                            "id": "EXTRA",
                            "summary": "extra",
                            "details": "",
                            "affected": [],
                            "references": [],
                        }
                    ]
                },
            ]
        }

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client

            result = await scanner._query_single_batch([pkg])

        # Second result should be skipped (i >= len(packages))
        assert len(result) == 0


class TestQueryIndividualFallback:
    """Tests for _query_individual_fallback."""

    async def test_success_path(self, scanner):
        """Individual fallback queries each package and returns vulns."""
        pkg = make_package(name="fb-pkg")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "FB-VULN-1",
                    "summary": "Fallback vuln",
                    "details": "",
                    "affected": [],
                    "references": [],
                }
            ]
        }

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client
            with patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock):
                result = await scanner._query_individual_fallback([pkg])

        assert len(result) == 1
        assert result[0].id == "FB-VULN-1"

    async def test_429_skips_package(self, scanner):
        """429 rate limit skips the package."""
        pkg = make_package(name="rate-pkg")
        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_client
            with patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock):
                result = await scanner._query_individual_fallback([pkg])

        assert result == []

    async def test_exception_per_package_continues(self, scanner):
        """Exception on one package doesn't stop processing others."""
        pkgs = [make_package(name="fail-pkg"), make_package(name="ok-pkg")]
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"vulns": []}

        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("parse error")
            return mock_200

        with patch("services.dependency_visualization.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=side_effect)
            mock_cls.return_value = mock_client
            with patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock):
                result = await scanner._query_individual_fallback(pkgs)

        # First package fails, second succeeds (with 0 vulns)
        assert result == []


class TestExtractVersionRanges:
    """Tests for _extract_version_ranges."""

    def test_extracts_introduced_and_fixed(self, scanner):
        """Extracts both introduced and fixed versions."""
        vuln_data = {
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.2.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.0"},
                            ]
                        }
                    ]
                }
            ]
        }
        affected, fixed = scanner._extract_version_ranges(vuln_data)
        assert affected == ["0", "2.0.0"]
        assert fixed == ["1.2.0", "2.1.0"]

    def test_no_affected_key(self, scanner):
        """Missing 'affected' key returns empty lists."""
        affected, fixed = scanner._extract_version_ranges({})
        assert affected == []
        assert fixed == []

    def test_multiple_affected_entries(self, scanner):
        """Multiple affected entries are all processed."""
        vuln_data = {
            "affected": [
                {"ranges": [{"events": [{"introduced": "1.0"}]}]},
                {"ranges": [{"events": [{"fixed": "3.0"}]}]},
            ]
        }
        affected, fixed = scanner._extract_version_ranges(vuln_data)
        assert "1.0" in affected
        assert "3.0" in fixed


class TestExtractSeverityFromOsv:
    """Tests for _extract_severity_from_osv."""

    def test_cvss_v3_score(self, scanner):
        """CVSS_V3 score is converted to severity."""
        data = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert scanner._extract_severity_from_osv(data) == "HIGH"

    def test_database_specific_severity(self, scanner):
        """Falls back to database_specific severity."""
        data = {"database_specific": {"severity": "moderate"}}
        assert scanner._extract_severity_from_osv(data) == "MODERATE"

    def test_database_specific_none_severity(self, scanner):
        """database_specific severity of None returns UNKNOWN."""
        data = {"database_specific": {"severity": None}}
        assert scanner._extract_severity_from_osv(data) == "UNKNOWN"

    def test_no_severity_returns_unknown(self, scanner):
        """No severity info returns UNKNOWN."""
        assert scanner._extract_severity_from_osv({}) == "UNKNOWN"

    def test_empty_severity_list(self, scanner):
        """Empty severity list falls through to UNKNOWN."""
        data = {"severity": []}
        assert scanner._extract_severity_from_osv(data) == "UNKNOWN"

    def test_non_cvss_v3_type_skipped(self, scanner):
        """Non-CVSS_V3 types in severity list are skipped."""
        data = {"severity": [{"type": "OTHER", "score": "9.0"}]}
        assert scanner._extract_severity_from_osv(data) == "UNKNOWN"


class TestCvssToSeverity:
    """Tests for _cvss_to_severity score boundaries."""

    def test_critical_score(self, scanner):
        assert scanner._cvss_to_severity(9.0) == "CRITICAL"
        assert scanner._cvss_to_severity(10.0) == "CRITICAL"

    def test_high_score(self, scanner):
        assert scanner._cvss_to_severity(7.0) == "HIGH"
        assert scanner._cvss_to_severity(8.9) == "HIGH"

    def test_moderate_score(self, scanner):
        assert scanner._cvss_to_severity(4.0) == "MODERATE"
        assert scanner._cvss_to_severity(6.9) == "MODERATE"

    def test_low_score(self, scanner):
        assert scanner._cvss_to_severity(0.0) == "LOW"
        assert scanner._cvss_to_severity(3.9) == "LOW"


class TestDependencyVisualizer:
    """Tests for DependencyVisualizer class."""

    @pytest.fixture
    def visualizer(self):
        from services.dependency_visualization import DependencyVisualizer

        return DependencyVisualizer()

    def test_empty_packages_tree(self, visualizer):
        """Empty package list returns 'No dependencies found.'"""
        result = visualizer.generate_dependency_tree_text([])
        assert result == "No dependencies found."

    def test_single_package_tree(self, visualizer):
        """Single package generates correct tree output."""
        pkg = make_package(name="fastapi", version="0.115.0")
        result = visualizer.generate_dependency_tree_text([pkg])
        assert "fastapi" in result
        assert "0.115.0" in result
        assert "Dependency Tree:" in result

    def test_package_with_severity(self, visualizer):
        """Package with severity shows security info."""
        pkg = ExternalPackage(name="django", version="4.2.0", ecosystem="pypi", severity="HIGH")
        result = visualizer.generate_dependency_tree_text([pkg])
        assert "Security: HIGH" in result

    def test_package_with_license(self, visualizer):
        """Package with license shows license info."""
        pkg = ExternalPackage(name="fastapi", version="0.115.0", ecosystem="pypi", license="MIT")
        result = visualizer.generate_dependency_tree_text([pkg])
        assert "License: MIT" in result

    def test_package_without_license(self, visualizer):
        """Package without license shows 'Unknown'."""
        pkg = make_package(name="nolicense")
        result = visualizer.generate_dependency_tree_text([pkg])
        assert "License: Unknown" in result

    def test_more_than_20_packages_truncated(self, visualizer):
        """More than 20 packages shows truncation message."""
        pkgs = [make_package(name=f"pkg-{i}") for i in range(25)]
        result = visualizer.generate_dependency_tree_text(pkgs)
        assert "... and 5 more packages" in result

    def test_exactly_20_packages_no_truncation(self, visualizer):
        """Exactly 20 packages does not show truncation."""
        pkgs = [make_package(name=f"pkg-{i}") for i in range(20)]
        result = visualizer.generate_dependency_tree_text(pkgs)
        assert "... and" not in result

    def test_empty_vulnerabilities_summary(self, visualizer):
        """Empty vulnerabilities returns 'No vulnerabilities found.'"""
        result = visualizer.generate_vulnerability_summary_text([])
        assert result == "No vulnerabilities found."

    def test_vulnerability_summary_counts(self, visualizer):
        """Vulnerability summary counts severities correctly."""
        vulns = [
            make_vuln(vuln_id="V1", severity="CRITICAL"),
            make_vuln(vuln_id="V2", severity="HIGH"),
            make_vuln(vuln_id="V3", severity="HIGH"),
            make_vuln(vuln_id="V4", severity="MODERATE"),
            make_vuln(vuln_id="V5", severity="LOW"),
        ]
        result = visualizer.generate_vulnerability_summary_text(vulns)
        assert "Total Vulnerabilities: 5" in result
        assert "Critical: 1" in result
        assert "High: 2" in result
        assert "Moderate: 1" in result
        assert "Low: 1" in result
        assert "Vulnerability Summary:" in result

    def test_vulnerability_summary_lists_top_10(self, visualizer):
        """Summary lists up to 10 vulnerabilities."""
        vulns = [make_vuln(vuln_id=f"V-{i}", summary=f"Vuln {i} description") for i in range(15)]
        result = visualizer.generate_vulnerability_summary_text(vulns)
        # Should show first 10
        assert "1. V-0" in result
        assert "10. V-9" in result
        # Should not show 11th
        assert "11." not in result

    def test_vulnerability_summary_unknown_severity_not_counted(self, visualizer):
        """Vulnerabilities with non-standard severity are not counted in known buckets."""
        vulns = [make_vuln(vuln_id="V-UNK", severity="UNKNOWN")]
        result = visualizer.generate_vulnerability_summary_text(vulns)
        assert "Total Vulnerabilities: 1" in result
        assert "Critical: 0" in result
        assert "High: 0" in result


class TestGetCacheKey:
    """Tests for _get_cache_key determinism."""

    def test_same_package_same_key(self, scanner):
        """Same package data produces same cache key."""
        pkg1 = make_package(name="x", version="1.0", ecosystem="pypi")
        pkg2 = make_package(name="x", version="1.0", ecosystem="pypi")
        assert scanner._get_cache_key(pkg1) == scanner._get_cache_key(pkg2)

    def test_different_version_different_key(self, scanner):
        """Different versions produce different cache keys."""
        pkg1 = make_package(name="x", version="1.0")
        pkg2 = make_package(name="x", version="2.0")
        assert scanner._get_cache_key(pkg1) != scanner._get_cache_key(pkg2)

    def test_different_ecosystem_different_key(self, scanner):
        """Different ecosystems produce different cache keys."""
        pkg1 = make_package(name="x", ecosystem="pypi")
        pkg2 = make_package(name="x", ecosystem="npm")
        assert scanner._get_cache_key(pkg1) != scanner._get_cache_key(pkg2)


class TestGetCacheStatsHitPotential:
    """Tests for get_cache_stats cache_hit_potential calculation."""

    def test_all_valid(self, scanner):
        """100% hit potential when all entries are valid."""
        scanner.vulnerability_cache["a"] = {
            "data": [],
            "timestamp": datetime.now(UTC),
        }
        scanner.vulnerability_cache["b"] = {
            "data": [],
            "timestamp": datetime.now(UTC),
        }
        stats = scanner.get_cache_stats()
        assert stats["cache_hit_potential"] == "100.0%"

    def test_all_expired(self, scanner):
        """0% hit potential when all entries are expired."""
        scanner.vulnerability_cache["a"] = {
            "data": [],
            "timestamp": datetime.now(UTC) - timedelta(hours=10),
        }
        stats = scanner.get_cache_stats()
        assert stats["cache_hit_potential"] == "0.0%"


def _osv_record(
    vuln_id: str = "CVE-2024-33663",
    name: str = "python-jose",
    introduced: str = "0",
    fixed: str | None = "3.4.0",
    cvss: str = "7.5",
    *,
    versions: list[str] | None = None,
    withdrawn: bool = False,
) -> dict:
    """A minimal OSV record in the shape the offline DB stores."""
    affected: dict = {"package": {"ecosystem": "PyPI", "name": name}}
    if versions is not None:
        # Enumerated-versions record (no range).
        affected["versions"] = versions
    else:
        events: list[dict] = [{"introduced": introduced}]
        if fixed is not None:
            events.append({"fixed": fixed})
        affected["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    record: dict = {
        "id": vuln_id,
        "summary": f"Vulnerability in {name}",
        "details": "",
        "severity": [{"type": "CVSS_V3", "score": cvss}],
        "affected": [affected],
        "references": [],
        "published": "",
        "modified": "",
    }
    if withdrawn:
        record["withdrawn"] = "2024-01-01T00:00:00Z"
    return record


def _write_db(tmp_path, name: str, records: list[dict], ecosystem: str = "PyPI"):
    import json

    eco_dir = tmp_path / ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)
    (eco_dir / f"{name}.json").write_text(json.dumps(records))
    return tmp_path


def _offline_scanner(tmp_path):
    return DependencyVulnerabilityScanner(
        timeout=5, enable_cache=False, offline_db_dir=str(tmp_path)
    )


class TestOfflineScan:
    """Offline, version-aware OSV scanning from a baked per-package DB (E3.19)."""

    async def test_baseline_high_for_vulnerable_pin(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")])
        assert len(result) == 1
        assert result[0].severity == "HIGH"
        assert result[0].package_name == "python-jose"
        assert "3.4.0" in result[0].fixed_versions

    async def test_drops_to_zero_after_upgrade(self, tmp_path):
        """The delta proof: the patched version reports nothing (version-aware)."""
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities([make_package("python-jose", "3.4.0")])
        assert result == []

    async def test_version_boundaries(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        # Just below the fix → still affected.
        assert len(await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.9")])) == 1
        # Above the fix → clear.
        assert await scanner.scan_vulnerabilities([make_package("python-jose", "3.5.0")]) == []

    async def test_summary_maps_high_count(self, tmp_path):
        """Offline result flows into the byte-identical summary fields."""
        from services.dependency_analysis import DependencyAnalyzer

        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        analyzer = DependencyAnalyzer()

        pkg_vuln = make_package("python-jose", "3.3.0")
        vulns = await scanner.scan_vulnerabilities([pkg_vuln])
        summary = analyzer.generate_summary([pkg_vuln], vulns)
        assert summary.high_vulnerabilities == 1
        assert summary.total_vulnerabilities == 1
        assert summary.vulnerable_packages == 1

        pkg_fixed = make_package("python-jose", "3.4.0")
        vulns_fixed = await scanner.scan_vulnerabilities([pkg_fixed])
        summary_fixed = analyzer.generate_summary([pkg_fixed], vulns_fixed)
        assert summary_fixed.high_vulnerabilities == 0

    async def test_missing_record_file_returns_empty(self, tmp_path):
        (tmp_path / "PyPI").mkdir()
        scanner = _offline_scanner(tmp_path)
        assert await scanner.scan_vulnerabilities([make_package("not-in-db", "1.0.0")]) == []

    async def test_withdrawn_excluded(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record(withdrawn=True)])
        scanner = _offline_scanner(tmp_path)
        assert await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")]) == []

    async def test_explicit_versions_list(self, tmp_path):
        rec = _osv_record(fixed=None, versions=["3.3.0"])
        _write_db(tmp_path, "python-jose", [rec])
        scanner = _offline_scanner(tmp_path)
        assert len(await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")])) == 1
        assert await scanner.scan_vulnerabilities([make_package("python-jose", "9.9.9")]) == []

    async def test_malformed_json_skipped(self, tmp_path):
        eco = tmp_path / "PyPI"
        eco.mkdir()
        (eco / "python-jose.json").write_text("{not valid json")
        scanner = _offline_scanner(tmp_path)
        # No raise, just empty.
        assert await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")]) == []

    async def test_unpinned_version_conservative_include(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities([make_package("python-jose", "*")])
        assert len(result) == 1

    async def test_name_and_ecosystem_normalization(self, tmp_path):
        """Underscores/case in the requested name resolve to the dash DB file."""
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities([make_package("Python_Jose", "3.3.0", "pypi")])
        assert len(result) == 1

    async def test_scoped_npm_name_resolves_to_the_builder_filename(self, tmp_path):
        """``@scope/pkg`` is baked as ``@scope_pkg.json``; the lookup must match.

        Regression (2026-11-04): only ``normalize_name`` was mirrored, so a
        scoped package looked up ``npm/@scope/pkg.json`` — a nested path that
        never exists — and every scoped package silently read as clean instead
        of being checked.
        """
        record = _osv_record(name="@axe-core/playwright")
        record["affected"][0]["package"]["ecosystem"] = "npm"
        _write_db(tmp_path, "@axe-core_playwright", [record], ecosystem="npm")
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities(
            [make_package("@axe-core/playwright", "1.0.0", "npm")]
        )
        assert [v.package_name for v in result] == ["@axe-core/playwright"]
        assert scanner.lookup_errors == []

    async def test_unknown_ecosystem_is_unchecked_not_clean(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = _offline_scanner(tmp_path)
        result = await scanner.scan_vulnerabilities(
            [make_package("python-jose", "3.3.0", "unknown-eco")]
        )
        assert result == []
        # No DB for the ecosystem => the package was never checked: degraded.
        assert scanner.lookup_errors == [
            "no offline OSV DB for ecosystem 'unknown-eco': 1 package(s) unchecked (python-jose)"
        ]

    async def test_offline_disabled_by_default_uses_online(self, monkeypatch):
        """No offline dir + no env → the online OSV path is taken (zero regression)."""
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)
        scanner = DependencyVulnerabilityScanner(timeout=5, enable_cache=False)
        assert scanner._offline_db_dir is None
        with patch.object(scanner, "_query_osv_batched", new_callable=AsyncMock) as mock_q:
            mock_q.return_value = []
            await scanner.scan_vulnerabilities([make_package("requests", "2.31.0")])
            mock_q.assert_called_once()

    async def test_env_enables_offline(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(tmp_path))
        _write_db(tmp_path, "python-jose", [_osv_record()])
        scanner = DependencyVulnerabilityScanner(timeout=5, enable_cache=False)
        assert scanner._offline_db_dir == str(tmp_path)
        result = await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")])
        assert len(result) == 1


class TestSeverityFromRealOsvShapes:
    """Real OSV records store CVSS as a VECTOR string or a qualitative label,
    not a bare number — both must score correctly and never drop the record."""

    @pytest.fixture
    def s(self):
        return DependencyVulnerabilityScanner(timeout=5, enable_cache=False)

    def test_database_specific_label_preferred(self, s):
        rec = {
            "id": "GHSA-x",
            "database_specific": {"severity": "CRITICAL"},
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}
            ],
        }
        assert s._extract_severity_from_osv(rec) == "CRITICAL"

    def test_medium_label_maps_to_moderate(self, s):
        assert (
            s._extract_severity_from_osv({"database_specific": {"severity": "MEDIUM"}})
            == "MODERATE"
        )

    def test_cvss_v3_vector_scored(self, s):
        # AV:N/AC:H/.../C:H/I:H/A:N (scope unchanged) -> base 7.4 -> HIGH.
        rec = {
            "id": "PYSEC-x",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}
            ],
        }
        assert s._extract_severity_from_osv(rec) == "HIGH"

    def test_cvss_v3_full_impact_is_critical(self, s):
        rec = {
            "id": "x",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
        assert s._extract_severity_from_osv(rec) == "CRITICAL"

    def test_cvss_v4_only_falls_back_to_unknown(self, s):
        # v4 vector alone is not scored here; no label -> UNKNOWN (caller-safe).
        rec = {
            "id": "x",
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                }
            ],
        }
        assert s._extract_severity_from_osv(rec) == "UNKNOWN"

    def test_numeric_score_still_supported(self, s):
        rec = {"id": "x", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert s._extract_severity_from_osv(rec) == "CRITICAL"

    def test_no_severity_is_unknown(self, s):
        assert s._extract_severity_from_osv({"id": "x", "severity": None}) == "UNKNOWN"

    def test_vector_record_not_dropped(self, s):
        # Regression: a CVSS-vector record must parse (previously float() raised
        # -> _parse_osv_vulnerability returned None -> the HIGH record vanished).
        rec = {
            "id": "GHSA-y",
            "summary": "x",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [],
        }
        vuln = s._parse_osv_vulnerability(rec)
        assert vuln is not None
        assert vuln.severity == "CRITICAL"

    def test_malformed_vector_returns_none(self, s):
        assert s._cvss_vector_to_score("CVSS:3.1/garbage") is None
        assert s._cvss_vector_to_score("not-a-vector") is None

    async def test_offline_scan_buckets_high_crit_from_vectors(self, tmp_path):
        """End-to-end: a vector-only record produces a HIGH+ count offline."""
        rec = {
            "id": "PYSEC-z",
            "summary": "Vulnerability in python-jose",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "python-jose"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.4.0"}]}
                    ],
                }
            ],
        }
        _write_db(tmp_path, "python-jose", [rec])
        scanner = DependencyVulnerabilityScanner(
            timeout=5, enable_cache=False, offline_db_dir=str(tmp_path)
        )
        vulns = await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0")])
        assert len(vulns) == 1
        assert vulns[0].severity == "CRITICAL"
        # Patched version clears it -> the delta gate sees high+crit drop to 0.
        assert await scanner.scan_vulnerabilities([make_package("python-jose", "3.4.0")]) == []


def _client_mock(post=None, get=None):
    """An httpx.AsyncClient stand-in usable as ``async with``."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    if post is not None:
        client.post = post
    if get is not None:
        client.get = get
    return client


def _resp(status: int, body=None):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = body
    return response


class TestLookupErrorsAreRecorded:
    """A fail-soft lookup must leave a trace in ``lookup_errors`` (coding-security#103)."""

    async def test_failed_batch_is_recorded(self, scanner):
        with patch.object(scanner, "_query_single_batch", new_callable=AsyncMock) as mock_batch:
            mock_batch.side_effect = RuntimeError("API down")
            await scanner._query_osv_batched([make_package(name="fail-pkg")])
        assert scanner.lookup_errors and "API down" in scanner.lookup_errors[0]

    async def test_non_200_batch_status_is_recorded(self, scanner):
        client = _client_mock(post=AsyncMock(return_value=_resp(500)))
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            await scanner._query_single_batch([make_package(name="server-error")])
        assert scanner.lookup_errors == ["batch of 1: OSV status 500"]

    async def test_non_200_individual_status_is_recorded(self, scanner):
        client = _client_mock(post=AsyncMock(return_value=_resp(503)))
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            await scanner._query_individual_fallback([make_package(name="pkg-a")])
        assert scanner.lookup_errors == ["pkg-a: OSV status 503"]

    async def test_individual_429_is_recorded(self, scanner):
        client = _client_mock(post=AsyncMock(return_value=_resp(429)))
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            await scanner._query_individual_fallback([make_package(name="pkg-a")])
        assert scanner.lookup_errors == ["pkg-a: OSV rate-limited (429)"]


class TestOsvEcosystemName:
    async def test_individual_query_sends_the_canonical_ecosystem(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"vulns": []}))
        client = _client_mock(post=post)
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            await scanner._query_individual_fallback([make_package(ecosystem="pypi")])
        assert post.call_args.kwargs["json"]["package"]["ecosystem"] == "PyPI"

    async def test_batch_query_sends_the_canonical_ecosystem(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"results": [{}, {}]}))
        client = _client_mock(post=post)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            await scanner._query_single_batch(
                [make_package(ecosystem="pypi"), make_package(name="left-pad", ecosystem="npm")]
            )
        queries = post.call_args.kwargs["json"]["queries"]
        assert [q["package"]["ecosystem"] for q in queries] == ["PyPI", "npm"]


_FULL = {
    "id": "GHSA-full-0001",
    "summary": "",
    "details": "",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}],
        }
    ],
    "references": [],
    "modified": "2026-01-01T00:00:00Z",
}
_STUB = {"id": "GHSA-full-0001", "modified": "2026-01-01T00:00:00Z"}


class TestRecordHydration:
    """querybatch returns {id, modified}; the full record comes from GET /v1/vulns/{id}."""

    async def test_stub_is_hydrated_once_across_batches(self, scanner):
        scanner.batch_size = 1  # two packages -> two concurrent batches, same advisory
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": [_STUB]}]}))
        get = AsyncMock(return_value=_resp(200, _FULL))
        client = _client_mock(post=post, get=get)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities(
                [make_package(name="requests"), make_package(name="requests-extra")]
            )
        assert get.call_count == 1
        assert get.call_args.args[0] == "https://api.osv.dev/v1/vulns/GHSA-full-0001"
        assert vulns[0].severity == "CRITICAL"
        assert vulns[0].fixed_versions == ["9.9"]
        assert scanner.lookup_errors == []

    async def test_failed_fetch_records_unknown_no_fix_and_is_not_cached(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": [_STUB]}]}))
        get = AsyncMock(side_effect=httpx.ReadTimeout("osv slow"))
        client = _client_mock(post=post, get=get)
        pkg = make_package(name="requests")
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([pkg])
        assert [(v.id, v.severity, v.fixed_versions) for v in vulns] == [
            ("GHSA-full-0001", "UNKNOWN", [])
        ]
        assert scanner.lookup_errors and "GHSA-full-0001" in scanner.lookup_errors[0]
        # An incomplete result must not replay as a clean cache hit next scan.
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache

    async def test_paginated_result_is_recorded(self, scanner):
        post = AsyncMock(
            return_value=_resp(200, {"results": [{"vulns": [_FULL], "next_page_token": "x"}]})
        )
        client = _client_mock(post=post)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            await scanner.scan_vulnerabilities([make_package(name="requests")])
        assert scanner.lookup_errors == ["requests: OSV results paginated (not followed)"]


class TestPerPackageFixedVersions:
    def test_only_the_named_packages_ranges_count(self, scanner):
        record = {
            "id": "GHSA-x",
            "affected": [
                {
                    "package": {"name": "Alpha_Pkg"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.5"}]}],
                },
                {
                    "package": {"name": "beta"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.5"}]}],
                },
            ],
        }
        vuln = scanner._parse_osv_vulnerability(record, package_name="alpha-pkg")
        assert vuln is not None
        assert vuln.fixed_versions == ["1.5"]


# PYSEC-2023-74 (requests, CVE-2023-32681) as OSV publishes it: a GIT range whose
# "fixed" event is a COMMIT HASH, next to the ECOSYSTEM range with the version.
_PYSEC_2023_74 = {
    "id": "PYSEC-2023-74",
    "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
    "details": "Requests is a HTTP library. Since Requests 2.3.0, ...",
    "affected": [
        {
            "package": {
                "ecosystem": "PyPI",
                "name": "requests",
                "purl": "pkg:pypi/requests",
            },
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/psf/requests",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": _REQUESTS_FIX_COMMIT},
                    ],
                },
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}],
                },
            ],
            "versions": ["2.3.0", "2.30.0"],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://github.com/psf/requests/security"}],
    "published": "2023-05-26T18:15:00Z",
    "modified": "2023-06-05T01:13:00Z",
}


class TestGitRangesAreNotVersions:
    """A GIT range's events are commit hashes; they must never reach fixed_versions."""

    def test_pysec_git_range_hash_is_not_a_fixed_version(self, scanner):
        vuln = scanner._parse_osv_vulnerability(_PYSEC_2023_74, package_name="requests")
        assert vuln is not None
        assert vuln.fixed_versions == ["2.31.0"]
        assert vuln.affected_versions == ["2.3.0"]

    async def test_pysec_package_fix_union_is_the_version(self, tmp_path):
        from services.dependency_analyzer import attach_vulnerabilities

        _write_db(tmp_path, "requests", [_PYSEC_2023_74])
        scanner = _offline_scanner(tmp_path)
        pkg = make_package("requests", "2.30.0")
        await scanner.scan_vulnerabilities([pkg])
        assert scanner.lookup_errors == []
        [enriched] = attach_vulnerabilities([pkg], scanner.package_vulnerabilities)
        assert enriched.fixed_versions == ["2.31.0"]


class TestOfflineUncoveredEcosystem:
    """Prod bakes only the PyPI DB: an npm package is UNCHECKED, never clean."""

    async def test_npm_without_a_db_is_degraded_and_named(self, tmp_path):
        _write_db(tmp_path, "python-jose", [_osv_record()])  # PyPI only
        scanner = DependencyVulnerabilityScanner(
            timeout=5, enable_cache=True, offline_db_dir=str(tmp_path)
        )
        npm_pkg = make_package("left-pad", "1.3.0", "npm")
        result = await scanner.scan_vulnerabilities([make_package("python-jose", "3.3.0"), npm_pkg])
        # The covered ecosystem still reports its finding...
        assert [v.package_name for v in result] == ["python-jose"]
        # ...and the uncovered one makes the scan degraded, naming the ecosystem.
        assert scanner.lookup_errors == [
            "no offline OSV DB for ecosystem 'npm': 1 package(s) unchecked (left-pad)"
        ]
        # An unchecked package must not replay as a clean cache hit.
        assert scanner._get_cache_key(npm_pkg) not in scanner.vulnerability_cache


def _stub_ids(n: int) -> list[dict]:
    return [{"id": f"GHSA-fan-{i:04d}", "modified": "2026-01-01T00:00:00Z"} for i in range(n)]


def _full_record(vuln_id: str) -> dict:
    return {**_FULL, "id": vuln_id}


class TestRecordFetchFanOut:
    """GET /v1/vulns/{id} fan-out: bounded concurrency, capped ids, total time budget."""

    async def test_concurrency_is_exactly_the_bound(self, scanner):
        ids = _stub_ids(3 * _OSV_RECORD_FETCH_CONCURRENCY)
        in_flight = 0
        peak = 0

        async def get(url, **kwargs):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return _resp(200, _full_record(url.rsplit("/", 1)[-1]))

        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": ids}]}))
        client = _client_mock(post=post, get=get)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([make_package(name="requests")])
        assert _OSV_RECORD_FETCH_CONCURRENCY == 8
        # Not 1 (serial) and not len(ids) (unbounded).
        assert peak == 8
        assert len(vulns) == len(ids)
        assert scanner.lookup_errors == []

    def test_default_cap_is_the_named_constant(self):
        assert _OSV_MAX_RECORD_FETCHES_PER_SCAN == 500
        assert DependencyVulnerabilityScanner().max_record_fetches == 500

    async def test_id_cap_marks_degraded_not_truncated(self, scanner):
        scanner.max_record_fetches = 3
        ids = _stub_ids(5)
        get = AsyncMock(
            side_effect=lambda url, **kw: _resp(200, _full_record(url.rsplit("/", 1)[-1]))
        )
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": ids}]}))
        client = _client_mock(post=post, get=get)
        pkg = make_package(name="requests")
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([pkg])
        assert get.call_count == 3
        # Every advisory is still reported (the 2 over the cap as UNKNOWN stubs)...
        assert len(vulns) == 5
        assert sorted(v.severity for v in vulns) == ["CRITICAL"] * 3 + ["UNKNOWN"] * 2
        # ...and the scan reads degraded, once, and is not cached.
        assert len(scanner.lookup_errors) == 1
        assert "cap of 3 distinct ids" in scanner.lookup_errors[0]
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache

    async def test_time_budget_marks_degraded_not_truncated(self, scanner):
        scanner.record_fetch_budget_seconds = 0.05

        async def get(url, **kwargs):
            await asyncio.sleep(5)
            return _resp(200, _full_record(url.rsplit("/", 1)[-1]))

        ids = _stub_ids(12)
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": ids}]}))
        client = _client_mock(post=post, get=get)
        pkg = make_package(name="requests")
        loop = asyncio.get_running_loop()
        started = loop.time()
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([pkg])
        assert loop.time() - started < 2
        assert [v.severity for v in vulns] == ["UNKNOWN"] * 12
        assert len(scanner.lookup_errors) == 1
        assert "budget of 0.05s" in scanner.lookup_errors[0]
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache

    async def test_a_get_timeout_is_a_per_id_error_not_the_budget(self, scanner):
        get = AsyncMock(side_effect=TimeoutError("read timed out"))
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": [_STUB]}]}))
        client = _client_mock(post=post, get=get)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            await scanner.scan_vulnerabilities([make_package(name="requests")])
        assert scanner.lookup_errors == [
            "GHSA-full-0001: OSV record fetch failed: timeout: read timed out"
        ]


class TestIncompleteResultsAreNeverCached:
    """Every lookup path: an incomplete result must not replay as a clean cache hit."""

    async def _individual(self, scanner, pkg, *, get, body):
        client = _client_mock(post=AsyncMock(return_value=_resp(200, body)), get=get)
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            return await scanner._query_individual_fallback([pkg])

    async def test_individual_path_caches_a_complete_result(self, scanner):
        """Positive control: the path CAN cache, so the negatives below mean something."""
        pkg = make_package(name="requests")
        await self._individual(
            scanner, pkg, get=AsyncMock(return_value=_resp(200, _FULL)), body={"vulns": [_STUB]}
        )
        assert scanner.lookup_errors == []
        assert scanner._get_cache_key(pkg) in scanner.vulnerability_cache

    async def test_individual_path_failed_fetch_is_not_cached(self, scanner):
        pkg = make_package(name="requests")
        vulns = await self._individual(
            scanner,
            pkg,
            get=AsyncMock(return_value=_resp(502)),
            body={"vulns": [_STUB]},
        )
        assert [v.severity for v in vulns] == ["UNKNOWN"]
        assert scanner.lookup_errors == ["GHSA-full-0001: OSV record fetch status 502"]
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache

    async def test_individual_path_paginated_result_is_not_cached(self, scanner):
        pkg = make_package(name="requests")
        await self._individual(
            scanner, pkg, get=None, body={"vulns": [_FULL], "next_page_token": "x"}
        )
        assert scanner.lookup_errors == ["requests: OSV results paginated (not followed)"]
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache

    def test_cache_write_refuses_an_incomplete_result(self, scanner):
        pkg = make_package(name="requests")
        scanner._cache_package_vulnerabilities(pkg, [], complete=False)
        assert scanner._get_cache_key(pkg) not in scanner.vulnerability_cache


def _ranged(name: str, events: list[dict], vuln_id: str = "GHSA-r") -> dict:
    return {
        "id": vuln_id,
        "summary": "",
        "details": "",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        "references": [],
    }


# The live false positives on openplanner (2026-11-04), ranges as OSV publishes them.
_CRYPTOGRAPHY_GHSA_X4QR = _ranged(
    "cryptography", [{"introduced": "0.8.1"}, {"fixed": "39.0.1"}], "GHSA-x4qr-2fvf-3mr5"
)
# The real record also names openssl-src, whose range [0, 111.25.0) WOULD contain
# 50.0.2: only this package's entries may decide the verdict.
_CRYPTOGRAPHY_GHSA_X4QR["affected"].append(
    {
        "package": {"ecosystem": "crates.io", "name": "openssl-src"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "111.25.0"}]}],
    }
)
_PYJWT_PYSEC_2026_4146 = _ranged(
    "pyjwt", [{"introduced": "2.11.0"}, {"last_affected": "2.13.0"}], "PYSEC-2026-4146"
)
_PYJWT_PYSEC_2025_183 = _ranged(
    "pyjwt", [{"introduced": "0"}, {"last_affected": "2.10.1"}], "PYSEC-2025-183"
)


class TestRangeEvents:
    """OSV range events: introduced / fixed / last_affected / limit."""

    @pytest.mark.parametrize(
        ("record", "version", "affected"),
        [
            (_CRYPTOGRAPHY_GHSA_X4QR, "50.0.2", False),
            (_CRYPTOGRAPHY_GHSA_X4QR, "39.0.1", False),
            (_CRYPTOGRAPHY_GHSA_X4QR, "39.0.0", True),
            (_PYJWT_PYSEC_2026_4146, "2.15.1", False),
            (_PYJWT_PYSEC_2026_4146, "2.13.0", True),  # last_affected is inclusive
            (_PYJWT_PYSEC_2026_4146, "2.12.1", True),
            (_PYJWT_PYSEC_2026_4146, "2.10.0", False),
            (_PYJWT_PYSEC_2025_183, "2.15.1", False),
            (_PYJWT_PYSEC_2025_183, "2.10.1", True),
            (_PYJWT_PYSEC_2025_183, "1.7.0", True),
        ],
    )
    def test_live_false_positive_ranges(self, scanner, record, version, affected):
        name = record["affected"][0]["package"]["name"]
        assert scanner._affects_installed_version(record, version, package_name=name) is affected

    def test_without_scoping_another_packages_range_would_match(self, scanner):
        assert scanner._affects_installed_version(_CRYPTOGRAPHY_GHSA_X4QR, "50.0.2") is True

    def test_limit_is_an_exclusive_upper_bound(self, scanner):
        rec = _ranged("x", [{"introduced": "1.0"}, {"limit": "2.0"}])
        assert scanner._affects_installed_version(rec, "1.9") is True
        assert scanner._affects_installed_version(rec, "2.0") is False

    def test_star_limit_leaves_the_interval_open(self, scanner):
        rec = _ranged("x", [{"introduced": "1.0"}, {"limit": "*"}])
        assert scanner._affects_installed_version(rec, "99.0") is True

    def test_second_interval_after_last_affected(self, scanner):
        rec = _ranged(
            "x",
            [
                {"introduced": "1.0"},
                {"last_affected": "1.2"},
                {"introduced": "3.0"},
                {"fixed": "3.1"},
            ],
        )
        assert scanner._affects_installed_version(rec, "2.0") is False
        assert scanner._affects_installed_version(rec, "3.0.5") is True

    def test_only_this_packages_entries_decide(self, scanner):
        rec = _ranged("pyjwt", [{"introduced": "0"}, {"fixed": "1.0"}])
        rec["affected"].append(
            {
                "package": {"ecosystem": "PyPI", "name": "other"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        )
        assert scanner._affects_installed_version(rec, "2.15.1", package_name="PyJWT") is False

    def test_unevaluable_record_follows_the_caller_default(self, scanner):
        rec = {"id": "x", "affected": []}
        assert scanner._affects_installed_version(rec, "1.0") is False
        assert scanner._affects_installed_version(rec, "1.0", when_unevaluable=True) is True

    def test_unpinned_version_is_conservative(self, scanner):
        assert scanner._affects_installed_version(_CRYPTOGRAPHY_GHSA_X4QR, None) is True
        assert scanner._affects_installed_version(_CRYPTOGRAPHY_GHSA_X4QR, "*") is True

    async def test_offline_last_affected_is_honoured(self, tmp_path):
        _write_db(tmp_path, "pyjwt", [_PYJWT_PYSEC_2026_4146, _PYJWT_PYSEC_2025_183])
        scanner = _offline_scanner(tmp_path)
        assert await scanner.scan_vulnerabilities([make_package("pyjwt", "2.15.1")]) == []
        hit = await scanner.scan_vulnerabilities([make_package("pyjwt", "2.12.0")])
        assert [v.id for v in hit] == ["PYSEC-2026-4146"]


class TestOnlineQueriesAreVersionScoped:
    """The online path sends the version and filters what comes back by it."""

    async def test_batch_sends_version_and_drops_out_of_range_records(self, scanner):
        stub = {"id": "GHSA-x4qr-2fvf-3mr5", "modified": "2026-01-01T00:00:00Z"}
        post = AsyncMock(return_value=_resp(200, {"results": [{"vulns": [stub]}]}))
        get = AsyncMock(return_value=_resp(200, _CRYPTOGRAPHY_GHSA_X4QR))
        client = _client_mock(post=post, get=get)
        pkg = make_package("cryptography", "50.0.2")
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([pkg])
        assert post.call_args.kwargs["json"]["queries"] == [
            {"package": {"name": "cryptography", "ecosystem": "PyPI"}, "version": "50.0.2"}
        ]
        assert vulns == []
        assert scanner.lookup_errors == []

    async def test_batch_keeps_an_in_range_record(self, scanner):
        post = AsyncMock(
            return_value=_resp(200, {"results": [{"vulns": [_CRYPTOGRAPHY_GHSA_X4QR]}]})
        )
        client = _client_mock(post=post)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner.scan_vulnerabilities([make_package("cryptography", "38.0.0")])
        assert [v.id for v in vulns] == ["GHSA-x4qr-2fvf-3mr5"]

    async def test_unpinned_package_is_queried_name_only(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"results": [{}]}))
        client = _client_mock(post=post)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            await scanner._query_single_batch([make_package("cryptography", "*")])
        assert "version" not in post.call_args.kwargs["json"]["queries"][0]

    async def test_individual_fallback_sends_version_and_filters(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"vulns": [_PYJWT_PYSEC_2025_183]}))
        client = _client_mock(post=post)
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            vulns = await scanner._query_individual_fallback([make_package("pyjwt", "2.15.1")])
        assert post.call_args.kwargs["json"]["version"] == "2.15.1"
        assert vulns == []

    def test_cache_key_differs_per_version(self, scanner):
        assert scanner._get_cache_key(make_package("a", "1.0")) != scanner._get_cache_key(
            make_package("a", "2.0")
        )


class TestOnlyExactVersionsAreSentOnline:
    """A range sent to OSV as a bare version would hide the advisories for every
    other version the range admits: only an exact pin is version-scoped."""

    @pytest.mark.parametrize(
        ("version", "specifier", "ecosystem"),
        [
            ("4.17.0", "^4.17.0", "npm"),
            ("2.0", ">=2.0", "pypi"),
            ("4.x", None, "npm"),
            ("4.17.0", "~4.17.0", "npm"),
            ("latest", None, "npm"),
            ("latest", "latest", "npm"),
            ("1.2", None, "npm"),
            ("2.0", "~=2.0", "pypi"),
            ("2.0", ">=2.0,<3", "pypi"),
            ("1.2.3", "1.2.3", "crates.io"),  # a bare Cargo.toml version is a caret range
            # Audit 2 (2026-11-04): a range hiding in a semver prerelease / whitespace.
            ("1.2.3-beta||9.9.9", None, "npm"),
            ("1.2.3 \t|| 2.0", None, "npm"),
            ("1.2.3-beta,2.0.0", None, "npm"),
            ("1.2.3+build*", None, "npm"),
        ],
    )
    async def test_inexact_version_is_queried_by_name_and_keeps_every_record(
        self, scanner, version, specifier, ecosystem
    ):
        pkg = ExternalPackage(
            name="cryptography", version=version, specifier=specifier, ecosystem=ecosystem
        )
        assert "version" not in scanner._osv_query(pkg)
        post = AsyncMock(
            return_value=_resp(200, {"results": [{"vulns": [_CRYPTOGRAPHY_GHSA_X4QR]}]})
        )
        client = _client_mock(post=post)
        with patch("services.dependency_visualization.httpx.AsyncClient", return_value=client):
            vulns = await scanner._query_single_batch([pkg])
        assert "version" not in post.call_args.kwargs["json"]["queries"][0]
        assert [v.id for v in vulns] == ["GHSA-x4qr-2fvf-3mr5"]

    @pytest.mark.parametrize(
        ("version", "specifier", "ecosystem", "sent"),
        [
            ("50.0.2", None, "pypi", "50.0.2"),  # lockfile: resolved, no specifier
            ("50.0.2", "==50.0.2", "pypi", "50.0.2"),
            ("4.17.21", None, "npm", "4.17.21"),
            ("4.17.21", "4.17.21", "npm", "4.17.21"),
            ("1.0.0-rc.1", None, "npm", "1.0.0-rc.1"),
            ("1.2.3", "=1.2.3", "crates.io", "1.2.3"),
        ],
    )
    def test_exact_pin_is_sent(self, scanner, version, specifier, ecosystem, sent):
        pkg = ExternalPackage(name="x", version=version, specifier=specifier, ecosystem=ecosystem)
        assert scanner._osv_query(pkg)["version"] == sent

    async def test_individual_fallback_keeps_records_for_a_range(self, scanner):
        post = AsyncMock(return_value=_resp(200, {"vulns": [_PYJWT_PYSEC_2025_183]}))
        client = _client_mock(post=post)
        pkg = ExternalPackage(
            name="pyjwt", version="2.15.1", specifier=">=2.15.1", ecosystem="pypi"
        )
        with (
            patch("services.dependency_visualization.httpx.AsyncClient", return_value=client),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            vulns = await scanner._query_individual_fallback([pkg])
        assert "version" not in post.call_args.kwargs["json"]
        assert [v.id for v in vulns] == ["PYSEC-2025-183"]


class TestOfflineUsesTheExactPinDecision:
    """Audit 2 (2026-11-04): the offline DB path filtered by ANY version string,
    so a range (``>=2.15.1``) dropped every advisory below its floor. Only an
    exact pin may filter; otherwise every non-withdrawn record is reported."""

    async def test_range_reports_every_record(self, tmp_path):
        _write_db(tmp_path, "pyjwt", [_PYJWT_PYSEC_2026_4146, _PYJWT_PYSEC_2025_183])
        scanner = _offline_scanner(tmp_path)
        pkg = ExternalPackage(
            name="pyjwt", version="2.15.1", specifier=">=2.15.1", ecosystem="pypi"
        )
        vulns = await scanner.scan_vulnerabilities([pkg])
        assert sorted(v.id for v in vulns) == ["PYSEC-2025-183", "PYSEC-2026-4146"]

    async def test_exact_pin_still_filters(self, tmp_path):
        _write_db(tmp_path, "pyjwt", [_PYJWT_PYSEC_2026_4146, _PYJWT_PYSEC_2025_183])
        scanner = _offline_scanner(tmp_path)
        pkg = ExternalPackage(
            name="pyjwt", version="2.15.1", specifier="==2.15.1", ecosystem="pypi"
        )
        assert await scanner.scan_vulnerabilities([pkg]) == []
