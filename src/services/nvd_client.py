"""NVD (National Vulnerability Database) API client for CVSS enrichment.

HTTP API client following the OSVScanner pattern with caching and rate limiting.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import UTC, datetime, timedelta

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DURATION_HOURS = 24
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1
MAX_BACKOFF_SECONDS = 10


class NVDCVSSData(BaseModel):
    """CVSS data from NVD for a specific CVE."""

    cve_id: str = Field(..., description="CVE identifier")
    cvss_v31_score: float | None = Field(None, description="CVSS v3.1 base score")
    cvss_v31_severity: str | None = Field(None, description="LOW/MEDIUM/HIGH/CRITICAL")
    cvss_v31_vector: str | None = Field(None, description="CVSS v3.1 vector string")
    description: str = Field("", description="CVE description")
    published_date: str | None = Field(None, description="Publication date")
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class NVDClient:
    """Client for querying NVD REST API 2.0 for CVSS enrichment data."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.environ.get("NVD_API_KEY")
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[NVDCVSSData | None, datetime]] = {}
        self._request_timestamps: list[float] = []

    async def __aenter__(self) -> NVDClient:
        self._client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.aclose()

    async def get_cve(self, cve_id: str) -> NVDCVSSData | None:
        """Fetch CVSS data for a single CVE ID.

        Returns cached data if available and not expired.
        """
        # Check cache
        if cve_id in self._cache:
            cached_data, timestamp = self._cache[cve_id]
            age = datetime.now(UTC) - timestamp
            if age < timedelta(hours=CACHE_DURATION_HOURS):
                logger.debug(f"NVD cache hit for {cve_id}")
                return cached_data

        # Query API
        result = await self._query_nvd_api({"cveId": cve_id})

        if result is None:
            self._cache[cve_id] = (None, datetime.now(UTC))
            return None

        # Parse response
        nvd_data = self._parse_nvd_response(result, cve_id)
        self._cache[cve_id] = (nvd_data, datetime.now(UTC))
        return nvd_data

    async def batch_get_cves(self, cve_ids: list[str]) -> dict[str, NVDCVSSData]:
        """Fetch CVSS data for multiple CVE IDs with rate limiting.

        Caps at 50 CVEs per batch to respect NVD rate limits.
        """
        results: dict[str, NVDCVSSData] = {}

        # Cap at 50 to be respectful
        cve_ids_to_fetch = list(set(cve_ids))[:50]

        for cve_id in cve_ids_to_fetch:
            try:
                data = await self.get_cve(cve_id)
                if data:
                    results[cve_id] = data
            except Exception as e:
                logger.warning(f"Failed to fetch NVD data for {cve_id}: {e}")

        logger.info(f"NVD batch fetch: {len(results)}/{len(cve_ids_to_fetch)} CVEs enriched")
        return results

    async def _query_nvd_api(self, params: dict) -> dict | None:
        """Query NVD API with retry and rate limiting."""
        for attempt in range(MAX_RETRIES):
            try:
                await self._enforce_rate_limit()

                if not self._client:
                    self._client = httpx.AsyncClient()

                headers = {}
                if self._api_key:
                    headers["apiKey"] = self._api_key

                response = await self._client.get(
                    NVD_API_BASE,
                    params=params,
                    headers=headers,
                    timeout=httpx.Timeout(30),
                )

                self._request_timestamps.append(time.monotonic())

                if response.status_code == 200:
                    return response.json()

                elif response.status_code == 404:
                    logger.debug(f"CVE not found in NVD: {params}")
                    return None

                elif response.status_code == 429:
                    wait_time = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                    logger.warning(
                        f"NVD rate limited. Waiting {wait_time}s "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    await asyncio.sleep(wait_time)
                    continue

                else:
                    logger.error(f"NVD API error: {response.status_code} - {response.text}")
                    return None

            except TimeoutError:
                logger.warning(f"NVD API timeout (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    wait_time = min(BASE_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                    await asyncio.sleep(wait_time)

            except Exception as e:
                logger.exception(f"Error querying NVD API: {e}")
                return None

        logger.error(f"Failed to query NVD API after {MAX_RETRIES} attempts")
        return None

    async def _enforce_rate_limit(self):
        """Enforce NVD rate limits via sliding window.

        Without API key: 5 requests per 30 seconds
        With API key: 50 requests per 30 seconds
        """
        max_requests = 50 if self._api_key else 5
        window_seconds = 30.0
        now = time.monotonic()

        # Prune old timestamps
        self._request_timestamps = [
            ts for ts in self._request_timestamps if now - ts < window_seconds
        ]

        if len(self._request_timestamps) >= max_requests:
            oldest = self._request_timestamps[0]
            sleep_time = window_seconds - (now - oldest) + 0.1
            if sleep_time > 0:
                logger.debug(f"NVD rate limit: sleeping {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)

    def _parse_nvd_response(self, data: dict, cve_id: str) -> NVDCVSSData | None:
        """Parse NVD 2.0 API response into NVDCVSSData."""
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_item = vulnerabilities[0].get("cve", {})

            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS v3.1 metrics
            cvss_score = None
            cvss_severity = None
            cvss_vector = None

            metrics = cve_item.get("metrics", {})
            cvss_v31_list = metrics.get("cvssMetricV31", [])
            if cvss_v31_list:
                cvss_data = cvss_v31_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")

            # Extract references
            references = []
            for ref in cve_item.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            return NVDCVSSData(
                cve_id=cve_id,
                cvss_v31_score=cvss_score,
                cvss_v31_severity=cvss_severity,
                cvss_v31_vector=cvss_vector,
                description=description,
                published_date=cve_item.get("published"),
                references=references,
            )

        except Exception as e:
            logger.warning(f"Error parsing NVD response for {cve_id}: {e}")
            return None

    async def close(self):
        if self._client:
            await self._client.aclose()
