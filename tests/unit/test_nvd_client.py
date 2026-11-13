"""Tests for NVDClient."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.nvd_client import NVDClient, NVDCVSSData


@pytest.fixture
def client():
    return NVDClient()


@pytest.fixture
def client_with_key():
    return NVDClient(api_key="test-key")


class TestNVDClientInit:
    def test_default_no_key(self, client):
        assert client._api_key is None

    def test_with_key(self, client_with_key):
        assert client_with_key._api_key == "test-key"

    def test_env_key(self):
        with patch.dict("os.environ", {"NVD_API_KEY": "env-key"}):
            c = NVDClient()
            assert c._api_key == "env-key"


class TestGetCve:
    async def test_cache_hit(self, client):
        cached = NVDCVSSData(
            cve_id="CVE-2024-0001",
            cvss_v31_score=9.8,
            cvss_v31_severity="CRITICAL",
        )
        client._cache["CVE-2024-0001"] = (cached, datetime.now(UTC))

        result = await client.get_cve("CVE-2024-0001")
        assert isinstance(result, NVDCVSSData), "Cache hit should return NVDCVSSData"
        assert result.cvss_v31_score == 9.8

    async def test_cache_expired(self, client):
        cached = NVDCVSSData(cve_id="CVE-2024-0001", cvss_v31_score=9.8)
        client._cache["CVE-2024-0001"] = (
            cached,
            datetime.now(UTC) - timedelta(hours=48),
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "Test CVE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    }
                                }
                            ]
                        },
                        "references": [],
                    }
                }
            ]
        }
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        result = await client.get_cve("CVE-2024-0001")
        assert isinstance(result, NVDCVSSData), (
            "Expired cache should re-fetch and return NVDCVSSData"
        )
        assert result.cvss_v31_score == 7.5
        assert result.cvss_v31_severity == "HIGH"

    async def test_404_returns_none(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 404
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        result = await client.get_cve("CVE-9999-0001")
        assert result is None

    async def test_429_retries(self, client):
        mock_429 = MagicMock()
        mock_429.status_code = 429

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {},
                        "references": [],
                    }
                }
            ]
        }

        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=[mock_429, mock_200])

        with patch("services.nvd_client.asyncio.sleep", new_callable=AsyncMock):
            result = await client.get_cve("CVE-2024-0002")

        assert isinstance(result, NVDCVSSData), "Should return parsed NVDCVSSData after retry"
        assert result.cve_id == "CVE-2024-0002"
        assert result.description == "Test"

    async def test_timeout(self, client):
        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=TimeoutError("timeout"))

        with patch("services.nvd_client.asyncio.sleep", new_callable=AsyncMock):
            result = await client.get_cve("CVE-2024-0003")

        assert result is None

    async def test_connection_error(self, client):
        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=Exception("connection refused"))

        result = await client.get_cve("CVE-2024-0004")
        assert result is None


class TestBatchGetCves:
    async def test_batch_fetch(self, client):
        async def mock_get_cve(cve_id):
            if cve_id == "CVE-2024-0001":
                return NVDCVSSData(cve_id=cve_id, cvss_v31_score=9.8)
            return None

        with patch.object(client, "get_cve", side_effect=mock_get_cve):
            results = await client.batch_get_cves(["CVE-2024-0001", "CVE-2024-0002"])

        assert "CVE-2024-0001" in results
        assert "CVE-2024-0002" not in results

    async def test_batch_caps_at_50(self, client):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(100)]

        call_count = 0

        async def mock_get_cve(cve_id):
            nonlocal call_count
            call_count += 1
            return None

        with patch.object(client, "get_cve", side_effect=mock_get_cve):
            await client.batch_get_cves(cve_ids)

        assert call_count <= 50

    async def test_batch_handles_exceptions(self, client):
        async def mock_get_cve(cve_id):
            if cve_id == "CVE-2024-BAD":
                raise ConnectionError("network error")
            return NVDCVSSData(cve_id=cve_id, cvss_v31_score=5.0)

        with patch.object(client, "get_cve", side_effect=mock_get_cve):
            results = await client.batch_get_cves(["CVE-2024-0001", "CVE-2024-BAD"])

        assert "CVE-2024-0001" in results


class TestParseNvdResponse:
    def test_parse_valid_response(self, client):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "en", "value": "A critical vulnerability"},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "references": [
                            {"url": "https://example.com/advisory"},
                        ],
                        "published": "2024-01-15T00:00:00",
                    }
                }
            ]
        }

        result = client._parse_nvd_response(data, "CVE-2024-0001")
        assert isinstance(result, NVDCVSSData), "Valid response should parse to NVDCVSSData"
        assert result.cve_id == "CVE-2024-0001"
        assert result.cvss_v31_score == 9.8
        assert result.cvss_v31_severity == "CRITICAL"
        assert result.cvss_v31_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert result.description == "A critical vulnerability"
        assert result.references == ["https://example.com/advisory"]

    def test_parse_empty_vulnerabilities(self, client):
        result = client._parse_nvd_response({"vulnerabilities": []}, "CVE-2024-0001")
        assert result is None

    def test_parse_no_cvss(self, client):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [{"lang": "en", "value": "No CVSS"}],
                        "metrics": {},
                        "references": [],
                    }
                }
            ]
        }
        result = client._parse_nvd_response(data, "CVE-2024-0001")
        assert isinstance(result, NVDCVSSData), "Response without CVSS should still parse"
        assert result.cvss_v31_score is None
        assert result.description == "No CVSS"


class TestRateLimit:
    async def test_rate_limit_no_key(self, client):
        """Without API key, old timestamps are pruned and request proceeds."""
        client._request_timestamps = [0.0] * 5  # All old (epoch time)
        await client._enforce_rate_limit()
        # Old timestamps should have been pruned since they're well outside the 30s window
        assert len(client._request_timestamps) == 0, "Old timestamps should be pruned"

    async def test_rate_limit_with_key(self, client_with_key):
        """With API key, empty timestamps proceeds without blocking."""
        assert client_with_key._request_timestamps == []
        await client_with_key._enforce_rate_limit()
        # No timestamps added by enforce itself, should still be empty
        assert len(client_with_key._request_timestamps) == 0


class TestNVDCVSSDataModel:
    def test_model_creation(self):
        data = NVDCVSSData(
            cve_id="CVE-2024-0001",
            cvss_v31_score=9.8,
            cvss_v31_severity="CRITICAL",
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Critical vulnerability",
            published_date="2024-01-15",
            references=["https://example.com"],
        )
        assert data.cve_id == "CVE-2024-0001"
        assert data.cvss_v31_score == 9.8


class TestContextManager:
    async def test_aenter_aexit(self):
        async with NVDClient() as client:
            assert client._client is not None

    async def test_close(self):
        client = NVDClient()
        client._client = AsyncMock()
        await client.close()
        client._client.aclose.assert_called_once()

    async def test_close_when_no_client(self):
        client = NVDClient()
        client._client = None
        await client.close()  # Should not raise
        assert client._client is None, "Client should remain None after close"


class TestApiKeyHeader:
    async def test_api_key_sent_in_header(self, client_with_key):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}

        client_with_key._client = AsyncMock()
        client_with_key._client.get = AsyncMock(return_value=mock_response)

        await client_with_key._query_nvd_api({"cveId": "CVE-2024-0001"})

        call_kwargs = client_with_key._client.get.call_args
        assert call_kwargs.kwargs["headers"]["apiKey"] == "test-key"
