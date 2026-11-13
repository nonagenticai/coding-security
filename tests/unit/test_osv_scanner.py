"""Tests for OSVScanner."""

import json

import pytest

from services.osv_scanner import ECOSYSTEM_MAPPING, OSVScanner


@pytest.fixture
def scanner():
    return OSVScanner()


class TestOSVScanner:
    def test_ecosystem_detection(self, scanner):
        """Detect ecosystem from filename."""
        assert scanner._detect_ecosystem("package-lock.json") == "npm"
        assert scanner._detect_ecosystem("requirements.txt") == "PyPI"
        assert scanner._detect_ecosystem("Cargo.lock") == "crates.io"
        assert scanner._detect_ecosystem("go.mod") == "Go"
        assert scanner._detect_ecosystem("unknown.txt") is None

    def test_cache_miss(self, scanner):
        """Cache miss returns False."""
        assert scanner._is_cached("nonexistent") is False

    def test_ecosystem_mapping_completeness(self):
        """All expected ecosystems are mapped."""
        assert "package-lock.json" in ECOSYSTEM_MAPPING
        assert "requirements.txt" in ECOSYSTEM_MAPPING
        assert "Cargo.lock" in ECOSYSTEM_MAPPING
        assert "go.mod" in ECOSYSTEM_MAPPING
        assert "pom.xml" in ECOSYSTEM_MAPPING

    async def test_scan_nonexistent_lockfile(self, scanner):
        """Scanning nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            await scanner.scan_lockfile("/nonexistent/file.txt")

    async def test_scan_unsupported_lockfile(self, scanner, tmp_path):
        """Unsupported file type raises ValueError."""
        f = tmp_path / "unknown.txt"
        f.write_text("content")
        with pytest.raises(ValueError):
            await scanner.scan_lockfile(str(f))

    async def test_parse_requirements_txt(self, scanner, tmp_path):
        """Parse requirements.txt correctly."""
        req = tmp_path / "requirements.txt"
        req.write_text("fastapi==0.115.0\nuvicorn>=0.30.0\n# comment\n")
        packages = await scanner._parse_lockfile(req, "PyPI")
        assert len(packages) == 2

    async def test_parse_package_json(self, scanner, tmp_path):
        """Parse package.json correctly."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.0"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            )
        )
        packages = await scanner._parse_lockfile(pkg, "npm")
        assert len(packages) == 2

    async def test_query_osv_api_success(self, scanner):
        """Query OSV API returns vulnerabilities."""
        from unittest.mock import AsyncMock, MagicMock

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "summary": "Test vulnerability",
                    "details": "Details",
                    "severity": [{"rating": "HIGH"}],
                    "affected": [],
                    "references": [],
                }
            ]
        }
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(return_value=mock_response)
        result = await scanner._query_osv_api("PyPI", "django", "4.2.0")
        assert len(result) == 1
        assert result[0].id == "GHSA-1234"

    async def test_query_osv_api_rate_limited(self, scanner):
        """Rate limited response triggers retry."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {"vulns": []}
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(side_effect=[mock_429, mock_200])
        with patch("services.osv_scanner.asyncio.sleep", new_callable=AsyncMock):
            result = await scanner._query_osv_api("PyPI", "django", "4.2.0")
        assert result == []

    async def test_query_osv_api_timeout(self, scanner):
        """Timeout returns empty list."""
        from unittest.mock import AsyncMock, patch

        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(side_effect=TimeoutError("timeout"))
        with patch("services.osv_scanner.asyncio.sleep", new_callable=AsyncMock):
            result = await scanner._query_osv_api("PyPI", "django", "4.2.0")
        assert result == []

    async def test_query_osv_api_connection_error(self, scanner):
        """Connection error returns empty list."""
        from unittest.mock import AsyncMock

        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(side_effect=Exception("connection refused"))
        result = await scanner._query_osv_api("PyPI", "django", "4.2.0")
        assert result == []

    async def test_check_package_cache_hit(self, scanner):
        """Cache hit returns cached result."""
        from datetime import UTC, datetime

        from models.security_models import OSVVulnerability

        vuln = OSVVulnerability(
            id="GHSA-test",
            summary="test",
            severity="HIGH",
            affected_versions=["*"],
            package_name="django",
            ecosystem="PyPI",
        )
        scanner._cache["PyPI:django:4.2.0"] = ([vuln], datetime.now(UTC))
        result = await scanner.check_package("PyPI", "django", "4.2.0")
        assert len(result) == 1
        assert result[0].id == "GHSA-test"

    async def test_check_package_cache_miss(self, scanner):
        """Cache miss queries API."""
        from unittest.mock import AsyncMock, MagicMock

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(return_value=mock_response)
        result = await scanner.check_package("PyPI", "django", "4.2.0")
        assert result == []

    async def test_batch_query_multiple_packages(self, scanner):
        """Batch query handles multiple packages."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from models.security_models import PackageInfo

        packages = [
            PackageInfo(name="django", version="4.2.0", ecosystem="PyPI"),
            PackageInfo(name="flask", version="3.0.0", ecosystem="PyPI"),
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(return_value=mock_response)
        with patch("services.osv_scanner.asyncio.sleep", new_callable=AsyncMock):
            result = await scanner.batch_query(packages)
        assert isinstance(result, list)

    def test_parse_osv_response_valid(self, scanner):
        """Parse valid OSV response."""
        data = {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "summary": "Test vuln",
                    "details": "test details",
                    "severity": [{"rating": "HIGH"}],
                    "affected": [
                        {
                            "package": {"name": "django"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.2.1"}]}],
                        }
                    ],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"}],
                }
            ]
        }
        result = scanner._parse_osv_response(data, "PyPI", "django")
        assert len(result) == 1
        assert result[0].id == "GHSA-1234"
        assert result[0].severity == "HIGH"

    def test_parse_osv_response_empty(self, scanner):
        """Empty vulns returns empty list."""
        result = scanner._parse_osv_response({"vulns": []}, "PyPI", "django")
        assert result == []

    def test_parse_osv_response_no_vulns_key(self, scanner):
        """Missing vulns key returns empty list."""
        result = scanner._parse_osv_response({}, "PyPI", "django")
        assert result == []

    def test_extract_severity_from_list(self, scanner):
        """Extract severity from list."""
        result = scanner._extract_severity({"severity": [{"rating": "HIGH"}]})
        assert result == "HIGH"

    def test_extract_severity_from_string(self, scanner):
        """Extract severity from string."""
        result = scanner._extract_severity({"severity": "CRITICAL"})
        assert result == "CRITICAL"

    def test_extract_severity_none(self, scanner):
        """No severity returns None."""
        result = scanner._extract_severity({})
        assert result is None

    async def test_parse_cargo_lock(self, scanner, tmp_path):
        """Parse Cargo.lock file."""
        cargo = tmp_path / "Cargo.lock"
        cargo.write_text(
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n\n[[package]]\nname = "tokio"\nversion = "1.35.0"\n'
        )
        result = await scanner._parse_lockfile(cargo, "crates.io")
        assert len(result) == 2

    async def test_parse_go_mod(self, scanner, tmp_path):
        """Parse go.mod file."""
        gomod = tmp_path / "go.mod"
        gomod.write_text(
            "module example.com/mymod\n\ngo 1.21\n\nrequire (\n)\n\ngithub.com/gin-gonic/gin v1.9.0\n"
        )
        result = await scanner._parse_lockfile(gomod, "Go")
        assert isinstance(result, list)

    async def test_close(self, scanner):
        """Close closes the client."""
        from unittest.mock import AsyncMock

        scanner._client = AsyncMock()
        await scanner.close()
        scanner._client.aclose.assert_called_once()

    async def test_context_manager(self):
        """Context manager opens and closes client."""
        async with OSVScanner() as scanner:
            assert scanner._client is not None

    async def test_close_when_no_client(self, scanner):
        """Close is safe when no client exists."""
        scanner._client = None
        await scanner.close()  # Should not raise
        assert scanner._client is None, "Client should remain None after close"

    def test_get_from_cache_expired(self, scanner):
        """Expired cache returns empty list from _get_from_cache."""
        from datetime import UTC, datetime, timedelta

        scanner._cache["expired:key:1.0"] = (
            [],
            datetime.now(UTC) - timedelta(hours=48),
        )
        result = scanner._get_from_cache("expired:key:1.0")
        assert result == []

    def test_get_from_cache_missing(self, scanner):
        """Missing cache key returns empty list."""
        result = scanner._get_from_cache("nonexistent:key:1.0")
        assert result == []

    def test_is_cached_valid_entry(self, scanner):
        """Valid cache entry returns True."""
        from datetime import UTC, datetime

        scanner._cache["valid:key:1.0"] = ([], datetime.now(UTC))
        assert scanner._is_cached("valid:key:1.0") is True

    def test_is_cached_expired_entry(self, scanner):
        """Expired cache entry returns False."""
        from datetime import UTC, datetime, timedelta

        scanner._cache["old:key:1.0"] = (
            [],
            datetime.now(UTC) - timedelta(hours=48),
        )
        assert scanner._is_cached("old:key:1.0") is False

    async def test_query_osv_api_404(self, scanner):
        """404 response returns empty list."""
        from unittest.mock import AsyncMock, MagicMock

        mock_response = MagicMock()
        mock_response.status_code = 404
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(return_value=mock_response)
        result = await scanner._query_osv_api("PyPI", "nonexistent", "1.0.0")
        assert result == []

    async def test_query_osv_api_other_error_code(self, scanner):
        """Non-200/404/429 returns empty list."""
        from unittest.mock import AsyncMock, MagicMock

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        scanner._client = AsyncMock()
        scanner._client.post = AsyncMock(return_value=mock_response)
        result = await scanner._query_osv_api("PyPI", "django", "4.2.0")
        assert result == []

    async def test_query_osv_api_creates_client_if_none(self, scanner):
        """If client is None, it gets created before query."""
        from unittest.mock import AsyncMock, MagicMock, patch

        scanner._client = None
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}

        with patch("services.osv_scanner.httpx.AsyncClient") as mock_cls:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_cls.return_value = mock_instance
            result = await scanner._query_osv_api("PyPI", "django", "4.2.0")

        assert result == []

    async def test_batch_query_handles_exceptions_in_results(self, scanner):
        """Batch query skips exceptions from individual check_package calls."""
        from unittest.mock import AsyncMock, patch

        from models.security_models import PackageInfo

        packages = [
            PackageInfo(name="good-pkg", version="1.0.0", ecosystem="PyPI"),
            PackageInfo(name="bad-pkg", version="1.0.0", ecosystem="PyPI"),
        ]

        call_count = 0

        async def mock_check(ecosystem, package, version):
            nonlocal call_count
            call_count += 1
            if package == "bad-pkg":
                raise ConnectionError("network error")
            return []

        with patch.object(scanner, "check_package", side_effect=mock_check):
            with patch("services.osv_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scanner.batch_query(packages)

        assert isinstance(result, list)

    def test_parse_osv_response_with_cve_extraction(self, scanner):
        """Parse response extracts CVE IDs from reference URLs."""
        data = {
            "vulns": [
                {
                    "id": "GHSA-CVE-TEST",
                    "summary": "CVE test vuln",
                    "details": "details",
                    "severity": [{"rating": "CRITICAL"}],
                    "affected": [
                        {
                            "package": {"name": "django"},
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "4.2.1"},
                                    ]
                                }
                            ],
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-45678"},
                        {"url": "https://github.com/advisory/GHSA-CVE-TEST"},
                    ],
                }
            ]
        }
        result = scanner._parse_osv_response(data, "PyPI", "django")
        assert len(result) == 1
        assert "CVE-2023-45678" in result[0].cve_ids
        assert len(result[0].references) == 2

    def test_parse_osv_response_affected_with_fixed(self, scanner):
        """Parses fixed_versions from affected ranges."""
        data = {
            "vulns": [
                {
                    "id": "GHSA-FIX",
                    "summary": "Fix test",
                    "affected": [
                        {
                            "package": {"name": "mylib"},
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "1.0.0"},
                                        {"fixed": "1.2.3"},
                                    ]
                                }
                            ],
                        }
                    ],
                    "references": [],
                }
            ]
        }
        result = scanner._parse_osv_response(data, "PyPI", "mylib")
        assert result[0].affected_versions == ["1.0.0"]
        assert result[0].fixed_versions == ["1.2.3"]

    def test_parse_osv_response_malformed_vuln_skipped(self, scanner):
        """Malformed vulnerability data is skipped without crashing."""
        data = {
            "vulns": [
                {"id": "GOOD-1", "summary": "ok", "affected": [], "references": []},
                {"not_an_id": True},  # Missing required fields
            ]
        }
        result = scanner._parse_osv_response(data, "PyPI", "django")
        # First vuln parses OK, second has no id so it gets UNKNOWN
        assert len(result) >= 1
        assert result[0].id == "GOOD-1"

    def test_extract_severity_empty_list(self, scanner):
        """Empty severity list returns None."""
        result = scanner._extract_severity({"severity": []})
        assert result is None

    async def test_parse_npm_lockfile(self, scanner, tmp_path):
        """Parse npm package-lock.json correctly."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "packages": {
                        "": {"name": "root", "version": "1.0.0"},
                        "node_modules/express": {"version": "4.18.2"},
                        "node_modules/body-parser": {"version": "1.20.2"},
                    }
                }
            )
        )
        result = await scanner._parse_lockfile(lockfile, "npm")
        assert len(result) == 2
        names = [p.name for p in result]
        assert "express" in names
        assert "body-parser" in names

    async def test_parse_pom_xml(self, scanner, tmp_path):
        """Parse Maven pom.xml correctly."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            """<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.20</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
        </dependency>
    </dependencies>
</project>"""
        )
        result = await scanner._parse_lockfile(pom, "Maven")
        assert len(result) >= 2
        names = [p.name for p in result]
        assert "spring-core" in names
        assert "junit" in names

    async def test_parse_lockfile_unsupported_format(self, scanner, tmp_path):
        """Unsupported lockfile format returns empty list."""
        f = tmp_path / "Gemfile.lock"
        f.write_text("GEM\n  remote: https://rubygems.org/\n")
        result = await scanner._parse_lockfile(f, "RubyGems")
        assert result == []

    async def test_parse_lockfile_exception_returns_empty(self, scanner, tmp_path):
        """Parse error returns empty list instead of crashing."""
        f = tmp_path / "package-lock.json"
        f.write_text("not valid json at all")
        result = await scanner._parse_lockfile(f, "npm")
        assert result == []

    async def test_scan_lockfile_full_flow(self, scanner, tmp_path):
        """scan_lockfile detects ecosystem, parses, and queries."""
        from unittest.mock import AsyncMock, patch

        req = tmp_path / "requirements.txt"
        req.write_text("django==4.2.0\nflask==3.0.0\n")

        with patch.object(scanner, "batch_query", new_callable=AsyncMock) as mock_bq:
            mock_bq.return_value = []
            result = await scanner.scan_lockfile(str(req))

        assert result == []
        mock_bq.assert_called_once()
        # batch_query was called with 2 packages
        assert len(mock_bq.call_args[0][0]) == 2

    async def test_parse_go_mod_deduplication(self, scanner, tmp_path):
        """go.mod parser deduplicates packages."""
        gomod = tmp_path / "go.mod"
        gomod.write_text(
            "module example.com/test\n\ngo 1.21\n\n"
            "github.com/gin-gonic/gin v1.9.0\n"
            "github.com/gin-gonic/gin v1.9.0\n"  # Duplicate
            "golang.org/x/net v0.17.0\n"
        )
        result = await scanner._parse_lockfile(gomod, "Go")
        names = [p.name for p in result]
        # gin should appear only once
        assert names.count("github.com/gin-gonic/gin") == 1

    async def test_parse_requirements_txt_with_comments_and_blanks(self, scanner, tmp_path):
        """requirements.txt parser skips comments and blank lines."""
        req = tmp_path / "requirements.txt"
        req.write_text("# This is a comment\n\ndjango==4.2.0\n\n# another comment\nflask\n")
        result = await scanner._parse_lockfile(req, "PyPI")
        assert len(result) == 2
        names = [p.name for p in result]
        assert "django" in names
        assert "flask" in names

    async def test_parse_package_json_strips_version_specifiers(self, scanner, tmp_path):
        """package.json parser strips ^, ~, etc. from versions."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
                }
            )
        )
        result = await scanner._parse_lockfile(pkg, "npm")
        versions = {p.name: p.version for p in result}
        assert versions["express"] == "4.18.0"
        assert versions["lodash"] == "4.17.21"
