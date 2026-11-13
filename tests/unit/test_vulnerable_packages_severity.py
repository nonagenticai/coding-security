"""GET /{container}/vulnerable must return OSV-vulnerable packages (coding-security#103).

Before the fix nothing on this path set ``ExternalPackage.severity``, so the
``get_vulnerable_packages`` filter dropped every package and the route always
returned ``[]``. These tests run the REAL chain (manifest extraction -> OSV scan
-> enrichment -> filter); only the OSV data source is faked, and no test touches
the network (``httpx.AsyncClient.post`` is patched in every route test).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from models.architecture_models import Vulnerability
from models.container_models import ContainerInfo, ContainerStatus
from models.package_manager_models import ExternalPackage
from services.dependency_analyzer import attach_vulnerabilities

# Recorded-shape GHSA records for jinja2 (as the baked offline DB stores them).
# MODERATE is listed FIRST so a min-instead-of-max aggregation reads MODERATE.
_JINJA2_RECORDS = [
    {
        "id": "GHSA-g3rq-g295-4j3m",
        "aliases": ["CVE-2020-28493"],
        "summary": "Regular Expression Denial of Service (ReDoS) in Jinja2",
        "details": "",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.3"}]}
                ],
            }
        ],
        "references": [],
        "published": "2021-03-19T21:28:05Z",
        "modified": "2024-09-26T15:48:56Z",
    },
    {
        "id": "GHSA-462w-v97r-4m45",
        "aliases": ["CVE-2019-10906"],
        "summary": "Jinja2 sandbox escape via string formatting",
        "details": "",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}
                ],
            }
        ],
        "references": [],
        "published": "2019-04-10T14:30:13Z",
        "modified": "2024-09-26T15:48:56Z",
    },
]

_URL = "/api/dependencies/test-container/vulnerable"


def _container(codebase_path: Path) -> ContainerInfo:
    return ContainerInfo(
        container_name="test-container",
        api_endpoint="http://localhost:8080",
        codebase_path=str(codebase_path),
        repo_url="https://github.com/test/repo",
        branch="main",
        status=ContainerStatus.RUNNING,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A fixture repo: one known-vulnerable pin (jinja2 2.10) and one clean pin."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("jinja2==2.10\nsix==1.16.0\n")
    return root


@pytest.fixture
def offline_db(tmp_path: Path) -> Path:
    db = tmp_path / "osv-db"
    (db / "PyPI").mkdir(parents=True)
    (db / "PyPI" / "jinja2.json").write_text(json.dumps(_JINJA2_RECORDS))
    return db


def _no_network():
    return patch(
        "httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=AssertionError("test must not reach the network"),
    )


def _get(test_client, tenant_headers, repo: Path, url: str = _URL):
    with patch(
        "services.scan_runner.validate_and_get_container_for_tenant",
        new_callable=AsyncMock,
        return_value=_container(repo),
    ):
        return test_client.get(url, headers=tenant_headers)


def _assert_jinja2_row(data: list[dict]) -> None:
    assert [row["name"] for row in data] == ["jinja2"], data
    row = data[0]
    assert row["severity"] == "HIGH"
    assert row["vulnerability_ids"] == ["GHSA-462w-v97r-4m45", "GHSA-g3rq-g295-4j3m"]
    assert set(row["fixed_versions"]) == {"2.10.1", "2.11.3"}
    # Per-vulnerability fixes: what the conveyor-compute consumer reads.
    assert row["vulnerabilities"] == [
        {"id": "GHSA-462w-v97r-4m45", "severity": "HIGH", "fixed_versions": ["2.10.1"]},
        {"id": "GHSA-g3rq-g295-4j3m", "severity": "MODERATE", "fixed_versions": ["2.11.3"]},
    ]
    # Fields the conveyor-compute consumer reads are untouched.
    assert row["ecosystem"] == "pypi"
    assert row["version"] == "2.10"


class TestVulnerableRouteOffline:
    """The prod path: pod egress to OSV is blocked, so the baked offline DB is used."""

    def test_vulnerable_pin_is_returned_with_severity(
        self, test_client, tenant_headers, repo, offline_db, monkeypatch
    ):
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(offline_db))
        with _no_network():
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 200, response.text
        # six has no OSV record -> severity stays None -> excluded.
        _assert_jinja2_row(response.json())

    def test_missing_offline_db_is_an_error_not_an_empty_list(
        self, test_client, tenant_headers, repo, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(tmp_path / "does-not-exist"))
        with _no_network():
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 503, response.text

    def test_ecosystem_without_an_offline_db_is_an_error_not_clean(
        self, test_client, tenant_headers, repo, offline_db, monkeypatch
    ):
        """Prod bakes only the PyPI DB: npm packages are unchecked, so 503, not 200."""
        (repo / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(offline_db))
        with _no_network():
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 503, response.text
        assert "no offline OSV DB for ecosystem 'npm'" in response.text


class TestVulnerableRouteOnline:
    """The online OSV API path, with the HTTP layer mocked."""

    def test_mocked_osv_response_yields_severity(
        self, test_client, tenant_headers, repo, monkeypatch
    ):
        """querybatch returns ONLY {id, modified}; severity and fixes need GET /v1/vulns/{id}."""
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)
        batch_payloads: list[dict] = []
        record_gets: list[str] = []
        by_id = {r["id"]: r for r in _JINJA2_RECORDS}

        async def fake_post(self, url, json=None, **kwargs):  # noqa: A002
            assert url.endswith("/querybatch"), url
            batch_payloads.append(json)
            results = [
                {"vulns": _stubs(_JINJA2_RECORDS)} if q["package"]["name"] == "jinja2" else {}
                for q in json["queries"]
            ]
            return httpx.Response(
                200, json={"results": results}, request=httpx.Request("POST", url)
            )

        async def fake_get(self, url, **kwargs):
            vuln_id = url.rsplit("/", 1)[-1]
            record_gets.append(vuln_id)
            return httpx.Response(200, json=by_id[vuln_id], request=httpx.Request("GET", url))

        with (
            patch("httpx.AsyncClient.post", new=fake_post),
            patch("httpx.AsyncClient.get", new=fake_get),
        ):
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 200, response.text
        _assert_jinja2_row(response.json())
        # OSV's ecosystem names are case-sensitive: "pypi" is a 400.
        assert {q["package"]["ecosystem"] for q in batch_payloads[0]["queries"]} == {"PyPI"}
        assert sorted(record_gets) == sorted(by_id)

    def test_failed_record_fetch_is_an_error_not_a_clean_row(
        self, test_client, tenant_headers, repo, monkeypatch
    ):
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)

        async def fake_post(self, url, json=None, **kwargs):  # noqa: A002
            results = [
                {"vulns": _stubs(_JINJA2_RECORDS)} if q["package"]["name"] == "jinja2" else {}
                for q in json["queries"]
            ]
            return httpx.Response(
                200, json={"results": results}, request=httpx.Request("POST", url)
            )

        async def fake_get(self, url, **kwargs):
            return httpx.Response(502, request=httpx.Request("GET", url))

        with (
            patch("httpx.AsyncClient.post", new=fake_post),
            patch("httpx.AsyncClient.get", new=fake_get),
        ):
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 503, response.text
        assert "status 502" in response.text

    def test_osv_outage_is_an_error_not_an_empty_list(
        self, test_client, tenant_headers, repo, monkeypatch
    ):
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)
        with (
            patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                side_effect=httpx.ConnectError("osv unreachable"),
            ),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            response = _get(test_client, tenant_headers, repo)
        assert response.status_code == 503, response.text
        assert "osv unreachable" in response.text.lower()

    def test_osv_outage_marks_full_report_degraded(
        self, test_client, tenant_headers, repo, monkeypatch
    ):
        """The report route must not overwrite the analyzer's degraded flag."""
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)
        with (
            patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                side_effect=httpx.ConnectError("osv unreachable"),
            ),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
        ):
            response = _get(
                test_client, tenant_headers, repo, url="/api/dependencies/test-container"
            )
        assert response.status_code == 200, response.text
        assert response.json()["scan_degraded"] is True

    def test_osv_outage_marks_triggered_scan_degraded(
        self, test_client, tenant_headers, repo, monkeypatch
    ):
        """POST /scan must not overwrite the analyzer's degraded flag either."""
        monkeypatch.delenv("OSV_OFFLINE_DB_DIR", raising=False)
        with (
            patch(
                "httpx.AsyncClient.post",
                new_callable=AsyncMock,
                side_effect=httpx.ConnectError("osv unreachable"),
            ),
            patch("services.dependency_visualization.asyncio.sleep", new_callable=AsyncMock),
            patch(
                "services.scan_runner.validate_and_get_container_for_tenant",
                new_callable=AsyncMock,
                return_value=_container(repo),
            ),
        ):
            response = test_client.post(
                "/api/dependencies/test-container/scan", headers=tenant_headers
            )
        assert response.status_code == 200, response.text
        assert response.json()["scan_degraded"] is True


def _stubs(records: list[dict]) -> list[dict]:
    """What OSV querybatch really returns per advisory: id + modified only."""
    return [{"id": r["id"], "modified": r["modified"]} for r in records]


# One advisory affecting TWO packages, each with its own fix.
_SHARED_RECORD = {
    "id": "GHSA-shared-0001",
    "summary": "shared advisory",
    "details": "",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "alpha"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "beta"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.5"}]}],
        },
    ],
    "references": [],
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
}

# An advisory with NO fixed version (affected through latest).
_UNFIXED_RECORD = {
    "id": "GHSA-nofix-0001",
    "summary": "no fix published",
    "details": "",
    "database_specific": {"severity": "LOW"},
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "alpha"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        }
    ],
    "references": [],
    "published": "2026-01-01T00:00:00Z",
    "modified": "2026-01-01T00:00:00Z",
}


class TestSharedAndUnfixedAdvisories:
    @pytest.fixture
    def shared_repo(self, tmp_path: Path) -> Path:
        root = tmp_path / "shared-repo"
        root.mkdir()
        (root / "requirements.txt").write_text("alpha==1.0\nbeta==2.0\n")
        return root

    @pytest.fixture
    def shared_db(self, tmp_path: Path) -> Path:
        db = tmp_path / "shared-db"
        (db / "PyPI").mkdir(parents=True)
        (db / "PyPI" / "alpha.json").write_text(json.dumps([_SHARED_RECORD, _UNFIXED_RECORD]))
        (db / "PyPI" / "beta.json").write_text(json.dumps([_SHARED_RECORD]))
        return db

    def test_shared_advisory_attributes_to_both_packages(
        self, test_client, tenant_headers, shared_repo, shared_db, monkeypatch
    ):
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(shared_db))
        with _no_network():
            response = _get(test_client, tenant_headers, shared_repo)
        assert response.status_code == 200, response.text
        rows = {row["name"]: row for row in response.json()}
        assert set(rows) == {"alpha", "beta"}
        assert "GHSA-shared-0001" in rows["beta"]["vulnerability_ids"]
        # Each package gets ITS OWN fix from the shared advisory, never the other's.
        assert rows["beta"]["vulnerabilities"] == [
            {"id": "GHSA-shared-0001", "severity": "HIGH", "fixed_versions": ["2.5"]}
        ]
        assert rows["beta"]["fixed_versions"] == ["2.5"]

    def test_an_unfixed_advisory_nulls_the_package_fix_union(
        self, test_client, tenant_headers, shared_repo, shared_db, monkeypatch
    ):
        monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(shared_db))
        with _no_network():
            response = _get(test_client, tenant_headers, shared_repo)
        assert response.status_code == 200, response.text
        alpha = next(row for row in response.json() if row["name"] == "alpha")
        assert alpha["vulnerabilities"] == [
            {"id": "GHSA-nofix-0001", "severity": "LOW", "fixed_versions": []},
            {"id": "GHSA-shared-0001", "severity": "HIGH", "fixed_versions": ["1.5"]},
        ]
        # A union ["1.5"] would claim 1.5 fixes the package; it does not.
        assert alpha["fixed_versions"] is None


def _vuln(vuln_id: str, severity: str, fixed: list[str], package: str = "pkg") -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary="",
        details="",
        affected_versions=[],
        fixed_versions=fixed,
        references=[],
        published_date="",
        modified_date="",
        package_name=package,
    )


class TestAttachVulnerabilities:
    def test_severity_is_the_max(self):
        pkg = ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")
        vulns = [
            _vuln("A", "LOW", ["1.1"]),
            _vuln("B", "CRITICAL", ["2.0"]),
            _vuln("C", "MODERATE", ["1.1"]),
        ]
        (out,) = attach_vulnerabilities([pkg], {"pkg": vulns})
        assert out.severity == "CRITICAL"
        assert out.vulnerability_ids == ["A", "B", "C"]
        assert out.fixed_versions == ["1.1", "2.0"]
        assert [(v.id, v.fixed_versions) for v in out.vulnerabilities or []] == [
            ("A", ["1.1"]),
            ("B", ["2.0"]),
            ("C", ["1.1"]),
        ]

    def test_one_unfixed_vulnerability_nulls_the_union(self):
        pkg = ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")
        (out,) = attach_vulnerabilities(
            [pkg], {"pkg": [_vuln("A", "HIGH", ["1.1"]), _vuln("B", "LOW", [])]}
        )
        assert out.fixed_versions is None
        assert [(v.id, v.fixed_versions) for v in out.vulnerabilities or []] == [
            ("A", ["1.1"]),
            ("B", []),
        ]

    def test_unknown_outranks_low_so_it_is_not_filtered(self):
        pkg = ExternalPackage(name="pkg", version="1.0", ecosystem="pypi")
        (out,) = attach_vulnerabilities(
            [pkg], {"pkg": [_vuln("A", "LOW", []), _vuln("B", "UNKNOWN", [])]}
        )
        assert out.severity == "UNKNOWN"

    def test_package_without_vulnerabilities_is_unchanged(self):
        pkg = ExternalPackage(name="clean", version="1.0", ecosystem="pypi")
        (out,) = attach_vulnerabilities([pkg], {"pkg": [_vuln("A", "HIGH", [])]})
        assert out is pkg
        assert out.severity is None
        assert out.vulnerability_ids is None
        assert out.vulnerabilities is None
        assert out.fixed_versions is None
