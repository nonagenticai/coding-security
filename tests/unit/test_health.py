"""Tests for health and root endpoints."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from utils.osv_db_status import _read_generated_at


@pytest.fixture(autouse=True)
def _clear_osv_cache():
    _read_generated_at.cache_clear()
    yield
    _read_generated_at.cache_clear()


def _point_at(monkeypatch, db_dir):
    """Repoint the service at `db_dir`, asserting the repoint actually took.

    Without this assertion the "missing dir" tests would pass even if the env
    never reached settings — the real /opt/osv-db is absent locally too, so the
    expected `stale: True` would arrive for the wrong reason.
    """
    from config.settings import get_settings

    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(db_dir))
    get_settings.cache_clear()
    assert get_settings().osv_offline_db_dir == str(db_dir)


def test_health_endpoint(test_client):
    """GET /health returns service info."""
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "coding-security"


def test_health_reports_osv_db_block(test_client):
    """The osv_db freshness block is always present with all four keys."""
    data = test_client.get("/health").json()
    assert set(data["osv_db"]) == {"present", "generated_at", "age_days", "stale"}


def test_health_is_200_when_osv_db_dir_missing(test_client, monkeypatch, tmp_path):
    """A missing DB must never 500 the health check — it degrades to unknown."""
    _point_at(monkeypatch, tmp_path / "does-not-exist")
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["osv_db"]["stale"] is True


def test_health_is_200_when_manifest_malformed(test_client, monkeypatch, tmp_path):
    """A corrupt manifest must never 500 the health check."""
    (tmp_path / "manifest.json").write_text("{not json")
    _point_at(monkeypatch, tmp_path)
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["osv_db"]["present"] is False


def test_health_reports_fresh_db_as_not_stale(test_client, monkeypatch, tmp_path):
    stamp = (datetime.now(UTC) - timedelta(hours=2)).isoformat(timespec="seconds")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "generated_at": stamp.replace("+00:00", "Z")})
    )
    _point_at(monkeypatch, tmp_path)
    osv = test_client.get("/health").json()["osv_db"]
    assert osv["present"] is True
    assert osv["stale"] is False


def test_root_endpoint(test_client):
    """GET / returns service info with links."""
    response = test_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "coding-security"
    assert "docs" in data
    assert "health" in data
