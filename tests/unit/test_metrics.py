"""Tests for the /metrics endpoint (OSV DB freshness gauges)."""

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
    """Repoint the service at `db_dir`, asserting the repoint actually took."""
    from config.settings import get_settings

    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(db_dir))
    get_settings.cache_clear()
    assert get_settings().osv_offline_db_dir == str(db_dir)


def _metric_value(body: str, name: str) -> str | None:
    """Return the value of a single-series gauge line, or None if absent."""
    for line in body.splitlines():
        if line.startswith(f"{name}{{") or line.startswith(f"{name} "):
            return line.rsplit(" ", 1)[1]
    return None


def test_metrics_is_prometheus_text(test_client):
    """/metrics returns 200 text/plain with the two always-present gauges."""
    response = test_client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "osv_db_present" in body
    assert "osv_db_stale" in body
    # Gauges must be declared with TYPE lines (valid exposition format).
    assert "# TYPE osv_db_present gauge" in body
    assert "# TYPE osv_db_stale gauge" in body


def test_metrics_fresh_db(test_client, monkeypatch, tmp_path):
    """A fresh manifest → present 1, stale 0, and a numeric age line present."""
    stamp = (datetime.now(UTC) - timedelta(hours=2)).isoformat(timespec="seconds")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "generated_at": stamp.replace("+00:00", "Z")})
    )
    _point_at(monkeypatch, tmp_path)
    body = test_client.get("/metrics").text
    assert _metric_value(body, "osv_db_present") == "1"
    assert _metric_value(body, "osv_db_stale") == "0"
    age = _metric_value(body, "osv_db_age_days")
    assert age is not None and float(age) < 1.0


def test_metrics_stale_db(test_client, monkeypatch, tmp_path):
    """A 13-day-old manifest → stale 1 with a numeric age (default threshold 10)."""
    stamp = (datetime.now(UTC) - timedelta(days=13)).isoformat(timespec="seconds")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "generated_at": stamp.replace("+00:00", "Z")})
    )
    _point_at(monkeypatch, tmp_path)
    body = test_client.get("/metrics").text
    assert _metric_value(body, "osv_db_stale") == "1"
    assert float(_metric_value(body, "osv_db_age_days")) > 12.0


def test_metrics_manifest_absent_omits_age(test_client, monkeypatch, tmp_path):
    """Manifest missing → present 0, stale 1, and NO bogus 0-age line."""
    _point_at(monkeypatch, tmp_path / "does-not-exist")
    body = test_client.get("/metrics").text
    assert _metric_value(body, "osv_db_present") == "0"
    assert _metric_value(body, "osv_db_stale") == "1"
    # The whole point: never emit a numeric age when freshness is unknown.
    assert _metric_value(body, "osv_db_age_days") is None
    assert "osv_db_age_days" not in body
