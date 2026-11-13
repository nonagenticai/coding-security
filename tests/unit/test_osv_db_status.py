"""Tests for the baked OSV DB freshness signal."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from utils.osv_db_status import _read_generated_at, get_osv_db_status


def _write_manifest(db_dir, generated_at, *, schema_version=1):
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "generated_at": generated_at,
                "ecosystems": {"PyPI": {"packages": 15234, "records": 48771}},
            }
        )
    )


def _stamp(days_ago: float) -> str:
    moment = datetime.now(UTC) - timedelta(days=days_ago)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


@pytest.fixture(autouse=True)
def _clear_cache():
    _read_generated_at.cache_clear()
    yield
    _read_generated_at.cache_clear()


def test_fresh_db_is_not_stale(tmp_path):
    _write_manifest(tmp_path, _stamp(0.5))
    status = get_osv_db_status(str(tmp_path), 10)
    assert status["present"] is True
    assert status["stale"] is False
    assert status["age_days"] == pytest.approx(0.5, abs=0.1)


def test_thirteen_day_old_db_is_stale(tmp_path):
    """The real 2026-07-15 incident: 13d old against a 10d threshold."""
    _write_manifest(tmp_path, _stamp(13))
    status = get_osv_db_status(str(tmp_path), 10)
    assert status["present"] is True
    assert status["stale"] is True
    assert status["age_days"] == pytest.approx(13.0, abs=0.1)


def test_boundary_just_over_threshold_is_stale(tmp_path):
    _write_manifest(tmp_path, _stamp(10.1))
    assert get_osv_db_status(str(tmp_path), 10)["stale"] is True


def test_boundary_just_under_threshold_is_fresh(tmp_path):
    _write_manifest(tmp_path, _stamp(9.9))
    assert get_osv_db_status(str(tmp_path), 10)["stale"] is False


def test_missing_dir_reports_unknown_as_stale(tmp_path):
    status = get_osv_db_status(str(tmp_path / "nope"), 10)
    assert status == {
        "present": False,
        "generated_at": None,
        "age_days": None,
        "stale": True,
    }


def test_dir_without_manifest_reports_unknown_as_stale(tmp_path):
    (tmp_path / "PyPI").mkdir()
    assert get_osv_db_status(str(tmp_path), 10)["stale"] is True


def test_malformed_json_reports_unknown_as_stale(tmp_path):
    (tmp_path / "manifest.json").write_text("{not json")
    status = get_osv_db_status(str(tmp_path), 10)
    assert status["present"] is False
    assert status["stale"] is True


def test_manifest_without_generated_at_reports_unknown(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version": 1}))
    assert get_osv_db_status(str(tmp_path), 10)["present"] is False


def test_non_string_generated_at_reports_unknown(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"generated_at": 12345}))
    assert get_osv_db_status(str(tmp_path), 10)["present"] is False


def test_unparseable_generated_at_reports_unknown_but_echoes_value(tmp_path):
    _write_manifest(tmp_path, "not-a-timestamp")
    status = get_osv_db_status(str(tmp_path), 10)
    assert status["present"] is False
    assert status["stale"] is True
    assert status["generated_at"] == "not-a-timestamp"


def test_naive_timestamp_is_treated_as_utc(tmp_path):
    naive = (datetime.now(UTC) - timedelta(days=3)).replace(tzinfo=None)
    _write_manifest(tmp_path, naive.isoformat(timespec="seconds"))
    status = get_osv_db_status(str(tmp_path), 10)
    assert status["present"] is True
    assert status["age_days"] == pytest.approx(3.0, abs=0.1)


def test_parse_is_cached_but_age_is_recomputed(tmp_path):
    """The manifest is immutable in an image, so the parse is cached forever."""
    _write_manifest(tmp_path, _stamp(1))
    first = get_osv_db_status(str(tmp_path), 10)

    _write_manifest(tmp_path, _stamp(99))
    assert get_osv_db_status(str(tmp_path), 10)["generated_at"] == first["generated_at"]

    _read_generated_at.cache_clear()
    assert get_osv_db_status(str(tmp_path), 10)["stale"] is True


def test_cache_is_keyed_per_directory(tmp_path):
    fresh, stale = tmp_path / "fresh", tmp_path / "stale"
    _write_manifest(fresh, _stamp(1))
    _write_manifest(stale, _stamp(30))
    assert get_osv_db_status(str(fresh), 10)["stale"] is False
    assert get_osv_db_status(str(stale), 10)["stale"] is True
