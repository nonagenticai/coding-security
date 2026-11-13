"""Tests for the build-time OSV offline DB indexer.

`scripts/` is outside `pythonpath = ["src"]`, so the module is loaded by path.
It contributes nothing to the `--cov=src` denominator — these are correctness
tests for the build-time stamp the runtime staleness signal depends on.
"""

import importlib.util
import io
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "build_osv_offline_db.py"
_MODULE_NAME = "build_osv_offline_db"


def _load_module():
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: @dataclass resolves annotations via
    # sys.modules[cls.__module__], which is None for an unregistered module.
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load_module()


def _make_zip(path: Path, records: list[dict]) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for record in records:
            zf.writestr(f"{record['id']}.json", json.dumps(record))
    path.write_bytes(buf.getvalue())
    return path


def _record(vuln_id: str, package: str, modified: str) -> dict:
    return {
        "id": vuln_id,
        "summary": f"{vuln_id} summary",
        "modified": modified,
        "affected": [{"package": {"name": package, "ecosystem": "PyPI"}}],
    }


def test_build_db_indexes_packages_and_reports_stats(mod, tmp_path):
    zip_path = _make_zip(
        tmp_path / "all.zip",
        [
            _record("PYSEC-1", "python-jose", "2026-07-01T00:00:00Z"),
            _record("PYSEC-2", "requests", "2026-07-14T22:03:11Z"),
            _record("PYSEC-3", "requests", "2026-07-02T00:00:00Z"),
        ],
    )
    stats = mod.build_db(zip_path, tmp_path / "db", "PyPI")

    assert stats.packages == 2
    assert stats.records == 3
    assert stats.newest_record_modified == "2026-07-14T22:03:11Z"
    assert (tmp_path / "db" / "PyPI" / "requests.json").is_file()
    assert len(json.loads((tmp_path / "db" / "PyPI" / "requests.json").read_text())) == 2


def test_package_names_are_normalized(mod, tmp_path):
    zip_path = _make_zip(
        tmp_path / "all.zip", [_record("P-1", "Python_Jose.X", "2026-01-01T00:00:00Z")]
    )
    mod.build_db(zip_path, tmp_path / "db", "PyPI")
    assert (tmp_path / "db" / "PyPI" / "python-jose-x.json").is_file()


async def test_runtime_lookup_filename_matches_every_baked_file(mod, tmp_path):
    """The runtime must open the SAME filename the builder wrote.

    Regression (2026-11-04): the builder sanitises ``/`` and ``\\`` to ``_``
    (``@scope/pkg`` -> ``@scope_pkg.json``), but the runtime mirrored only the
    name normaliser. Every scoped npm package then looked up a nested path that
    never exists and silently read as 'no advisories'. This runs the REAL
    offline scan against a REAL built DB, so it fails if the call site stops
    matching the builder (a helper-only assertion would not).
    """
    from models.package_manager_models import ExternalPackage
    from services.dependency_visualization import DependencyVulnerabilityScanner

    def _vulnerable(vuln_id: str, name: str) -> dict:
        return {
            "id": vuln_id,
            "summary": f"{vuln_id} summary",
            "details": "",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": name},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
                    ],
                }
            ],
            "references": [],
            "published": "",
            "modified": "2026-01-01T00:00:00Z",
        }

    names = [
        "python-jose",  # plain
        "lodash.merge",  # npm dot-separated
        "@axe-core/playwright",  # npm scoped
        "@formatjs/ecma402-abstract",  # npm scoped + dot/underscore
        "My_Pkg.Name",  # mixed case / separator
    ]
    zip_path = _make_zip(
        tmp_path / "all.zip", [_vulnerable(f"T-{i}", name) for i, name in enumerate(names)]
    )
    mod.build_db(zip_path, tmp_path / "db", "npm")
    eco_dir = tmp_path / "db" / "npm"
    assert len(list(eco_dir.iterdir())) == len(names)

    scanner = DependencyVulnerabilityScanner(
        timeout=5, enable_cache=False, offline_db_dir=str(tmp_path / "db")
    )
    packages = [ExternalPackage(name=name, version="1.0.0", ecosystem="npm") for name in names]
    found = await scanner.scan_vulnerabilities(packages)
    assert scanner.lookup_errors == []
    assert sorted(v.package_name for v in found) == sorted(names)


def test_records_with_no_package_are_not_counted(mod, tmp_path):
    zip_path = _make_zip(
        tmp_path / "all.zip",
        [{"id": "ORPHAN-1", "modified": "2026-07-01T00:00:00Z", "affected": []}],
    )
    stats = mod.build_db(zip_path, tmp_path / "db", "PyPI")
    assert stats.packages == 0
    assert stats.records == 0


def test_manifest_written_at_db_root_not_inside_ecosystem(mod, tmp_path):
    """A root manifest cannot collide with a package named 'manifest'."""
    db = tmp_path / "db"
    stats = mod.BuildStats(
        packages=15234, records=48771, newest_record_modified="2026-07-14T22:03:11Z"
    )
    path = mod.write_manifest(db, "PyPI", stats, "2026-07-15T04:17:33Z")

    assert path == db / "manifest.json"
    assert not (db / "PyPI" / "manifest.json").exists()

    manifest = json.loads(path.read_text())
    assert manifest["schema_version"] == 1
    assert manifest["generated_at"] == "2026-07-15T04:17:33Z"
    assert manifest["ecosystems"]["PyPI"]["packages"] == 15234
    assert manifest["ecosystems"]["PyPI"]["records"] == 48771
    assert manifest["ecosystems"]["PyPI"]["newest_record_modified"] == "2026-07-14T22:03:11Z"
    assert manifest["ecosystems"]["PyPI"]["source"].endswith("/PyPI/all.zip")
    datetime.fromisoformat(manifest["generated_at"].replace("Z", "+00:00"))


def test_manifest_merge_preserves_other_ecosystems(mod, tmp_path):
    db = tmp_path / "db"
    stats = mod.BuildStats(packages=10, records=20, newest_record_modified=None)
    mod.write_manifest(db, "PyPI", stats, "2026-07-15T04:17:33Z")
    mod.write_manifest(db, "npm", stats, "2026-07-16T04:17:33Z")

    manifest = json.loads((db / "manifest.json").read_text())
    assert set(manifest["ecosystems"]) == {"PyPI", "npm"}
    # Top-level generated_at tracks the MOST RECENT bake — that is what the
    # runtime staleness check reads.
    assert manifest["generated_at"] == "2026-07-16T04:17:33Z"


def test_manifest_merge_survives_a_corrupt_existing_manifest(mod, tmp_path):
    db = tmp_path / "db"
    db.mkdir()
    (db / "manifest.json").write_text("{not json")
    stats = mod.BuildStats(packages=1, records=1, newest_record_modified=None)
    mod.write_manifest(db, "PyPI", stats, "2026-07-15T04:17:33Z")
    assert json.loads((db / "manifest.json").read_text())["ecosystems"]["PyPI"]["packages"] == 1


def test_main_stamps_a_parseable_recent_generated_at(mod, tmp_path):
    zip_path = _make_zip(
        tmp_path / "all.zip", [_record("PYSEC-1", "requests", "2026-07-01T00:00:00Z")]
    )
    db = tmp_path / "db"
    assert mod.main([str(zip_path), str(db), "--ecosystem", "PyPI"]) == 0

    stamp = json.loads((db / "manifest.json").read_text())["generated_at"]
    assert stamp.endswith("Z")
    age = (datetime.now(UTC) - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
    assert 0 <= age < 60


def test_main_returns_1_when_zip_missing(mod, tmp_path):
    assert mod.main([str(tmp_path / "nope.zip"), str(tmp_path / "db")]) == 1
