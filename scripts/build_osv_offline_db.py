#!/usr/bin/env python3
"""Build a per-package OSV offline database from an ecosystem ``all.zip`` export.

The OSV project publishes one zip per ecosystem at
``https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip``.
That zip is a *flat* set of ``<VULN-ID>.json`` records with **no package
index**, so a per-package lookup at scan time would have to read the whole set.
This build-time script re-groups the flat records into one
``<out_dir>/<ECOSYSTEM>/<package-name>.json`` file per package (a JSON list of
records), so the runtime scanner does an O(1) file open per dependency.

It runs at Docker build time on a CI runner *with* network egress — the
runtime pod is egress-blocked by the ambient-mesh policy and never re-fetches.
Pure stdlib (no app imports) so it stays out of the ``src`` coverage denominator.

Each record is field-stripped to only what the runtime parser reads
(``_parse_osv_vulnerability`` in ``dependency_visualization.py``) to keep the
baked image layer small while preserving ``fixed_versions`` for the upgrade
engine.

Usage::

    python build_osv_offline_db.py <all.zip> <out_dir> [--ecosystem PyPI]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_NORMALIZE_RE = re.compile(r"[-_.]+")

# Manifest lives at the DB ROOT, a sibling of the <ecosystem>/ subdirs — never
# inside one. Packages are written to <out_dir>/<ECOSYSTEM>/<pkg>.json, so a
# root-level file cannot collide with a package name.
MANIFEST_FILENAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1

_SOURCE_URL_TEMPLATE = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


def normalize_name(name: str) -> str:
    """Normalise a package name so the index and the runtime lookup agree.

    Mirrors ``_normalize_pkg_name`` in ``dependency_visualization.py`` —
    lower-case and collapse runs of ``- _ .`` to a single ``-`` (PEP 503 for
    PyPI; harmless and stable for the other ecosystems we mirror).
    """
    return _NORMALIZE_RE.sub("-", name.strip().lower())


# Only the fields the runtime parser (_parse_osv_vulnerability /
# _extract_severity_from_osv / _extract_version_ranges / _affects_installed_version)
# actually reads. Everything else is dropped to shrink the image layer.
_KEEP_FIELDS = (
    "id",
    "summary",
    "details",
    "severity",
    "affected",
    "references",
    "published",
    "modified",
    "withdrawn",
    "database_specific",
)


def _strip_record(record: dict) -> dict:
    """Keep only the fields the runtime parser reads."""
    return {k: record[k] for k in _KEEP_FIELDS if k in record}


def _package_names(record: dict) -> set[str]:
    """Lower-cased package names this record affects (one record can list many)."""
    names: set[str] = set()
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        name = pkg.get("name")
        if name:
            names.add(normalize_name(str(name)))
    return names


@dataclass(frozen=True)
class BuildStats:
    """What a single-ecosystem bake produced, for the manifest."""

    packages: int
    records: int
    # Newest ``modified`` across the indexed records, or None if no record
    # carried one. Distinguishes "our cron stopped re-baking" from "OSV's own
    # export is frozen" — without it a stale DB and a stale UPSTREAM look
    # identical. OSV emits RFC3339, which sorts lexicographically, so max() on
    # the raw string is correct and needs no parsing.
    newest_record_modified: str | None


def build_db(zip_path: Path, out_dir: Path, ecosystem: str) -> BuildStats:
    """Group the flat OSV zip into per-package files. Returns the bake stats."""
    by_package: dict[str, list[dict]] = defaultdict(list)
    indexed_ids: set[str] = set()
    newest_modified: str | None = None

    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                record = json.loads(zf.read(name))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"WARN: skipping malformed record {name}: {exc}", file=sys.stderr)
                continue
            stripped = _strip_record(record)
            pkg_names = _package_names(record)
            if not pkg_names:
                continue
            for pkg_name in pkg_names:
                by_package[pkg_name].append(stripped)
            indexed_ids.add(str(record.get("id") or name))
            modified = stripped.get("modified")
            if isinstance(modified, str) and (
                newest_modified is None or modified > newest_modified
            ):
                newest_modified = modified

    eco_dir = out_dir / ecosystem
    eco_dir.mkdir(parents=True, exist_ok=True)
    for pkg_name, records in by_package.items():
        # Sanitise the filename: PyPI normalises to lowercase, and names never
        # contain path separators, but defend against a hostile record anyway.
        safe = pkg_name.replace("/", "_").replace("\\", "_")
        (eco_dir / f"{safe}.json").write_text(json.dumps(records, separators=(",", ":")))

    return BuildStats(
        packages=len(by_package),
        records=len(indexed_ids),
        newest_record_modified=newest_modified,
    )


def write_manifest(
    out_dir: Path,
    ecosystem: str,
    stats: BuildStats,
    generated_at: str,
) -> Path:
    """Write/merge ``<out_dir>/manifest.json`` and return its path.

    Merges any pre-existing ``ecosystems`` entries so baking a second ecosystem
    into the same dir does not clobber the first. The top-level ``generated_at``
    always reflects the most recent bake — that is what the runtime staleness
    check reads.
    """
    path = out_dir / MANIFEST_FILENAME
    ecosystems: dict[str, dict] = {}
    if path.is_file():
        try:
            prior = json.loads(path.read_text())
            existing = prior.get("ecosystems")
            if isinstance(existing, dict):
                ecosystems = existing
        except (OSError, ValueError) as exc:
            print(f"WARN: ignoring unreadable existing manifest: {exc}", file=sys.stderr)

    ecosystems[ecosystem] = {
        "packages": stats.packages,
        "records": stats.records,
        "newest_record_modified": stats.newest_record_modified,
        "source": _SOURCE_URL_TEMPLATE.format(ecosystem=ecosystem),
        "generated_at": generated_at,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "generated_at": generated_at,
                "ecosystems": ecosystems,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path, help="Path to the OSV <ECOSYSTEM>/all.zip")
    parser.add_argument("out_dir", type=Path, help="Output DB directory (e.g. /opt/osv-db)")
    parser.add_argument(
        "--ecosystem",
        default="PyPI",
        help="OSV ecosystem name (subdir under out_dir). Default: PyPI",
    )
    args = parser.parse_args(argv)

    if not args.zip_path.is_file():
        print(f"ERROR: {args.zip_path} not found", file=sys.stderr)
        return 1

    # Stamp BEFORE build_db: the zip was fetched by the curl immediately
    # preceding this process, so process start ~= fetch time. Stamping after
    # build_db would record the INDEX time and drift by the whole indexing run.
    generated_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    stats = build_db(args.zip_path, args.out_dir, args.ecosystem)
    manifest = write_manifest(args.out_dir, args.ecosystem, stats, generated_at)
    print(
        f"Indexed {stats.packages} {args.ecosystem} packages "
        f"({stats.records} records) into {args.out_dir / args.ecosystem}"
    )
    print(f"Wrote {manifest} (generated_at={generated_at})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
