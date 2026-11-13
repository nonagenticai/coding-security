"""Freshness of the baked offline OSV CVE database.

The OSV DB is baked into the image at build time (see ``scripts/build_osv_offline_db.py``
and the Dockerfile). The runtime pod's egress to api.osv.dev is blocked by the
ambient-mesh policy BY DESIGN, so the image is the *only* refresh vehicle — a
weekly cron re-bakes it.

That makes a stale DB invisible: the scanner keeps answering, just from older
data. This module surfaces the DB's age so ``/health`` can report it, turning a
silent no-op cron into an observable one.

Freshness is measured at RUNTIME from a build-time stamp on purpose. A
build-time assertion cannot work: if the OSV layer is a cache hit the assertion
never executes, and a cache-hit layer is exactly how an ancient DB ships. Nor
can an image label be used — image build time is not the ``all.zip`` fetch time.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "manifest.json"


@lru_cache(maxsize=8)
def _read_generated_at(db_dir: str) -> str | None:
    """Read ``generated_at`` from the baked manifest, or None if unavailable.

    Cached FOREVER, deliberately: the manifest is baked into an immutable image
    and cannot change while the process lives, so there is nothing for a TTL to
    catch. Only the *parse* is cached — age is recomputed per call — so the
    cache can never serve a stale age. Keyed on ``db_dir`` so each test's
    ``tmp_path`` is a distinct entry; use ``cache_clear()`` to reset.
    """
    path = Path(db_dir) / MANIFEST_FILENAME
    try:
        generated_at = json.loads(path.read_text())["generated_at"]
    except FileNotFoundError:
        logger.warning("OSV manifest missing at %s — DB age unknown", path)
        return None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # ValueError covers json.JSONDecodeError; OSError covers
        # PermissionError / IsADirectoryError.
        logger.warning("OSV manifest at %s unreadable: %s", path, exc)
        return None
    if not isinstance(generated_at, str):
        logger.warning("OSV manifest at %s has non-string generated_at", path)
        return None
    return generated_at


def _parse(generated_at: str) -> datetime | None:
    """Parse an RFC3339 stamp, treating a naive value as UTC."""
    try:
        parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("OSV manifest generated_at is unparseable: %r", generated_at)
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def get_osv_db_status(db_dir: str, max_age_days: int) -> dict[str, Any]:
    """Describe the baked OSV DB's freshness. Never raises.

    ``stale`` is True whenever freshness cannot be established. "Age unknown" IS
    the invisible-stale case — defaulting it to False would rebuild the very bug
    this exists to expose.

    This is an observability signal only. It deliberately does NOT feed the
    health ``status`` or the HTTP code: a stale DB still finds nearly every CVE,
    so failing the probe would crash-loop the pod and remove the scanner
    entirely — strictly worse than serving slightly old data.
    """
    unknown: dict[str, Any] = {
        "present": False,
        "generated_at": None,
        "age_days": None,
        "stale": True,
    }

    generated_at = _read_generated_at(db_dir)
    if generated_at is None:
        return unknown

    parsed = _parse(generated_at)
    if parsed is None:
        return {**unknown, "generated_at": generated_at}

    age_days = (datetime.now(UTC) - parsed).total_seconds() / 86400.0
    return {
        "present": True,
        "generated_at": generated_at,
        "age_days": round(age_days, 1),
        "stale": age_days > max_age_days,
    }
