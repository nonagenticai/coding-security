"""Prometheus text exposition for coding-security — the single source of truth.

This module is the service's metrics "registry". It is deliberately the ONLY
place the exposition text is built, because it is rendered by TWO listeners:

  1. the app port (:8693) ``GET /metrics`` route in ``app_factory``, and
  2. the dedicated metrics port (:9693) served by ``metrics_server``.

Keeping one renderer is what makes the two ports byte-identical, so the
Prometheus scrape can be MOVED from (1) to (2) without any change to the series
it produces. Do not inline a second copy of this text anywhere.

Why a dedicated port exists at all: the cross-namespace AuthorizationPolicy that
admits the (non-ambient, therefore plaintext and principal-less) Prometheus
scrape can only match on ``source.ipBlocks``, i.e. the whole 10.42.0.0/16 pod
CIDR. Because metrics were served on the APP port, that grant had to name the
app port, which handed every pod in the cluster an ALLOW to the entire API.
Serving metrics on their own port makes the grant port-scopable to a listener
that exposes nothing but metrics — exactly the shape the :9121 redis-exporter
grants already have.

Hand-rolled rather than ``prometheus_client`` on purpose: a security-scanning
service should not grow a metrics dependency for three gauges.
"""

from __future__ import annotations

# Prometheus text exposition format v0.0.4 — the content type BOTH listeners
# must answer with, so a scrape config is identical against either port.
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# The one path either listener serves metrics on.
METRICS_PATH = "/metrics"


def render_metrics() -> str:
    """Render the OSV CVE-DB freshness gauges in Prometheus text format.

    Exposes the age of the BAKED offline OSV CVE database, so a pod that goes
    stale WHILE RUNNING (a failed weekly re-bake, a rollback) is alertable — the
    ``/health`` block is only read by the CI smoke gate at build time.
    """
    from config.settings import get_settings
    from utils.osv_db_status import get_osv_db_status

    settings = get_settings()
    osv = get_osv_db_status(settings.osv_offline_db_dir, settings.osv_db_max_age_days)
    labels = 'service="coding-security"'
    lines = [
        "# HELP osv_db_present Baked OSV CVE DB manifest readable (1) or not (0).",
        "# TYPE osv_db_present gauge",
        f"osv_db_present{{{labels}}} {int(osv['present'])}",
        "# HELP osv_db_stale Baked OSV CVE DB stale or freshness unknown (1), else fresh (0).",
        "# TYPE osv_db_stale gauge",
        f"osv_db_stale{{{labels}}} {int(osv['stale'])}",
    ]
    # Emit age ONLY when known. The manifest-missing case has no numeric age;
    # present/stale still carry the signal so an alert can fire on "unknown".
    age_days = osv["age_days"]
    if age_days is not None:
        lines += [
            "# HELP osv_db_age_days Age in days of the baked OSV CVE DB.",
            "# TYPE osv_db_age_days gauge",
            f"osv_db_age_days{{{labels}}} {age_days}",
        ]
    return "\n".join(lines) + "\n"
