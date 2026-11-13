"""Application settings using Pydantic BaseSettings.

Service URLs default to empty strings; the production validator
(`model_post_init`) raises if any required URL is missing. Real values come
from the coding-security Deployment env block in gitops-production
(``clusters/strato/services/coding-security/``).

See ``gitops-production/docs/config-externalization-policy.md`` and the
canonical reference at ``inference-router/src/settings.py``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import ClassVar

from coding_client.config import BaseMicroserviceSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseMicroserviceSettings):
    """Configuration settings loaded from environment variables.

    URLs intentionally default to ``""`` — they MUST be provided by env in
    production. ``model_post_init`` raises in production if any
    ``_REQUIRED_IN_PRODUCTION`` field is empty. Tests / local dev set
    ``ENVIRONMENT`` to anything other than ``"production"`` to bypass.
    """

    service_name: str = "coding-security"
    version: str = "1.0.0"
    environment: str = "production"
    port: int = 8693
    # Dedicated Prometheus metrics listener (see src/metrics_server.py). Metrics
    # are served on BOTH this port and the app port; this one exposes NOTHING
    # else, so the cross-namespace scrape grant — which can only match the whole
    # 10.42.0.0/16 pod CIDR, Prometheus being non-ambient and therefore
    # plaintext — can be port-scoped to it instead of to the app port and its
    # entire API surface. 9693 mirrors app port 8693 in the 9xxx exporter range
    # (cf. :9121 redis, :9187 postgres); verified unused fleet-wide.
    # 0 = bind an ephemeral port (tests only).
    metrics_port: int = 9693
    # Kill switch. The listener is additive — the app-port /metrics keeps
    # working either way — so turning it off degrades nothing that works today.
    metrics_server_enabled: bool = True
    log_level: str = "INFO"
    enable_docs: bool = False
    enable_auth: bool = True
    # NB no ``default_tenant_id`` field. It carried the literal ``"n8n-dev"``
    # with ZERO readers — ``auth/tenant.py`` imports the name from
    # ``coding_client.auth.tenant``, where it is ``None`` when unset. A dead
    # field with that literal is a booby trap, not inert: it is the stale
    # pre-uuid7 label of a tenant that really exists, so the next reader would
    # have got a tenant nobody chose rather than a failure. This repo already
    # paid for that once — see ``routers/security/_common.py``, which used to
    # hardcode ``X-Tenant-Id: "n8n-dev"`` outright.

    # Service URLs — placeholders; real values come from gitops env.
    database_url: str = ""
    redis_url: str = ""
    otel_endpoint: str = ""
    containers_service_url: str = ""
    # Workspace root inside a coding-containers workspace pod (env WORKSPACE_ROOT):
    # the remote scan roots and the .repos/ listing are built under it.
    workspace_root: str = "/workspace"
    # github_service_url is OPTIONAL — only needed when the
    # /upgrade and /upgrade-major routes are called with commit=true or
    # open_pr=true. Read-only flows don't depend on it.
    github_service_url: str = ""

    cors_origins: list[str] = ["*"]

    # NVD API
    nvd_api_key: str | None = None

    # Docker registry for image scanning.
    docker_registry_url: str = ""
    docker_registry_username: str = "registry"
    docker_registry_password: str = ""

    # Scanner timeouts
    trivy_scan_timeout: int = 300
    grype_scan_timeout: int = 300
    syft_scan_timeout: int = 180

    # Container-scan wall-clock budgets (env: SECURITY_SCAN_BUDGET_SECONDS,
    # SECURITY_FETCH_TIMEOUT_SECONDS). Ops-tunable without a code change: the
    # scan of a real repo can outrun the default and get bounded to a degraded
    # grade F, so this is deliberately configurable rather than a hardcoded
    # constant. Observability/tuning only — never required at startup.
    security_scan_budget_seconds: float = 60.0
    security_fetch_timeout_seconds: float = 120.0

    # Async (task_id + poll) container-scan model (env:
    # SECURITY_ASYNC_SCAN_BUDGET_SECONDS, SECURITY_SCAN_TASK_TTL_SECONDS). The
    # async submit endpoint runs the scan in a background task under a wider
    # wall-clock budget than the sync path (no upstream gateway budget to fail
    # under — the caller polls for the result), and the completed record is
    # cached in Redis for the TTL below (24h) so a poll after completion returns
    # it. Observability/tuning only — never required at startup.
    security_async_scan_budget_seconds: float = 300.0
    security_scan_task_ttl_seconds: int = 86400

    # Poll-time staleness bound for async (task_id + poll) scan records (env:
    # SECURITY_SCAN_STALE_AFTER_SECONDS). A background task stamps updated_at on
    # every write and re-stamps a running heartbeat once its slow fetch phase is
    # done; if the poll finds a queued/running record whose updated_at is older
    # than this bound (or missing), the worker is presumed dead and the poll
    # derives status=failed+stale instead of a permanent running. Shared by both
    # the container-security and dependency async paths — the dependency fetch is
    # a shorter (~60s) phase, so this default is deliberately conservative for
    # it. Observability/tuning only — never required at startup.
    security_scan_stale_after_seconds: float = 600.0

    # Async (task_id + poll) dependency-scan model (env:
    # DEPENDENCY_SCAN_ASYNC_BUDGET_SECONDS). Wall-clock budget for the background
    # dependency scan submitted via POST /{container_name}/scan/async; the async
    # record reuses ``security_scan_task_ttl_seconds`` above for its Redis TTL.
    # Observability/tuning only — never required at startup.
    dependency_scan_async_budget_seconds: float = 300.0

    # Durable async-scan worker (Redis Streams consumer group). The async scan
    # submit endpoints enqueue a job onto ``scan_stream`` instead of running it
    # in an in-process FastAPI BackgroundTask; a consumer-group worker started in
    # the app lifespan drains the stream, bounding concurrency by the worker's
    # read-loop count (was unbounded with BackgroundTasks). All knobs are
    # tuning-only — never required at startup — so they stay out of
    # ``_REQUIRED_IN_PRODUCTION``.
    scan_worker_enabled: bool = True
    scan_worker_concurrency: int = 2
    scan_stream: str = "security:scan:jobs"
    scan_consumer_group: str = "coding-security-scanner"
    scan_consumer_name: str = "worker-0"
    scan_worker_block_ms: int = 5000
    scan_reclaim_interval_seconds: float = 60.0
    scan_reclaim_min_idle_seconds: int = 900
    scan_max_deliveries: int = 3
    scan_stream_maxlen: int = 10000

    # Baked offline OSV database (per-package records). When present, the
    # dependency-CVE scanner reads CVEs from here instead of api.osv.dev —
    # the pod's egress to OSV is blocked by the ambient-mesh policy. Absence
    # degrades to the (egress-blocked) online path; it must NOT crash startup,
    # so it stays out of _REQUIRED_IN_PRODUCTION. The Dockerfile bakes the DB
    # and exports OSV_OFFLINE_DB_DIR, which the scanner reads directly.
    osv_offline_db_dir: str = "/opt/osv-db"

    # Age at which /health reports the baked OSV DB as stale. The re-bake cron
    # is weekly, so a healthy age sawtooths 0->7d; add promote/rollout lag and
    # call it 8. One MISSED cycle reaches 15d. 10 therefore never fires in a
    # healthy week but trips ~3 days into a missed one. Deliberately not 14:
    # that would have let the real 13-day 2026-07-15 staleness pass silently.
    # Observability only — absence never fails startup, so it stays out of
    # _REQUIRED_IN_PRODUCTION.
    osv_db_max_age_days: int = 10

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)

    # Fields whose absence should fail loud at startup in production.
    # Diagnostic / optional fields (nvd_api_key, docker_registry_password)
    # stay out.
    _SERVICE_NAME: ClassVar[str] = "coding-security"
    _REQUIRED_IN_PRODUCTION: ClassVar[tuple[str, ...]] = (
        "database_url",
        "redis_url",
        "containers_service_url",
        "docker_registry_url",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached application settings singleton."""
    return Settings()
