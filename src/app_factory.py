"""Application factory for the coding-security service."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import redis.asyncio as aioredis
from coding_client.api.logging_setup import configure_logging
from coding_client.api.request_logging import HealthCheckFilter, RequestLoggingMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

if TYPE_CHECKING:
    from config.settings import Settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level resources (initialised in lifespan)
# ---------------------------------------------------------------------------
_redis: aioredis.Redis | None = None


def build_redis(settings: Settings) -> aioredis.Redis:
    """The service's Redis client.

    redis-py 8 defaults ``socket_timeout`` to 5 s, and the scan worker's idle
    XREADGROUP blocks server-side for ``scan_worker_block_ms`` (5 s): the read
    timeout raced the server's empty reply on every idle poll and the loser
    logged a TimeoutError traceback (#117). The read timeout must outlast the
    block.
    """
    return aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=settings.scan_worker_block_ms / 1000 + 5,
    )


def get_redis() -> aioredis.Redis:
    """Return the shared Redis connection (available after startup)."""
    if _redis is None:
        raise RuntimeError("Redis not initialised -- called before lifespan startup?")
    return _redis


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage application lifespan."""
    global _redis  # noqa: PLW0603

    startup_time = time.time()
    service_name = os.getenv("SERVICE_NAME", "coding-security")
    version = os.getenv("VERSION", "1.0.0")
    environment = os.getenv("ENVIRONMENT", "production")

    logger.info("Starting %s v%s (%s)", service_name, version, environment)

    try:
        # Database migrations handled by K8s initContainer
        print("[startup] Database migrations handled by K8s initContainer", flush=True)

        # -- Redis ----------------------------------------------------------
        try:
            from config.settings import get_settings

            settings = get_settings()
            _redis = build_redis(settings)
            result = _redis.ping()
            if hasattr(result, "__await__"):
                await result
            logger.debug("Redis ping result: %s", result)
            logger.info("Redis connected: %s", settings.redis_url)
        except Exception as exc:
            logger.warning("Redis connection failed (non-fatal): %s", exc)
            _redis = None

        # -- Pre-warm the SAST detector singleton ---------------------------
        # Building it runs blocking ``subprocess.run --version`` probes in the
        # bandit/secrets scanner __init__s (up to ~20s if a tool binary is
        # wedged). Warm it OFF-THREAD now, before serving traffic, so the sync
        # __init__ callers (SecurityScanService / UnifiedSecurityScanner, which
        # can't await) and the first async request all hit a cached instance
        # instead of blocking the event loop. A wedged binary must NOT crash
        # startup/readiness — on failure we log and continue (the sync fallback
        # still builds lazily on first use).
        try:
            from services.security_detector import get_security_detector_async

            await get_security_detector_async()
            logger.info("SAST detector singleton pre-warmed")
        except Exception as exc:
            logger.warning("SAST detector pre-warm failed (non-fatal): %s", exc)

        # -- Durable async-scan worker --------------------------------------
        # Drains the Redis-Streams scan queue in-process (replaces the old
        # in-request BackgroundTasks execution). Lazy import so app_factory has
        # no import-time dependency on the worker (which imports the scan
        # runner / routers surface). Skipped in tests and when Redis is down.
        app.state.scan_worker = None
        try:
            from config.settings import get_settings

            settings = get_settings()
            if (
                settings.scan_worker_enabled
                and environment not in ("test", "testing")
                and _redis is not None
            ):
                from services.scan_worker import ScanWorker

                worker = ScanWorker(settings, get_redis)
                worker.start()
                app.state.scan_worker = worker
                logger.info("Durable async-scan worker started")
        except Exception as exc:
            logger.warning("Scan worker start failed (non-fatal): %s", exc)
            app.state.scan_worker = None

        # -- Dedicated-port metrics listener --------------------------------
        # Serves ONLY /metrics on its own port, in ADDITION to the app-port
        # /metrics route below (which is untouched and keeps working). Exists so
        # the cross-namespace Prometheus scrape grant — an ALLOW that can only
        # match source.ipBlocks 10.42.0.0/16, because Prometheus is non-ambient
        # and its scrape therefore carries neither a SPIFFE principal nor a
        # source namespace — can later be port-scoped to a listener with no API
        # surface, rather than naming the app port and handing every pod in the
        # cluster an ALLOW to the whole API.
        #
        # Non-fatal on failure, matching /health's reasoning about the OSV DB:
        # crash-looping the pod removes the scanner altogether, which is strictly
        # worse than losing one gauge that is still readable on the app port.
        app.state.metrics_server = None
        try:
            from config.settings import get_settings

            settings = get_settings()
            if settings.metrics_server_enabled:
                from metrics_server import MetricsServer

                metrics_server = MetricsServer(settings.metrics_port)
                metrics_server.start()
                app.state.metrics_server = metrics_server
                logger.info("Metrics listener started on port %s", metrics_server.bound_port)
        except Exception as exc:
            logger.warning("Metrics listener start failed (non-fatal): %s", exc)
            app.state.metrics_server = None

        # Telemetry is NOT set up here. It used to be, and it exported nothing:
        # FastAPIInstrumentor.instrument_app() inside a lifespan is a silent
        # no-op (Starlette has already built the middleware stack), and the
        # endpoint it read -- OTEL_EXPORTER_OTLP_ENDPOINT -- is not the variable
        # this fleet provisions. See create_app(), which calls setup_tracing()
        # at construction time and raises if anyone moves it back in here.

        startup_duration = time.time() - startup_time
        logger.info("%s ready! Started in %.2fs", service_name, startup_duration)
        yield
    except Exception as e:
        logger.error("Error during %s startup: %s", service_name, e)
        raise
    finally:
        # Stop the worker BEFORE closing Redis so its loops don't hit a closed
        # connection mid-shutdown (an in-flight job is left un-acked → reclaimed
        # on the next start).
        worker = getattr(app.state, "scan_worker", None)
        if worker is not None:
            await worker.stop()
        metrics_server = getattr(app.state, "metrics_server", None)
        if metrics_server is not None:
            metrics_server.stop()
            logger.info("Metrics listener stopped")
        if _redis is not None:
            await _redis.aclose()
            logger.info("Redis connection closed")
        logger.info("Shutting down %s", service_name)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    configure_logging()

    from config.settings import get_settings

    settings = get_settings()

    app = FastAPI(
        title=settings.service_name,
        description=(
            "Static security analysis service for codebases managed by the "
            "code-graph-helper platform.\n\n"
            "**Auth:** Istio ext_authz via `coding-client` AuthMiddleware. "
            "Tenant isolation via `X-Tenant-Id` header "
            "(falls back to `DEFAULT_TENANT_ID`).\n\n"
            "**Endpoint groups:**\n\n"
            "- `/api/security` -- Code vulnerability scanning "
            "(SQL injection, XSS, command injection, hardcoded secrets, "
            "weak crypto, buffer overflows), sandbox config generation, "
            "container security scans with graded reports\n"
            "- `/api/dependencies` -- Package dependency analysis with "
            "CVE detection via OSV.dev, outdated/vulnerable package listing\n"
            "- `/api/dependencies/system` -- System-level dependency detection "
            "(apt/yum/brew/etc.), install script / Dockerfile snippet / "
            "CI config generation"
        ),
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    _add_middlewares(app, settings)
    _add_exception_handlers(app)
    _include_routers(app)

    # Tracing, at construction time. setup_tracing() raises if it is ever called
    # after the app has started, because the instrumentation would be discarded
    # in silence there -- which is exactly how this service went untraced while
    # logging that tracing was enabled. It also instruments outbound httpx, so
    # coding-security becomes a source of service-graph edges and not only a
    # target.
    from coding_client.telemetry import setup_tracing

    setup_tracing(app, settings.service_name)

    # OpenAPI security (KAG standard)
    from coding_client.api.openapi_config import configure_openapi

    configure_openapi(
        app,
        protected_prefixes={"/api/security", "/api/dependencies"},
        public_endpoints={"/", "/health", "/docs", "/redoc", "/openapi.json"},
    )

    return app


def _add_middlewares(app: FastAPI, settings) -> None:
    """Add middlewares in KAG standard order: CORS -> RequestLogging -> Auth."""
    enable_auth = getattr(settings, "enable_auth", True)
    if isinstance(enable_auth, str):
        enable_auth = enable_auth.lower() == "true"

    # Auth middleware (sets request.state.user from Istio headers)
    if enable_auth:
        try:
            from coding_client.auth.middleware import AuthMiddleware
        except ImportError as exc:
            # A failed import must fail CLOSED: silently skipping the middleware
            # would run the whole service with no authentication at all — the
            # exact defect this branch used to have (it logged a warning and
            # continued). Mirrors the production-fail-fast contract already used
            # for required settings (coding_client's
            # BaseMicroserviceSettings._enforce_required_in_production): raise in
            # production, warn otherwise so a partially-installed dev checkout can
            # still boot. Matches coding-testing's app_factory._add_middlewares.
            environment = getattr(settings, "environment", "production")
            if environment == "production":
                raise RuntimeError(
                    "coding-security cannot import coding_client.auth.middleware."
                    "AuthMiddleware; refusing to start in production without "
                    f"authentication. Original import error: {exc}"
                ) from exc
            logger.warning(
                "AuthMiddleware not available (%s); starting WITHOUT authentication "
                "because environment=%s. This would be a hard failure in production.",
                exc,
                environment,
            )
        else:
            app.add_middleware(AuthMiddleware)  # type: ignore[invalid-argument-type]
            logger.info("Auth middleware enabled")
    else:
        logger.warning("Auth middleware DISABLED (ENABLE_AUTH=false)")

    # Request logging (generates request_id, adds X-Request-ID + X-Processing-Time)
    app.add_middleware(RequestLoggingMiddleware)  # type: ignore[invalid-argument-type]

    # CORS
    cors_origins = getattr(settings, "cors_origins", ["*"])
    app.add_middleware(
        CORSMiddleware,  # type: ignore[invalid-argument-type]
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Suppress /health noise from uvicorn access logs
    logging.getLogger("uvicorn.access").addFilter(HealthCheckFilter())


def _add_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers for standardized error responses."""
    from coding_client.api.exception_handlers import register_exception_handlers

    register_exception_handlers(app)


def _include_routers(app: FastAPI) -> None:
    """Include all routers."""

    @app.get("/health", operation_id="health_check")
    async def health():
        # osv_db reports the age of the BAKED offline CVE database. The pod
        # cannot re-download it (egress to OSV is blocked by design), so only a
        # rebuild refreshes it and a stale DB is otherwise invisible — the
        # scanner keeps answering, just from older data. `stale` is an
        # observability signal and never affects `status` or the HTTP code:
        # failing the probe would crash-loop the pod and remove the scanner
        # altogether, which is worse than slightly old data.
        from config.settings import get_settings
        from utils.osv_db_status import get_osv_db_status

        settings = get_settings()
        return {
            "status": "ok",
            "service": os.getenv("SERVICE_NAME", "coding-security"),
            "version": os.getenv("VERSION", "1.0.0"),
            "osv_db": get_osv_db_status(settings.osv_offline_db_dir, settings.osv_db_max_age_days),
        }

    @app.get("/metrics", operation_id="metrics", include_in_schema=False)
    async def metrics():
        # Prometheus text exposition of the baked OSV CVE DB's freshness, so a
        # pod that goes stale WHILE RUNNING (a failed weekly re-bake, a rollback)
        # is alertable — the /health block is only read by the CI smoke gate at
        # build time. `/metrics` is auth-exempt via the coding_client
        # AuthMiddleware PUBLIC_PATHS, so an in-mesh scrape is not blocked.
        #
        # ⚠️ KEEP THIS ROUTE. The dedicated metrics port (see metrics_server.py)
        # is ADDITIVE: removing this one would take the live scrape dark the
        # instant it merged, before the scrape has been moved — the exact
        # failure mode of gitops #2298 (8 targets up==0 in 14s, OsvCveDbStale
        # unable to fire). Both listeners render from metrics_exposition, so
        # they are byte-identical by construction.
        from starlette.responses import PlainTextResponse

        from metrics_exposition import CONTENT_TYPE, render_metrics

        return PlainTextResponse(render_metrics(), media_type=CONTENT_TYPE)

    @app.get("/", operation_id="get_root")
    async def root():
        return {
            "service": os.getenv("SERVICE_NAME", "coding-security"),
            "version": os.getenv("VERSION", "1.0.0"),
            "docs": "/docs",
            "health": "/health",
        }

    from routers.dependencies import router as dependencies_router
    from routers.security import router as security_router
    from routers.system_dependencies import router as system_dependencies_router

    app.include_router(security_router, prefix="/api/security", tags=["Security"])
    app.include_router(dependencies_router, prefix="/api/dependencies", tags=["Dependencies"])
    app.include_router(
        dependencies_router,
        prefix="/api/security/dependencies",
        tags=["Dependencies"],
        include_in_schema=False,
    )
    app.include_router(
        system_dependencies_router,
        prefix="/api/dependencies/system",
        tags=["System Dependencies"],
    )
