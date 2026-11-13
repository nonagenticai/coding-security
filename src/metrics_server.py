"""Dedicated-port Prometheus metrics listener.

Serves ``GET /metrics`` — and NOTHING else — on its own TCP port, alongside the
main application listener. See ``metrics_exposition`` for why this exists: it
lets the pod-CIDR AuthorizationPolicy that admits the plaintext Prometheus
scrape be port-scoped to a listener with no application surface, instead of
naming the app port and thereby granting the whole cluster access to the API.

Design notes
------------
* The listener is a bare ASGI callable, not a FastAPI app. That is the security
  property, enforced structurally rather than by configuration: there is no
  router to mount an application route onto, so this port CANNOT grow one by
  accident. Every path that is not ``/metrics`` gets a 404 with an empty body.
* No authentication, by design and by necessity. Prometheus lives in a
  non-ambient namespace, so its scrape arrives as plaintext with no SPIFFE
  principal and no credentials of any kind. The app-port ``/metrics`` is
  likewise auth-exempt via the coding_client AuthMiddleware ``PUBLIC_PATHS``.
  The exposition contains only OSV CVE-DB freshness gauges — no tenant data, no
  application data.
* It runs on its own thread with its own event loop rather than as a task on the
  app's loop. uvicorn's ``Server.serve()`` captures process signal handlers when
  it runs on the main thread; doing that from inside the app's lifespan would
  clobber the OUTER uvicorn's handlers and break graceful shutdown. Off the main
  thread, uvicorn's ``capture_signals()`` is a documented no-op.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

from metrics_exposition import CONTENT_TYPE, METRICS_PATH, render_metrics

logger = logging.getLogger(__name__)

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

# Methods a Prometheus scrape may use. Anything else on /metrics is a 405.
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})


async def metrics_asgi_app(scope: Scope, receive: Receive, send: Send) -> None:
    """ASGI app serving ONLY ``GET /metrics``; every other path is a bare 404.

    Deliberately has no router, no middleware and no application state. The
    absence of any way to reach application data from this port is the entire
    point of the dedicated listener.
    """
    if scope["type"] != "http":
        return

    path = scope.get("path", "")
    method = scope.get("method", "GET")

    if path != METRICS_PATH:
        # Not found — and crucially, no application handler exists to fall
        # through to. An empty body leaks nothing about what the pod runs.
        await _respond(send, 404, b"", "text/plain; charset=utf-8", method)
        return

    if method not in _ALLOWED_METHODS:
        await _respond(send, 405, b"", "text/plain; charset=utf-8", method)
        return

    try:
        body = render_metrics().encode("utf-8")
    except Exception:
        # A scrape must never take the pod down, and a 500 is a clearer signal
        # to Prometheus than a dropped connection.
        logger.exception("Metrics rendering failed on the dedicated metrics port")
        await _respond(send, 500, b"", "text/plain; charset=utf-8", method)
        return

    await _respond(send, 200, body, CONTENT_TYPE, method)


async def _respond(send: Send, status: int, body: bytes, content_type: str, method: str) -> None:
    """Send a complete ASGI HTTP response (HEAD gets the headers, no body)."""
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode("latin-1")),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b"" if method == "HEAD" else body})


class MetricsServer:
    """Runs :func:`metrics_asgi_app` on a dedicated port, on its own thread.

    ``port=0`` binds an ephemeral port — used by tests so a suite never fights
    the real port. Read the actual port back from :attr:`bound_port`.
    """

    # nosec-justification for B104 (hardcoded_bind_all_interfaces) below:
    # binding all interfaces is REQUIRED, not incidental. Prometheus scrapes the
    # pod IP (10.42.x.x:9693); a loopback bind would make the target unreachable
    # and take the OSV freshness signal dark — the exact outcome this whole
    # change exists to prevent. The blast radius is bounded by what the socket
    # serves: `metrics_asgi_app` has no router and 404s every path but /metrics,
    # so there is no application surface to reach. Network scoping is enforced
    # where it belongs — the NetworkPolicy admits only the prometheus namespace,
    # and the mesh AuthorizationPolicy is port-scoped. Suppressed inline rather
    # than added to [tool.bandit] skips so B104 stays live for the rest of the repo.
    def __init__(self, port: int, host: str = "0.0.0.0") -> None:  # nosec B104
        self._port = port
        self._host = host
        self._server: Any = None
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """True once the listening socket is bound and accepting."""
        return (
            self._server is not None
            and bool(getattr(self._server, "started", False))
            and self._thread is not None
            and self._thread.is_alive()
        )

    @property
    def bound_port(self) -> int | None:
        """The port actually bound, or None if the server is not up."""
        servers = getattr(self._server, "servers", None)
        if not servers:
            return None
        sockets = getattr(servers[0], "sockets", None)
        if not sockets:
            return None
        return int(sockets[0].getsockname()[1])

    def start(self, timeout: float = 15.0) -> None:
        """Start the listener and BLOCK until the socket is bound.

        Blocking is deliberate: returning before the bind would let the pod pass
        readiness while its metrics port is still dead, which is precisely the
        silent-monitoring-gap this whole change exists to prevent.
        """
        import uvicorn

        config = uvicorn.Config(
            metrics_asgi_app,
            host=self._host,
            port=self._port,
            log_level="warning",
            access_log=False,
            # The metrics app has no lifespan of its own; asking for one would
            # make uvicorn emit a spurious "lifespan unsupported" warning.
            lifespan="off",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, name="metrics-server", daemon=True)
        thread.start()

        deadline = time.monotonic() + timeout
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError(
                    f"Metrics server thread died before binding {self._host}:{self._port}"
                )
            if time.monotonic() >= deadline:
                server.should_exit = True
                raise TimeoutError(
                    f"Metrics server did not bind {self._host}:{self._port} within {timeout}s"
                )
            time.sleep(0.02)

        self._server = server
        self._thread = thread
        logger.info("Metrics listener bound on %s:%s%s", self._host, self.bound_port, METRICS_PATH)

    def stop(self, timeout: float = 10.0) -> None:
        """Ask the listener to exit and join its thread. Idempotent."""
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.should_exit = True
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                logger.warning("Metrics server thread did not stop within %ss", timeout)
