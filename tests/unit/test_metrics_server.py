"""Tests for the DEDICATED-PORT Prometheus metrics listener.

The listener exists so the cross-namespace scrape grant can be port-scoped to a
socket with no application surface. Three properties therefore have to hold, and
each has a test here that fails by name if it stops holding:

  * it actually starts (a listener that never binds takes monitoring dark —
    gitops #2298, 8 targets ``up == 0`` in 14 seconds);
  * it serves the SAME exposition as the app port (so the scrape can be moved
    without changing a single series); and
  * it serves NOTHING BUT metrics (otherwise port-scoping the grant buys
    nothing — which is the whole reason the app port could not simply be
    allowed).

Plus the additive-only guarantee: the app-port ``/metrics`` must keep working,
because it is the live scrape target until the AuthorizationPolicy is updated in
a later change.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from metrics_exposition import CONTENT_TYPE, render_metrics
from metrics_server import MetricsServer
from utils.osv_db_status import _read_generated_at


@pytest.fixture(autouse=True)
def _clear_osv_cache():
    _read_generated_at.cache_clear()
    yield
    _read_generated_at.cache_clear()


@pytest.fixture
def metrics_server():
    """A dedicated metrics listener on an ephemeral port, stopped on teardown."""
    server = MetricsServer(port=0, host="127.0.0.1")
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _url(server: MetricsServer, path: str) -> str:
    return f"http://127.0.0.1:{server.bound_port}{path}"


def _fresh_db(tmp_path, monkeypatch):
    """Point the service at a freshly-stamped OSV manifest, assert it took."""
    from config.settings import get_settings

    stamp = (datetime.now(UTC) - timedelta(hours=2)).isoformat(timespec="seconds")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "generated_at": stamp.replace("+00:00", "Z")})
    )
    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(tmp_path))
    get_settings.cache_clear()
    assert get_settings().osv_offline_db_dir == str(tmp_path)


# ---------------------------------------------------------------------------
# 1. It starts — and the APP's lifespan is what starts it.
# ---------------------------------------------------------------------------


def test_lifespan_starts_dedicated_metrics_listener(test_client):
    """The app's lifespan binds a metrics listener on a port of its own.

    MUTATION GUARD: deleting the `MetricsServer(...).start()` block from
    `app_factory.lifespan` — i.e. the listener never starts — fails HERE.
    """
    server = test_client.app.state.metrics_server
    assert server is not None, "lifespan did not start the dedicated metrics listener"
    assert server.is_running, "metrics listener object exists but its socket is not bound"

    port = server.bound_port
    assert isinstance(port, int) and port > 0, f"metrics listener has no bound port: {port!r}"
    # A DEDICATED port: it must not be the app port it exists to get off of.
    from config.settings import get_settings

    assert port != get_settings().port


def test_lifespan_started_listener_is_reachable(test_client):
    """The listener the lifespan started answers a real HTTP scrape.

    `is_running` alone is a claim about our own bookkeeping; this drives the
    actual socket, which is what Prometheus will do.
    """
    server = test_client.app.state.metrics_server
    assert server is not None
    response = httpx.get(_url(server, "/metrics"), timeout=10.0)
    assert response.status_code == 200
    assert "osv_db_present" in response.text


def test_lifespan_stops_the_listener_on_shutdown(monkeypatch):
    """Shutdown releases the port, so a pod restart cannot hit `address in use`."""
    from fastapi.testclient import TestClient

    from app_factory import create_app
    from config.settings import get_settings

    monkeypatch.setenv("ENABLE_AUTH", "false")
    get_settings.cache_clear()

    app = create_app()
    with TestClient(app, client=("127.0.0.1", 12345)):
        server = app.state.metrics_server
        assert server is not None and server.is_running
        port = server.bound_port

    assert not server.is_running
    with pytest.raises(httpx.ConnectError):
        httpx.get(f"http://127.0.0.1:{port}/metrics", timeout=5.0)


# ---------------------------------------------------------------------------
# 2. Same registry as the app port — a moved scrape must see identical series.
# ---------------------------------------------------------------------------


def test_metrics_port_serves_the_same_registry_as_the_app_port(
    test_client, metrics_server, tmp_path, monkeypatch
):
    """Both listeners render the SAME exposition, byte for byte.

    Not just "a known metric name appears on both": identical bytes is what
    makes moving the scrape from :8693 to :9693 a no-op for every series,
    recording rule and alert that reads them.
    """
    _fresh_db(tmp_path, monkeypatch)

    app_port_body = test_client.get("/metrics").text
    metrics_port_body = httpx.get(_url(metrics_server, "/metrics"), timeout=10.0).text

    # The known gauge names must be on BOTH — including the alerting one.
    for name in ("osv_db_present", "osv_db_stale", "osv_db_age_days"):
        assert name in app_port_body, f"{name} missing from the app port"
        assert name in metrics_port_body, f"{name} missing from the dedicated metrics port"

    assert metrics_port_body == app_port_body
    assert metrics_port_body == render_metrics()


def test_metrics_port_uses_the_prometheus_content_type(metrics_server):
    """Same exposition content type as the app port, so scrape config is portable."""
    response = httpx.get(_url(metrics_server, "/metrics"), timeout=10.0)
    assert response.status_code == 200
    assert response.headers["content-type"] == CONTENT_TYPE


def test_metrics_port_reflects_a_stale_db(metrics_server, tmp_path, monkeypatch):
    """The gauge that OsvCveDbStale alerts on is live on the dedicated port too.

    A listener that served a constant would pass every shape test above and
    still make the alert unfireable.
    """
    from config.settings import get_settings

    stamp = (datetime.now(UTC) - timedelta(days=13)).isoformat(timespec="seconds")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "generated_at": stamp.replace("+00:00", "Z")})
    )
    monkeypatch.setenv("OSV_OFFLINE_DB_DIR", str(tmp_path))
    get_settings.cache_clear()

    body = httpx.get(_url(metrics_server, "/metrics"), timeout=10.0).text
    assert 'osv_db_stale{service="coding-security"} 1' in body


# ---------------------------------------------------------------------------
# 3. No credentials required — Prometheus is non-ambient and has none to send.
# ---------------------------------------------------------------------------


def test_metrics_port_needs_no_credentials(metrics_server):
    """A bare scrape with NO auth headers at all gets 200 and real metrics.

    Prometheus is in a non-ambient namespace: its scrape is plaintext with no
    SPIFFE principal, no Bearer and no X-Tenant-Id. If this port required any of
    them the scrape would 401 and the OSV freshness signal would go dark.
    """
    with httpx.Client(timeout=10.0) as client:
        response = client.get(_url(metrics_server, "/metrics"))

    assert response.status_code == 200, f"unauthenticated scrape rejected: {response.status_code}"
    assert "osv_db_present" in response.text
    # Nothing may hint that a credential would have changed the answer.
    assert "www-authenticate" not in {k.lower() for k in response.headers}


# ---------------------------------------------------------------------------
# 4. ONLY metrics — the property that makes port-scoping the grant worthwhile.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/api/security/scan",
        "/api/dependencies/system/list-known",
        "/metrics/../health",
    ],
)
def test_metrics_port_serves_only_metrics(metrics_server, path):
    """Every non-/metrics path on the dedicated port is a 404 with no app data.

    MUTATION GUARD: pointing `MetricsServer` at the FastAPI application instead
    of `metrics_asgi_app` — i.e. serving the app on the metrics port — fails
    HERE. That mutant keeps every metrics test above green, because the app also
    serves /metrics; this is the only thing that catches it.
    """
    response = httpx.get(_url(metrics_server, path), timeout=10.0)

    assert response.status_code == 404, (
        f"{path} returned {response.status_code} on the metrics port — "
        "the dedicated port is serving application routes"
    )
    body = response.text
    assert body == ""
    # Belt and braces: no fingerprint of the application on this socket.
    for leak in ("coding-security", "openapi", "swagger", "detail", "status"):
        assert leak not in body.lower()


def test_metrics_port_rejects_write_methods(metrics_server):
    """No verb other than GET/HEAD is answered — a scrape port is read-only."""
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        response = httpx.request(method, _url(metrics_server, "/metrics"), timeout=10.0)
        assert response.status_code == 405, f"{method} /metrics returned {response.status_code}"


def test_metrics_port_answers_head(metrics_server):
    """HEAD /metrics returns headers with no body (Prometheus probes with it)."""
    response = httpx.head(_url(metrics_server, "/metrics"), timeout=10.0)
    assert response.status_code == 200
    assert response.headers["content-type"] == CONTENT_TYPE
    assert response.content == b""


# ---------------------------------------------------------------------------
# 5. Additive only — the app port keeps serving metrics.
# ---------------------------------------------------------------------------


def test_app_port_metrics_still_works(test_client, tmp_path, monkeypatch):
    """The app-port /metrics route is UNCHANGED and still the live scrape target.

    Until the cross-namespace AuthorizationPolicy names the new port, :8693 is
    the only port Prometheus is allowed to reach. Removing this route would take
    the OSV freshness signal dark on merge.
    """
    _fresh_db(tmp_path, monkeypatch)

    response = test_client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# TYPE osv_db_present gauge" in response.text
    assert 'osv_db_present{service="coding-security"} 1' in response.text


def test_app_port_metrics_needs_no_credentials(test_client):
    """The app-port /metrics stays auth-exempt (coding_client PUBLIC_PATHS)."""
    response = test_client.get("/metrics", headers={})
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 6. Failure handling — a metrics fault must never take the pod with it.
# ---------------------------------------------------------------------------


def test_render_failure_returns_500_not_a_dropped_connection(metrics_server, monkeypatch):
    """A broken render answers 500 so the scrape reports `up 1` + no series."""
    import metrics_server as metrics_server_module

    def _boom() -> str:
        raise RuntimeError("manifest exploded")

    monkeypatch.setattr(metrics_server_module, "render_metrics", _boom)
    response = httpx.get(_url(metrics_server, "/metrics"), timeout=10.0)
    assert response.status_code == 500


def test_disabled_metrics_server_leaves_the_app_port_intact(monkeypatch):
    """METRICS_SERVER_ENABLED=false skips the listener; app-port metrics survive.

    The kill switch must degrade to today's behaviour exactly, never to a
    service that fails to boot.
    """
    from fastapi.testclient import TestClient

    from config.settings import get_settings

    monkeypatch.setenv("METRICS_SERVER_ENABLED", "false")
    monkeypatch.setenv("ENABLE_AUTH", "false")
    get_settings.cache_clear()

    from app_factory import create_app

    app = create_app()
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert app.state.metrics_server is None
        assert "osv_db_present" in client.get("/metrics").text


def test_start_failure_is_non_fatal_for_the_app(monkeypatch):
    """A listener that cannot bind logs and continues — it never crash-loops the pod.

    Losing a gauge that is still readable on the app port is strictly better
    than removing the scanner from the cluster.
    """
    from fastapi.testclient import TestClient

    import metrics_server as metrics_server_module
    from config.settings import get_settings

    def _explode(self, timeout: float = 15.0) -> None:
        raise OSError("address already in use")

    monkeypatch.setattr(metrics_server_module.MetricsServer, "start", _explode)
    monkeypatch.setenv("ENABLE_AUTH", "false")
    get_settings.cache_clear()

    from app_factory import create_app

    app = create_app()
    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        assert app.state.metrics_server is None
        assert client.get("/health").status_code == 200
        assert "osv_db_present" in client.get("/metrics").text


def test_bound_port_is_none_before_start_and_stop_is_idempotent():
    """An unstarted server reports no port; stop() on it is a safe no-op."""
    server = MetricsServer(port=0, host="127.0.0.1")
    assert server.bound_port is None
    assert not server.is_running
    server.stop()
    server.stop()
