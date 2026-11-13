"""coding-security must set tracing up at construction, never in the lifespan.

This service previously built a tracer provider, registered it, and called
``FastAPIInstrumentor.instrument_app(app)`` from inside ``lifespan`` — then logged
``"OpenTelemetry tracing enabled"``. It exported zero spans, because by the time
a lifespan runs Starlette has already built the middleware stack and the
instrumentation is discarded in silence.

These tests are the per-repo half of the guard. ``coding_client.telemetry``
raises on a post-startup call; this file proves this repo calls it on the
supported side of that line, and that a real request produces a real span.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

APP_FACTORY = Path(__file__).resolve().parents[2] / "src" / "app_factory.py"


@pytest.fixture(autouse=True)
def _reset_global_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """``set_tracer_provider`` is set-once per process; isolate each test."""
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None, raising=False)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once(), raising=False)


def _module() -> ast.Module:
    source = APP_FACTORY.read_text(encoding="utf-8")
    # Non-vacuity: a path that silently read an empty or wrong file would make
    # every assertion below pass against nothing.
    assert len(source) > 5_000, f"{APP_FACTORY} looks wrong: {len(source)} bytes"
    assert "def create_app" in source, f"{APP_FACTORY} does not define create_app"
    return ast.parse(source)


def _enclosing_function(tree: ast.Module, target: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for child in ast.walk(node):
                if child is target:
                    return node.name
    return None


def _setup_tracing_calls(tree: ast.Module) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "setup_tracing"
    ]


def test_setup_tracing_is_called_exactly_once_from_create_app() -> None:
    tree = _module()
    calls = _setup_tracing_calls(tree)

    assert len(calls) == 1, f"expected exactly one setup_tracing() call, found {len(calls)}"
    where = _enclosing_function(tree, calls[0])
    assert where == "create_app", (
        f"setup_tracing() is called from {where!r}, not create_app(). Anywhere that "
        "runs after the app has started exports zero spans."
    )


def test_the_lifespan_does_not_instrument_anything() -> None:
    """The old block is gone, not merely bypassed.

    Written as an AST check over the lifespan function rather than a text grep so
    the explanatory comment that replaced the block cannot satisfy it.
    """
    tree = _module()
    lifespan = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "lifespan"
        ),
        None,
    )
    assert lifespan is not None, "no lifespan function found — has this file been restructured?"

    banned = {"instrument_app", "set_tracer_provider", "instrument"}
    found = [
        node.func.attr
        for node in ast.walk(lifespan)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in banned
    ]
    assert not found, f"instrumentation calls left in the lifespan: {found}"


def test_a_real_request_through_the_real_app_produces_a_span(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The contract test above cannot prove spans exist. This one drives one.

    Both are needed: the AST test would still pass if setup_tracing itself broke,
    and this test would still pass if the call drifted to a place that happens to
    work today.
    """
    monkeypatch.setenv(
        "OTLP_TRACES_ENDPOINT", "http://tempo.tempo.svc.cluster.local:4318/v1/traces"
    )
    exporter = InMemorySpanExporter()
    real_add = TracerProvider.add_span_processor
    monkeypatch.setattr(
        TracerProvider,
        "add_span_processor",
        lambda self, _p: real_add(self, SimpleSpanProcessor(exporter)),
    )

    from app_factory import create_app

    app = create_app()
    with TestClient(app) as client:
        client.get("/health")  # excluded — must NOT be traced
        assert len(exporter.get_finished_spans()) == 0

        client.get("/openapi.json")  # a real, unexcluded path
    assert exporter.get_finished_spans(), "no span produced by the real application"
