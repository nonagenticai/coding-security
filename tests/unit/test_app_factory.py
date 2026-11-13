"""Tests for app_factory._add_middlewares.

AuthMiddleware import failure must fail CLOSED, not skip silently.

Regression guard: `_add_middlewares` used to swallow the ImportError with
`logger.warning("AuthMiddleware not available, skipping")`, which meant a
broken coding_client install silently ran the whole service with NO
authentication at all.
"""

from __future__ import annotations

import logging
import sys
from unittest.mock import patch

import pytest
from fastapi import FastAPI


def _settings(*, enable_auth: bool = True, environment: str = "testing"):
    return type("Settings", (), {"enable_auth": enable_auth, "environment": environment})()


def _no_auth_middleware_module():
    """Context manager making `from coding_client.auth.middleware import ...`
    raise ImportError.

    A None entry in sys.modules is the documented way to make an import of
    that name fail without touching the real module on disk.
    """
    return patch.dict(sys.modules, {"coding_client.auth.middleware": None})


def test_add_middlewares_auth_disabled():
    """When enable_auth is False, no AuthMiddleware is added but CORS/logging are."""
    from app_factory import _add_middlewares

    app = FastAPI()
    _add_middlewares(app, _settings(enable_auth=False))

    assert not any(m.cls.__name__ == "AuthMiddleware" for m in app.user_middleware)
    assert any(m.cls.__name__ == "CORSMiddleware" for m in app.user_middleware)


def test_add_middlewares_registers_auth_when_import_succeeds():
    """Positive control: the normal path really does register AuthMiddleware."""
    from app_factory import _add_middlewares

    app = FastAPI()
    _add_middlewares(app, _settings(enable_auth=True))

    assert any(m.cls.__name__ == "AuthMiddleware" for m in app.user_middleware)


def test_add_middlewares_import_error_raises_in_production():
    """In production an unimportable AuthMiddleware must abort startup."""
    from app_factory import _add_middlewares

    app = FastAPI()
    with _no_auth_middleware_module():
        with pytest.raises(RuntimeError, match="refusing to start in production"):
            _add_middlewares(app, _settings(enable_auth=True, environment="production"))

    # And it must not have quietly registered an unauthenticated stack.
    assert not any(m.cls.__name__ == "AuthMiddleware" for m in app.user_middleware)


def test_add_middlewares_import_error_warns_outside_production(caplog):
    """Outside production the app still boots, but says loudly that auth is off."""
    from app_factory import _add_middlewares

    app = FastAPI()
    with caplog.at_level(logging.WARNING, logger="app_factory"), _no_auth_middleware_module():
        _add_middlewares(
            app, _settings(enable_auth=True, environment="development")
        )  # must not raise

    assert "starting WITHOUT authentication" in caplog.text
    assert not any(m.cls.__name__ == "AuthMiddleware" for m in app.user_middleware)
    # The rest of the stack is still wired.
    assert any(m.cls.__name__ == "CORSMiddleware" for m in app.user_middleware)
