"""Tests for the production-strict settings validator."""

from __future__ import annotations

import pytest


def _clear_required_env(monkeypatch) -> None:
    """Strip every env var the prod validator requires + the conftest defaults."""
    for key in (
        "DATABASE_URL",
        "REDIS_URL",
        "CONTAINERS_SERVICE_URL",
        "DOCKER_REGISTRY_URL",
        "OTEL_ENDPOINT",
    ):
        monkeypatch.delenv(key, raising=False)


def _fresh_settings_class():
    """Import Settings + clear lru_cache so the env state is re-read."""
    from config.settings import Settings, get_settings

    get_settings.cache_clear()
    return Settings


def test_settings_defaults_to_empty_strings(monkeypatch):
    """In a non-production environment, URL fields default to empty strings."""
    _clear_required_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "testing")

    settings_cls = _fresh_settings_class()
    s = settings_cls()

    assert s.database_url == ""
    assert s.redis_url == ""
    assert s.containers_service_url == ""
    assert s.docker_registry_url == ""
    assert s.otel_endpoint == ""


def test_production_validator_raises_when_required_missing(monkeypatch):
    """In production, instantiating Settings without required URLs must raise."""
    _clear_required_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")

    settings_cls = _fresh_settings_class()
    with pytest.raises(RuntimeError) as exc_info:
        settings_cls()

    msg = str(exc_info.value)
    assert "missing required fields in production" in msg
    assert "database_url" in msg
    assert "redis_url" in msg
    assert "containers_service_url" in msg
    assert "docker_registry_url" in msg


def test_production_validator_passes_when_required_set(monkeypatch):
    """When all required URLs are present, production Settings init succeeds."""
    _clear_required_env(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://u:p@postgres:5432/coding_security",
    )
    monkeypatch.setenv("REDIS_URL", "redis://redis.redis.svc.cluster.local:6379/0")
    monkeypatch.setenv(
        "CONTAINERS_SERVICE_URL",
        "http://coding-containers.coding-containers.svc.cluster.local:8691",
    )
    monkeypatch.setenv("DOCKER_REGISTRY_URL", "mirror.example.com")

    settings_cls = _fresh_settings_class()
    s = settings_cls()

    assert s.environment == "production"
    assert s.containers_service_url.endswith(":8691")
    assert s.docker_registry_url == "mirror.example.com"
