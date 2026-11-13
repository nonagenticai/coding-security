"""Tests for SystemSecurityService and RedisCacheManager (security_service.py)."""

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from config.security_config import SystemSecurityConfig
from models.security_models import (
    SecurityLevel,
    SecurityValidationRequest,
    SecurityValidationResult,
    SupportedLanguage,
)
from services.security_service import (
    RedisCacheManager,
    SecurityLanguageNotCoveredError,
    SystemSecurityService,
    create_security_service,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    code: str = "x = 1",
    language: SupportedLanguage = SupportedLanguage.PYTHON,
    security_level: SecurityLevel = SecurityLevel.MEDIUM,
    container_name: str | None = None,
) -> SecurityValidationRequest:
    return SecurityValidationRequest(
        code=code,
        language=language,
        security_level=security_level,
        container_name=container_name,
    )


class _CleanEngine:
    """A SAST engine that is installed and finds nothing."""

    def is_available(self) -> bool:
        return True

    async def scan(self, targets, **_kwargs):
        return []


def _clean_detector():
    """Regex detector with every engine planted clean.

    The real singleton reports a missing engine (semgrep / trivy are not on
    the test runner's PATH) as DEGRADED — correctly never "safe" — so tests of
    the safe path must plant installed engines.
    """
    from services.security_detector import SecurityVulnerabilityDetector

    d = SecurityVulnerabilityDetector()
    for name in ("_bandit", "_secrets", "_semgrep", "_iac", "_image"):
        setattr(d, name, _CleanEngine())
    return d


def _make_service(cache_manager=None) -> SystemSecurityService:
    config = SystemSecurityConfig()
    return SystemSecurityService(
        security_config=config, cache_manager=cache_manager, detector=_clean_detector()
    )


# ===========================================================================
# RedisCacheManager tests
# ===========================================================================


class TestRedisCacheManager:
    """Tests for RedisCacheManager get/set behaviour."""

    @pytest.mark.asyncio
    async def test_cache_get_miss_returns_none(self):
        """GET on a key that doesn't exist returns None."""
        redis = AsyncMock()
        redis.get.return_value = None
        mgr = RedisCacheManager(redis)
        result = await mgr.get("missing-key")
        assert result is None
        redis.get.assert_awaited_once_with("missing-key")

    @pytest.mark.asyncio
    async def test_cache_get_json_decode_failure_returns_none(self):
        """GET returns None when stored value is not valid JSON."""
        redis = AsyncMock()
        redis.get.return_value = b"not-json{{{"
        mgr = RedisCacheManager(redis)
        result = await mgr.get("bad-json-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_get_redis_exception_returns_none(self):
        """GET returns None when Redis raises an exception."""
        redis = AsyncMock()
        redis.get.side_effect = ConnectionError("connection lost")
        mgr = RedisCacheManager(redis)
        result = await mgr.get("any-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_set_success(self):
        """SET stores JSON-serialised value with TTL."""
        redis = AsyncMock()
        mgr = RedisCacheManager(redis)
        await mgr.set("k", {"a": 1}, ttl=60)
        redis.set.assert_awaited_once_with("k", json.dumps({"a": 1}), ex=60)

    @pytest.mark.asyncio
    async def test_cache_set_redis_exception_swallowed(self):
        """SET swallows Redis exceptions without raising."""
        redis = AsyncMock()
        redis.set.side_effect = ConnectionError("connection lost")
        mgr = RedisCacheManager(redis)
        await mgr.set("k", {"a": 1})
        # Verify the set was attempted (exception was swallowed, not prevented)
        redis.set.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cache_none_redis_client_get_noop(self):
        """GET is a no-op when redis client is None."""
        mgr = RedisCacheManager(None)
        result = await mgr.get("any-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_none_redis_client_set_noop(self):
        """SET is a no-op when redis client is None and does not attempt Redis call."""
        mgr = RedisCacheManager(None)
        await mgr.set("k", {"a": 1})
        # _redis is None, so no Redis call should have been attempted
        assert mgr._redis is None


# ===========================================================================
# SystemSecurityService.validate_code_security tests
# ===========================================================================


class TestValidateCodeSecurity:
    """Tests for the main validate_code_security method."""

    @pytest.mark.asyncio
    async def test_validate_cache_hit_returns_cached(self):
        """When cache contains a result, it is returned directly."""
        cache = AsyncMock()
        cached_data = {
            "is_safe": True,
            "violations": [],
            "risk_score": 0.0,
            "sandbox_config": {"memory_limit": "128m"},
        }
        cache.get.return_value = cached_data

        svc = _make_service(cache_manager=cache)
        req = _make_request(code="x = 1")
        result = await svc.validate_code_security(req)

        assert result.is_safe is True
        assert result.risk_score == 0.0
        cache.get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_validate_cache_error_falls_through(self):
        """When cache.get raises, validation proceeds normally."""
        cache = AsyncMock()
        cache.get.side_effect = ValueError("bad cache")
        cache.set = AsyncMock()

        svc = _make_service(cache_manager=cache)
        req = _make_request(code="x = 1")
        result = await svc.validate_code_security(req)

        # Should still produce a valid result (safe code)
        assert isinstance(result, SecurityValidationResult)
        assert result.is_safe is True

    @pytest.mark.asyncio
    async def test_validate_uncovered_language_is_not_computed(self):
        """A language with no pattern table is refused, never reported safe."""
        svc = _make_service()
        req = _make_request(code="Runtime.getRuntime().exec(cmd);", language=SupportedLanguage.JAVA)
        with pytest.raises(SecurityLanguageNotCoveredError):
            await svc.validate_code_security(req)

    @pytest.mark.asyncio
    async def test_validate_js_alias_uses_javascript_patterns(self):
        """'js' is checked with the javascript table, not passed as unknown."""
        svc = _make_service()
        req = _make_request(code="eval(userInput)", language=SupportedLanguage.JS)
        result = await svc.validate_code_security(req)

        assert result.is_safe is False
        assert result.violations

    @pytest.mark.asyncio
    async def test_validate_python_with_exec_call(self):
        """Python code with exec() triggers violations."""
        svc = _make_service()
        req = _make_request(code="exec('print(1)')", language=SupportedLanguage.PYTHON)
        result = await svc.validate_code_security(req)

        assert result.is_safe is False
        assert result.risk_score > 0
        # Should find at least the pattern-match for exec
        exec_violations = [
            v
            for v in result.violations
            if "exec" in v.pattern_matched.lower() or "exec" in v.description.lower()
        ]
        assert len(exec_violations) >= 1

    @pytest.mark.asyncio
    async def test_validate_container_lookup_success(self):
        """When container_name is given, container registry is consulted."""
        mock_registry = AsyncMock()
        mock_registry.get_container_async.return_value = {"name": "test-container"}

        svc = _make_service()
        req = _make_request(code="x = 1", container_name="test-container")

        with patch(
            "services.container_registry.get_container_registry",
            return_value=mock_registry,
        ):
            result = await svc.validate_code_security(req)

        assert isinstance(result, SecurityValidationResult)
        mock_registry.get_container_async.assert_awaited_once_with("test-container", tenant_id=None)

    @pytest.mark.asyncio
    async def test_validate_container_lookup_uses_caller_tenant(self):
        """The caller's tenant reaches the registry, so tenant workspaces resolve."""
        mock_registry = AsyncMock()
        mock_registry.get_container_async.return_value = {"name": "cv-ems-p4"}

        svc = _make_service()
        req = _make_request(code="x = 1", container_name="cv-ems-p4")

        with patch(
            "services.container_registry.get_container_registry",
            return_value=mock_registry,
        ):
            await svc.validate_code_security(req, tenant_id="tenant-a")

        mock_registry.get_container_async.assert_awaited_once_with(
            "cv-ems-p4", tenant_id="tenant-a"
        )

    @pytest.mark.asyncio
    async def test_validate_blank_comment_lines_skipped(self):
        """Blank lines and comment lines are not pattern-matched."""
        code = "\n".join(
            [
                "",
                "# this has exec( in a comment",
                "// eval( also in a comment",
                "x = 1",
            ]
        )
        svc = _make_service()
        req = _make_request(code=code, language=SupportedLanguage.PYTHON)
        result = await svc.validate_code_security(req)

        # Only x = 1 is scanned; no violations expected from comment lines
        pattern_violations = [
            v
            for v in result.violations
            if v.type
            not in ("dangerous_import", "ast_analysis", "dangerous_function_call", "syntax_error")
        ]
        assert len(pattern_violations) == 0

    @pytest.mark.asyncio
    async def test_validate_multiple_matches_accumulate_risk(self):
        """Multiple pattern matches on different lines accumulate risk_score."""
        code = "\n".join(
            [
                "eval('x')",
                "exec('y')",
                "os.system('z')",
            ]
        )
        svc = _make_service()
        req = _make_request(code=code, language=SupportedLanguage.PYTHON)
        result = await svc.validate_code_security(req)

        assert result.risk_score > 0
        assert len(result.violations) >= 3  # at least 3 pattern matches

    @pytest.mark.asyncio
    async def test_validate_cache_store_called_on_success(self):
        """After a successful validation, the result is cached."""
        cache = AsyncMock()
        cache.get.return_value = None

        svc = _make_service(cache_manager=cache)
        req = _make_request(code="x = 1")
        await svc.validate_code_security(req)

        cache.set.assert_awaited_once()
        # First positional arg is the cache key, second is the dict
        call_args = cache.set.call_args
        stored_value = call_args[0][1] if call_args[0] else call_args.kwargs.get("value")
        assert isinstance(stored_value, dict)

    def test_validate_cache_key_deterministic(self):
        """The same request always produces the same cache key."""
        svc = _make_service()
        req1 = _make_request(
            code="x = 1", language=SupportedLanguage.PYTHON, security_level=SecurityLevel.MEDIUM
        )
        req2 = _make_request(
            code="x = 1", language=SupportedLanguage.PYTHON, security_level=SecurityLevel.MEDIUM
        )

        key1 = svc._generate_cache_key(req1)
        key2 = svc._generate_cache_key(req2)
        assert key1 == key2

        # And it's a hex sha256
        expected = hashlib.sha256(b"v3:x = 1:python:medium").hexdigest()
        assert key1 == expected

    def test_validate_cache_key_differs_for_different_code(self):
        """Different code produces different cache keys."""
        svc = _make_service()
        req1 = _make_request(code="x = 1")
        req2 = _make_request(code="x = 2")
        assert svc._generate_cache_key(req1) != svc._generate_cache_key(req2)

    def test_validate_cache_key_differs_for_different_language(self):
        """Different languages produce different cache keys."""
        svc = _make_service()
        req1 = _make_request(code="x = 1", language=SupportedLanguage.PYTHON)
        req2 = _make_request(code="x = 1", language=SupportedLanguage.JAVASCRIPT)
        assert svc._generate_cache_key(req1) != svc._generate_cache_key(req2)

    def test_validate_cache_key_differs_for_different_level(self):
        """Different security levels produce different cache keys."""
        svc = _make_service()
        req1 = _make_request(code="x = 1", security_level=SecurityLevel.LOW)
        req2 = _make_request(code="x = 1", security_level=SecurityLevel.HIGH)
        assert svc._generate_cache_key(req1) != svc._generate_cache_key(req2)


# ===========================================================================
# generate_sandbox_config tests
# ===========================================================================


class TestGenerateSandboxConfig:
    """Tests for generate_sandbox_config."""

    @pytest.mark.asyncio
    async def test_sandbox_config_standard_level(self):
        """Medium security level uses 'medium' sandbox base config."""
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("python", "medium")
        assert cfg["security_level"] == "medium"
        assert cfg["memory_limit"] == "128m"
        assert cfg["read_only"] is True

    @pytest.mark.asyncio
    async def test_sandbox_config_strict_level(self):
        """High security level enforces stricter settings."""
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("python", "high")
        assert cfg["security_level"] == "high"
        assert cfg["memory_limit"] == "64m"
        # high drops ALL capabilities and adds none
        assert cfg["capabilities"]["add"] == []
        assert cfg["capabilities"]["drop"] == ["ALL"]
        # tmpfs present for high
        assert "/tmp" in cfg["tmpfs"]

    @pytest.mark.asyncio
    async def test_sandbox_config_relaxed_level(self):
        """Low security level is more permissive."""
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("python", "low")
        assert cfg["security_level"] == "low"
        assert cfg["memory_limit"] == "256m"
        assert cfg["read_only"] is False
        # Low level adds some capabilities
        assert "CHOWN" in cfg["capabilities"]["add"]

    @pytest.mark.asyncio
    async def test_sandbox_config_unknown_language_fallback(self):
        """An unknown language falls back to the ubuntu base image."""
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("haskell", "medium")
        assert cfg["image"] == "ubuntu:20.04"
        assert cfg["entrypoint"] == ["/bin/bash"]
        assert cfg["security_level"] == "medium"


# ===========================================================================
# Pattern initialization tests
# ===========================================================================


class TestPatternInitialization:
    """Verify that language patterns are enriched during init."""

    def test_python_patterns_loaded(self):
        """Python patterns include both base config and extended patterns."""
        svc = _make_service()
        python_patterns = svc.dangerous_patterns.get("python", [])
        # Base config has 7 patterns, _patterns() adds 8 more
        assert len(python_patterns) >= 10
        # Check an extended pattern exists
        descriptions = [p["description"] for p in python_patterns]
        assert "Access to builtin functions" in descriptions
        assert "Dynamic attribute access" in descriptions

    def test_javascript_patterns_loaded(self):
        """JavaScript patterns include both base config and extended patterns."""
        svc = _make_service()
        js_patterns = svc.dangerous_patterns.get("javascript", [])
        # Base config has 4, _patterns() adds 6 more
        assert len(js_patterns) >= 8
        descriptions = [p["description"] for p in js_patterns]
        assert "Dynamic function creation" in descriptions
        assert "innerHTML assignment" in descriptions


# ===========================================================================
# AST validation tests
# ===========================================================================


class TestValidatePythonAst:
    """Tests for _validate_python_ast method."""

    @pytest.mark.asyncio
    async def test_eval_call_detected(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("eval('1+1')")
        types = [v.type for v in violations]
        assert "dangerous_function_call" in types

    @pytest.mark.asyncio
    async def test_exec_call_detected(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("exec('x=1')")
        descs = [v.description for v in violations]
        assert any("exec" in d for d in descs)

    @pytest.mark.asyncio
    async def test_compile_call_detected(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("compile('x=1', '<string>', 'exec')")
        assert any(v.severity == SecurityLevel.HIGH for v in violations)

    @pytest.mark.asyncio
    async def test_dunder_import_detected(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("__import__('os')")
        assert any("__import__" in v.pattern_matched for v in violations)

    @pytest.mark.asyncio
    async def test_import_os_flagged(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("import os")
        assert any("os" in v.pattern_matched for v in violations)

    @pytest.mark.asyncio
    async def test_from_subprocess_import_flagged(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("from subprocess import run")
        assert any("subprocess" in v.description for v in violations)

    @pytest.mark.asyncio
    async def test_safe_import_not_flagged(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("import math")
        dangerous = [v for v in violations if v.type == "dangerous_import"]
        assert len(dangerous) == 0

    @pytest.mark.asyncio
    async def test_syntax_error_returns_violation(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("def f(:\n  pass")
        assert any(v.type == "syntax_error" for v in violations)

    @pytest.mark.asyncio
    async def test_safe_code_no_violations(self):
        svc = _make_service()
        violations = await svc._validate_python_ast("x = 1 + 2\nprint(x)")
        # Should only have ast_analysis for import if any, not dangerous_function_call
        dangerous = [v for v in violations if v.type == "dangerous_function_call"]
        assert len(dangerous) == 0

    @pytest.mark.asyncio
    async def test_dunder_import_is_medium_severity(self):
        """__import__() is flagged with MEDIUM severity."""
        svc = _make_service()
        violations = await svc._validate_python_ast("__import__('subprocess')")
        dunder = [
            v
            for v in violations
            if v.type == "dangerous_function_call" and "__import__" in v.pattern_matched
        ]
        assert len(dunder) >= 1
        assert dunder[0].severity == SecurityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_import_ctypes_flagged(self):
        """Import of ctypes (low-level C access) is flagged."""
        svc = _make_service()
        violations = await svc._validate_python_ast("import ctypes")
        assert any("ctypes" in v.pattern_matched or "ctypes" in v.description for v in violations)

    @pytest.mark.asyncio
    async def test_multiple_dangerous_functions(self):
        """Multiple dangerous function calls are all detected."""
        svc = _make_service()
        code = "eval('x')\nexec('y')\ncompile('z', '<>', 'exec')"
        violations = await svc._validate_python_ast(code)
        dangerous = [v for v in violations if v.type == "dangerous_function_call"]
        assert len(dangerous) >= 3


class TestValidateJavascriptPatterns:
    """Tests for _validate_javascript_patterns."""

    @pytest.mark.asyncio
    async def test_window_bracket_access_flagged(self):
        svc = _make_service()
        violations = await svc._validate_javascript_patterns("window['eval']('code')")
        assert len(violations) >= 1
        assert violations[0].type == "dynamic_access"

    @pytest.mark.asyncio
    async def test_safe_js_no_violations(self):
        svc = _make_service()
        violations = await svc._validate_javascript_patterns("const x = 1;")
        assert len(violations) == 0


# ===========================================================================
# validate_imports tests
# ===========================================================================


class TestValidateImports:
    """Tests for validate_imports."""

    @pytest.mark.asyncio
    async def test_python_imports_analyzed(self):
        svc = _make_service()
        result = await svc.validate_imports("import os\nimport subprocess", "python")
        assert isinstance(result, list)
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_js_imports_analyzed(self):
        svc = _make_service()
        result = await svc.validate_imports("const fs = require('fs');", "javascript")
        assert isinstance(result, list)
        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_unknown_language_returns_empty(self):
        svc = _make_service()
        result = await svc.validate_imports("import os", "brainfuck")
        assert result == []


class TestAnalyzeJavascriptImports:
    """Tests for _analyze_javascript_imports."""

    @pytest.mark.asyncio
    async def test_require_child_process(self):
        svc = _make_service()
        violations = await svc._analyze_javascript_imports("const cp = require('child_process');")
        assert len(violations) >= 1
        assert any("child_process" in v.description for v in violations)

    @pytest.mark.asyncio
    async def test_import_from_fs(self):
        svc = _make_service()
        violations = await svc._analyze_javascript_imports("import { readFile } from 'fs';")
        assert len(violations) >= 1

    @pytest.mark.asyncio
    async def test_safe_import_ok(self):
        svc = _make_service()
        violations = await svc._analyze_javascript_imports("import React from 'react';")
        assert len(violations) == 0


class TestIsDangerousModule:
    """Tests for _is_dangerous_module."""

    def test_os_is_dangerous(self):
        svc = _make_service()
        assert svc._is_dangerous_module("os") is True

    def test_os_path_is_dangerous(self):
        svc = _make_service()
        assert svc._is_dangerous_module("os.path") is True

    def test_math_is_safe(self):
        svc = _make_service()
        assert svc._is_dangerous_module("math") is False

    def test_subprocess_is_dangerous(self):
        svc = _make_service()
        assert svc._is_dangerous_module("subprocess") is True

    def test_pickle_is_dangerous(self):
        svc = _make_service()
        assert svc._is_dangerous_module("pickle") is True


class TestAnalyzePythonImports:
    """Tests for _analyze_python_imports."""

    @pytest.mark.asyncio
    async def test_valid_code_with_dangerous_imports(self):
        svc = _make_service()
        violations = await svc._analyze_python_imports("import os\nimport subprocess")
        assert len(violations) >= 2

    @pytest.mark.asyncio
    async def test_syntax_error_falls_back_to_regex(self):
        svc = _make_service()
        violations = await svc._analyze_python_imports("import os\ndef f(:\n  pass")
        # Regex fallback should still find 'import os'
        assert any("os" in v.description for v in violations)


# ===========================================================================
# Additional generate_sandbox_config tests
# ===========================================================================


class TestGenerateSandboxConfigExtended:
    @pytest.mark.asyncio
    async def test_javascript_language_config(self):
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("javascript", "medium")
        assert cfg["image"] == "node:18-alpine"
        assert cfg["entrypoint"] == ["node"]

    @pytest.mark.asyncio
    async def test_js_alias_works(self):
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("js", "medium")
        assert cfg["image"] == "node:18-alpine"

    @pytest.mark.asyncio
    async def test_critical_level_drops_all_caps(self):
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("python", "critical")
        assert cfg["capabilities"]["add"] == []
        assert cfg["capabilities"]["drop"] == ["ALL"]
        assert "/tmp" in cfg["tmpfs"]

    @pytest.mark.asyncio
    async def test_unknown_level_falls_back_to_medium(self):
        svc = _make_service()
        cfg = await svc.generate_sandbox_config("python", "nonexistent")
        # Falls back to medium
        assert cfg["memory_limit"] == "128m"


# ===========================================================================
# create_security_service factory
# ===========================================================================


class TestCreateSecurityService:
    def test_factory_returns_instance(self):
        svc = create_security_service()
        assert isinstance(svc, SystemSecurityService)

    def test_factory_with_cache(self):
        cache = MagicMock()
        svc = create_security_service(cache_manager=cache)
        assert svc.cache_manager is cache
