"""

Security Service - Integrates with existing architecture
Replaces basic validation in CodeExecutionService with comprehensive security analysis
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import logging
import re
from typing import Any

from config.security_config import SystemSecurityConfig
from models.security_models import (
    MAX_ANALYZED_LINE_CHARS,
    SecurityLevel,
    SecurityValidationRequest,
    SecurityValidationResult,
    SecurityViolation,
)
from services.inline_rules import (
    AST_BUDGET_PATTERN,
    CAT_CODE,
    CAT_DESERIALIZATION,
    CAT_DYNAMIC_ACCESS,
    CAT_NATIVE,
    CAT_PROCESS,
    CAT_REVERSE_SHELL,
    CAT_SQL,
    analyze_python_calls,
    generic_secret_violations,
)

logger = logging.getLogger(__name__)


class RedisCacheManager:
    """Cache manager backed by a real Redis client."""

    def __init__(self, redis_client: Any | None) -> None:
        self._redis = redis_client

    async def get(self, key: str) -> Any:
        """Get a value from Redis, deserialised from JSON. Returns None on miss or error."""
        if self._redis is None:
            return None
        try:
            raw = await self._redis.get(key)
            if raw is not None:
                return json.loads(raw)
        except Exception:
            logger.debug("Redis cache GET failed for key %s", key, exc_info=True)
        return None

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set a value in Redis as JSON with an expiry. Errors are swallowed."""
        if self._redis is None:
            return
        try:
            await self._redis.set(key, json.dumps(value), ex=ttl)
        except Exception:
            logger.debug("Redis cache SET failed for key %s", key, exc_info=True)


_LANGUAGE_ALIASES = {"js": "javascript"}

# Bump whenever validate_code_security starts checking something new, so a
# result computed (and cached for an hour) by an older, weaker validator is
# never served as the answer of the current one. v2 = vulnerability detector
# (SQLi, hardcoded secrets, ...) merged into the exec-danger table; v3 =
# alias-resolving AST call rules + token shapes + JS process/code rules.
_VALIDATION_CACHE_VERSION = "v3"

# File suffix the vulnerability detector keys its language off.
_DETECTOR_SUFFIX = {"python": ".py", "javascript": ".js"}

_SEVERITY_TO_LEVEL = {
    "critical": SecurityLevel.CRITICAL,
    "high": SecurityLevel.HIGH,
    "medium": SecurityLevel.MEDIUM,
    "low": SecurityLevel.LOW,
    "info": SecurityLevel.LOW,
}
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# HIGH findings of these categories make the code unsafe at MEDIUM and above
# regardless of the risk score: each is a way to reach destructive or arbitrary
# behaviour (os.remove, shutil.rmtree, __import__(name), globals()[...]). On
# main they were unsafe at MEDIUM only when an unrelated finding (`import os`)
# happened to push the score over 50.
BLOCKING_HIGH_CATEGORIES = frozenset(
    {
        "destructive_os_call",
        "dynamic_import",
        # In-process AST/table rules (services.inline_rules + the JS table): a
        # HIGH process/code-execution, deserialization, SQL-injection or
        # native-code finding is never tolerated at MEDIUM and above.
        CAT_PROCESS,
        CAT_CODE,
        CAT_DESERIALIZATION,
        CAT_DYNAMIC_ACCESS,
        CAT_NATIVE,
        CAT_REVERSE_SHELL,
        CAT_SQL,
    }
)

# HIGH/CRITICAL findings of these categories make the code unsafe at EVERY level.
ALWAYS_BLOCKING_CATEGORIES = frozenset({CAT_SQL, CAT_REVERSE_SHELL, "hardcoded_credentials"})


class SecurityLanguageNotCoveredError(Exception):
    """No dangerous-pattern table exists for the language: validation not computed."""

    def __init__(self, language: str) -> None:
        self.language = language
        super().__init__(
            f"security validation is not computed for language '{language}': "
            "no dangerous-pattern table exists for it (covered: python, javascript)"
        )


class SystemSecurityService:
    """
    Centralized security validation service that integrates with existing architecture.
    Replaces scattered security logic with comprehensive, cacheable validation.
    """

    def __init__(
        self,
        security_config: SystemSecurityConfig,
        cache_manager: Any | None = None,
        detector: Any | None = None,
    ):
        """Initialize the SystemSecurityService service.

        This initializes the SystemSecurityService with required dependencies
        and configuration for service operations.

        Args:
            security_config (SystemSecurityConfig): Configuration settings for security config
            cache_manager (Optional): Cache manager
            detector (Optional): Vulnerability detector; defaults to the shared
                singleton the /scan path uses.
        """
        self.security_config = security_config
        self.cache_manager = cache_manager
        self._detector = detector
        self._initialize_patterns()

    def _initialize_patterns(self) -> None:
        """Initialize security patterns from configuration."""
        # Per-instance copy: _patterns() extends these lists, and extending the
        # class-level DANGEROUS_PATTERNS appended the extra rules again on every
        # instantiation (each duplicate adding its weight to the risk score).
        self.dangerous_patterns = {
            lang: list(rules) for lang, rules in self.security_config.DANGEROUS_PATTERNS.items()
        }
        self.sandbox_configs = self.security_config.SANDBOX_CONFIGS

        # Add additional patterns based on security analysis
        self._patterns()

        logger.info(
            "Security patterns initialized for %d languages",
            len(self.dangerous_patterns),
        )

    def _patterns(self) -> None:
        """patterns with additional security checks."""

        # Python patterns
        if "python" in self.dangerous_patterns:
            self.dangerous_patterns["python"].extend(
                [
                    {
                        "pattern": r"__builtins__",
                        "severity": "critical",
                        "description": "Access to builtin functions",
                        "category": "builtin_access",
                        "suggested_fix": "Avoid accessing __builtins__ directly",
                    },
                    {
                        "pattern": r"globals\s*\(\s*\)",
                        "severity": "high",
                        "description": "Access to global namespace",
                        "category": "namespace_access",
                        "suggested_fix": "Use explicit variable declarations instead",
                    },
                    {
                        "pattern": r"locals\s*\(\s*\)",
                        "severity": "medium",
                        "description": "Access to local namespace",
                        "category": "namespace_access",
                        "suggested_fix": "Use explicit variable references instead",
                    },
                    {
                        "pattern": r"compile\s*\(",
                        "severity": "critical",
                        "description": "Code compilation",
                        "category": "code_execution",
                        "suggested_fix": "Use static code instead of dynamic compilation",
                    },
                    {
                        "pattern": r"getattr\s*\(",
                        "severity": "medium",
                        "description": "Dynamic attribute access",
                        "category": "dynamic_access",
                        "suggested_fix": "Use direct attribute access where possible",
                    },
                    {
                        "pattern": r"setattr\s*\(",
                        "severity": "medium",
                        "description": "Dynamic attribute modification",
                        "category": "dynamic_access",
                        "suggested_fix": "Use direct attribute assignment where possible",
                    },
                    {
                        "pattern": r"delattr\s*\(",
                        "severity": "medium",
                        "description": "Dynamic attribute deletion",
                        "category": "dynamic_access",
                        "suggested_fix": "Use del statement instead",
                    },
                    {
                        "pattern": r"hasattr\s*\(",
                        "severity": "low",
                        "description": "Dynamic attribute checking",
                        "category": "dynamic_access",
                        "suggested_fix": "Consider using try/except for attribute access",
                    },
                ]
            )

        # JavaScript patterns
        if "javascript" in self.dangerous_patterns:
            self.dangerous_patterns["javascript"].extend(
                [
                    {
                        "pattern": r"new\s+Function\s*\(",
                        "severity": "critical",
                        "description": "Dynamic function creation",
                        "category": "code_execution",
                        "suggested_fix": "Use static function declarations",
                    },
                    {
                        "pattern": r"setTimeout\s*\(\s*[\"']",
                        "severity": "high",
                        "description": "String-based setTimeout",
                        "category": "code_execution",
                        "suggested_fix": "Use function references in setTimeout",
                    },
                    {
                        "pattern": r"setInterval\s*\(\s*[\"']",
                        "severity": "high",
                        "description": "String-based setInterval",
                        "category": "code_execution",
                        "suggested_fix": "Use function references in setInterval",
                    },
                    {
                        "pattern": r"document\.write\s*\(",
                        "severity": "medium",
                        "description": "Document.write usage",
                        "category": "dom_manipulation",
                        "suggested_fix": "Use modern DOM manipulation methods",
                    },
                    {
                        "pattern": r"innerHTML\s*=",
                        "severity": "medium",
                        "description": "innerHTML assignment",
                        "category": "dom_manipulation",
                        "suggested_fix": "Use textContent or createElement for better security",
                    },
                    {
                        "pattern": r"window\[",
                        "severity": "medium",
                        "description": "Dynamic window property access",
                        "category": "dynamic_access",
                        "suggested_fix": "Use direct property access where possible",
                    },
                ]
            )

    async def validate_code_security(
        self, request: SecurityValidationRequest, tenant_id: str | None = None
    ) -> SecurityValidationResult:
        """Main security validation method with caching and comprehensive analysis."""
        # Note: This method has complex validation logic that requires tracking multiple
        # aspects of security analysis. The local variables are necessary for proper
        # security validation and risk assessment.

        # Validate container if provided
        if hasattr(request, "container_name") and request.container_name:
            from services.container_registry import get_container_registry

            container_registry = get_container_registry()
            # Resolve against the CALLER's tenant, as the scan endpoints do
            # (utils.container_validation.validate_and_get_container_for_tenant).
            # Without it the registry lookup missed every tenant workspace and
            # a real container_name answered 404.
            container_info = await container_registry.get_container_async(
                request.container_name, tenant_id=tenant_id
            )
            if not container_info:
                raise ValueError(f"Container '{request.container_name}' not found")

        # Check cache first
        cache_key = f"security:{self._generate_cache_key(request)}"
        if self.cache_manager:
            try:
                cached_result = await self.cache_manager.get(cache_key)
                if cached_result:
                    logger.debug("Security validation cache hit for key: %s", cache_key)
                    return SecurityValidationResult.model_validate(cached_result)
            except (ValueError, TypeError, AttributeError) as e:
                logger.warning("Cache retrieval failed: %s", e)

        try:
            # Get patterns for language ("js" is the same table as "javascript")
            language = request.language.lower()
            language = _LANGUAGE_ALIASES.get(language, language)
            patterns = self.dangerous_patterns.get(language, [])

            if not patterns:
                # No pattern table means nothing was checked. Answering
                # is_safe=True here passed ANY code in java/go/rust/cpp/c/
                # csharp/php/ruby as safe; the caller gets a refusal instead.
                raise SecurityLanguageNotCoveredError(request.language)

            # The whole analysis is CPU-bound regex/AST work over caller-supplied
            # code (up to 200,000 chars). Run it on a worker thread so one large
            # request cannot stall the event loop (health probes, other tenants).
            # The detector singleton is resolved HERE, on the serving loop, so
            # its module-level asyncio.Lock is never touched from the worker.
            if language in _DETECTOR_SUFFIX:
                await self._get_detector()
            violations, risk_score, vuln_violations, degraded_reasons = await asyncio.to_thread(
                self._analyze_code_in_worker, request.code, request.language, language, patterns
            )

            # Cap risk score at 100
            risk_score = min(risk_score, 100.0)

            # Determine safety based on security level
            is_safe = self._determine_safety(violations, risk_score, request.security_level)
            # A real vulnerability (not a risky-capability hint like `import socket`)
            # of high/critical severity is never tolerated by a risk threshold.
            if any(
                v.severity in (SecurityLevel.HIGH, SecurityLevel.CRITICAL) for v in vuln_violations
            ):
                is_safe = False
            # A built SQL query or a hardcoded credential found by the in-process
            # AST/secret rules is a vulnerability, not a capability hint: the
            # same "never tolerated" rule as the detector findings above.
            if any(
                v.severity in (SecurityLevel.HIGH, SecurityLevel.CRITICAL)
                and v.type in ALWAYS_BLOCKING_CATEGORIES
                for v in violations
            ):
                is_safe = False
            if request.security_level != SecurityLevel.LOW and any(
                v.severity == SecurityLevel.HIGH and v.type in BLOCKING_HIGH_CATEGORIES
                for v in violations
            ):
                is_safe = False
            # Part of the analysis did not run: we cannot say "safe".
            if degraded_reasons:
                is_safe = False

            # Generate sandbox config based on findings
            sandbox_config = await self.generate_sandbox_config(
                request.language, request.security_level.value
            )

            result = SecurityValidationResult(
                is_safe=is_safe,
                violations=violations,
                risk_score=risk_score,
                sandbox_config=sandbox_config,
                analysis_degraded=bool(degraded_reasons),
                degraded_reasons=degraded_reasons,
            )

            # Cache result. A degraded answer is NOT cached: the engine that
            # failed may succeed on the next call.
            if self.cache_manager and not degraded_reasons:
                try:
                    await self.cache_manager.set(cache_key, result.model_dump(), ttl=3600)
                    logger.debug("Security validation result cached with key: %s", cache_key)
                except (ValueError, TypeError, AttributeError) as e:
                    logger.warning("Cache storage failed: %s", e)

            logger.info(
                "Security validation completed: is_safe=%s, violations=%d, risk_score=%f",
                is_safe,
                len(violations),
                risk_score,
            )
            return result

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            logger.error("Security validation failed: %s", e)
            # In case of error, return unsafe result
            return SecurityValidationResult(
                is_safe=False,
                violations=[
                    SecurityViolation(
                        type="validation_error",
                        severity=SecurityLevel.CRITICAL,
                        line_number=None,
                        pattern_matched="internal_error",
                        description=f"Security validation failed: {str(e)}",
                        suggested_fix="Review code manually for security issues",
                    )
                ],
                risk_score=100.0,
                sandbox_config=await self.generate_sandbox_config(request.language, "high"),
            )

    def _analyze_code_in_worker(
        self, code: str, request_language: str, language: str, patterns: list[dict[str, str]]
    ) -> tuple[list[SecurityViolation], float, list[SecurityViolation], list[str]]:
        """Thread entry point: run :meth:`_analyze_code` on this thread's own loop."""
        return asyncio.run(self._analyze_code(code, request_language, language, patterns))

    async def _analyze_code(
        self, code: str, request_language: str, language: str, patterns: list[dict[str, str]]
    ) -> tuple[list[SecurityViolation], float, list[SecurityViolation], list[str]]:
        """Pattern table + AST + vulnerability detector over ``code``.

        Runs on a worker thread (its own event loop) — see validate_code_security.
        Returns ``(violations, risk_score, detector_violations, degraded_reasons)``.
        """
        violations: list[SecurityViolation] = []
        risk_score = 0.0
        degraded_reasons: list[str] = []

        # Analyze code line by line
        lines = code.splitlines()
        for line_num, line in enumerate(lines, 1):
            if len(line) > MAX_ANALYZED_LINE_CHARS:
                # Still scanned below, but on a line this long the detector's
                # main-equivalent long-span checks (unbounded originals under a
                # timeout) are not guaranteed to finish, so "nothing found"
                # here is not "safe".
                degraded_reasons.append(
                    f"line {line_num} is {len(line)} chars (> {MAX_ANALYZED_LINE_CHARS}); "
                    "very long lines are not fully analysed"
                )
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue  # Skip empty lines and comments

            for pattern_info in patterns:
                try:
                    if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                        severity = SecurityLevel(pattern_info["severity"])
                        violations.append(
                            SecurityViolation(
                                type=pattern_info.get("category", "unknown"),
                                severity=severity,
                                line_number=line_num,
                                pattern_matched=pattern_info["pattern"],
                                description=pattern_info["description"],
                                suggested_fix=pattern_info.get("suggested_fix"),
                            )
                        )
                        risk_score += _SEVERITY_WEIGHT.get(pattern_info["severity"], 0) * 10
                except re.error as e:
                    logger.warning("Invalid regex pattern: %s - %s", pattern_info["pattern"], e)
                    continue

        # Additional validation based on language
        additional_violations = await self._perform_additional_validation(code, request_language)
        violations.extend(additional_violations)

        # Adjust risk score based on additional violations
        for violation in additional_violations:
            risk_score += _SEVERITY_WEIGHT.get(violation.severity.value, 0) * 10
        if any(v.pattern_matched == "parser_overflow" for v in additional_violations):
            degraded_reasons.append("Python parser overflowed: AST analysis did not run")
        if any(v.pattern_matched == AST_BUDGET_PATTERN for v in additional_violations):
            degraded_reasons.append("AST work budget exceeded: alias/call analysis did not run")

        # The /scan path's IN-PROCESS pattern matcher (SQL injection, hardcoded
        # secrets, weak crypto, ...). No external engine runs here.
        # The table above is only an exec-danger list (os.system, eval, ...);
        # without this, `cur.execute("..." + uid)` and a hardcoded AWS secret
        # answered is_safe=true at every security level.
        vuln_violations, detector_reasons = await self._detect_vulnerabilities(code, language)
        degraded_reasons.extend(detector_reasons)
        seen = {(v.line_number, v.type) for v in violations}
        for violation in vuln_violations:
            key = (violation.line_number, violation.type)
            if key in seen:
                continue
            seen.add(key)
            violations.append(violation)
            risk_score += _SEVERITY_WEIGHT.get(violation.severity.value, 0) * 10

        return violations, risk_score, vuln_violations, degraded_reasons

    def _generate_cache_key(self, request: SecurityValidationRequest) -> str:
        """Generate a unique cache key for the request.

        Carries ``_VALIDATION_CACHE_VERSION`` so results cached by an older
        validator (which missed whole vulnerability classes) are never served.
        """
        content = (
            f"{_VALIDATION_CACHE_VERSION}:{request.code}:{request.language}:"
            f"{request.security_level.value}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

    async def _get_detector(self) -> Any:
        if self._detector is None:
            from services.security_detector import get_security_detector_async

            self._detector = await get_security_detector_async()
        return self._detector

    async def _detect_vulnerabilities(
        self, code: str, language: str
    ) -> tuple[list[SecurityViolation], list[str]]:
        """In-process vulnerability/secret patterns over inline code.

        /validate is a fast inline gate: it runs the /scan path's IN-PROCESS
        pattern matcher (SQLi, hardcoded secrets, weak crypto, ...) plus the
        generic high-entropy secret rule, and NEVER an external engine
        (bandit/semgrep/detect-secrets/trivy). Those are subprocesses: on a
        200k-char snippet detect-secrets alone ran >300 s holding a worker, and
        an absent engine degraded every /validate. They stay in /scan/*.
        Returns ``(violations, degraded_reasons)``.
        """
        if language not in _DETECTOR_SUFFIX:
            return [], [f"no vulnerability detector mapping for language '{language}'"]

        detector = await self._get_detector()
        reasons: list[str] = []
        matches = await detector.scan_inline(code, language, reasons)

        violations: list[SecurityViolation] = []
        for match in matches:
            severity_value = getattr(match.severity, "value", str(match.severity))
            level = _SEVERITY_TO_LEVEL.get(severity_value, SecurityLevel.MEDIUM)
            violations.append(
                SecurityViolation(
                    type=getattr(match.vulnerability_type, "value", str(match.vulnerability_type)),
                    severity=level,
                    line_number=match.line_start,
                    pattern_matched=match.pattern_id or "vulnerability_detector",
                    description=f"{match.title}: {match.description}".strip(": "),
                    suggested_fix=match.remediation_advice or None,
                )
            )
        violations.extend(generic_secret_violations(code))
        violations.sort(key=lambda v: (v.line_number or 0, v.type))
        return violations, reasons

    def _determine_safety(
        self,
        violations: list[SecurityViolation],
        risk_score: float,
        security_level: SecurityLevel,
    ) -> bool:
        """Determine if code is safe based on violations and security level."""

        # If no violations, code is safe
        if not violations:
            return True

        # Check for critical violations - always unsafe
        critical_violations = [v for v in violations if v.severity == SecurityLevel.CRITICAL]
        if critical_violations:
            return False

        # Risk score thresholds based on security level
        risk_thresholds = {
            SecurityLevel.LOW: 80.0,  # Allow higher risk
            SecurityLevel.MEDIUM: 50.0,  # Moderate risk tolerance
            SecurityLevel.HIGH: 20.0,  # Low risk tolerance
            SecurityLevel.CRITICAL: 0.0,  # No risk tolerance
        }

        threshold = risk_thresholds.get(security_level, 50.0)
        return risk_score <= threshold

    async def _perform_additional_validation(
        self, code: str, language: str
    ) -> list[SecurityViolation]:
        """Perform additional language-specific validation."""
        violations = []

        if language.lower() == "python":
            violations.extend(await self._validate_python_ast(code))
        elif language.lower() in ["javascript", "js"]:
            violations.extend(await self._validate_javascript_patterns(code))

        return violations

    async def _validate_python_ast(self, code: str) -> list[SecurityViolation]:
        """Validate Python code using AST analysis."""
        violations = []

        try:
            tree = ast.parse(code)
            # Alias-resolving call analysis (import os as o; o.execvp(...)).
            call_violations = analyze_python_calls(tree)
            violations.extend(call_violations)
            if any(v.pattern_matched == AST_BUDGET_PATTERN for v in call_violations):
                # Over the AST work budget: the walk below is skipped too.
                return violations

            # Check for dangerous AST nodes
            # Note: ast.Exec was removed in Python 3.8+, exec is now just a function call
            dangerous_nodes: dict[type[ast.AST], str] = {
                ast.Import: "Import statement (check if allowed)",
                ast.ImportFrom: "Import from statement (check if allowed)",
            }

            # Add ast.Eval only if it exists (it was also removed in Python 3.8+)
            if hasattr(ast, "Eval"):
                dangerous_nodes[ast.Eval] = "Use of eval function"

            for node in ast.walk(tree):
                node_type = type(node)

                # Check for dangerous statement nodes
                if node_type in dangerous_nodes:
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        # Additional validation for imports
                        import_violations = await self._validate_python_imports(node)
                        violations.extend(import_violations)
                    else:
                        violation = SecurityViolation(
                            type="ast_analysis",
                            severity=SecurityLevel.HIGH,
                            line_number=getattr(node, "lineno", None),
                            pattern_matched=type(node).__name__,
                            description=dangerous_nodes[node_type],
                            suggested_fix="Review the necessity of this construct",
                        )
                        violations.append(violation)

                # Check for dangerous function calls (eval, exec, etc.)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ["eval", "exec", "compile", "__import__"]:
                        severity_map = {
                            "eval": SecurityLevel.CRITICAL,
                            "exec": SecurityLevel.CRITICAL,
                            "compile": SecurityLevel.HIGH,
                            "__import__": SecurityLevel.MEDIUM,
                        }

                        violation = SecurityViolation(
                            type="dangerous_function_call",
                            severity=severity_map.get(func_name, SecurityLevel.HIGH),
                            line_number=getattr(node, "lineno", None),
                            pattern_matched=f"{func_name}()",
                            description=f"Call to dangerous function: {func_name}",
                            suggested_fix=f"Avoid using {func_name}() in user code",
                        )
                        violations.append(violation)

        except (MemoryError, RecursionError) as e:
            # Pathologically nested input (e.g. 20,000 open brackets) overflows
            # the parser. Previously this escaped as a 500.
            violations.append(
                SecurityViolation(
                    type="syntax_error",
                    severity=SecurityLevel.MEDIUM,
                    line_number=None,
                    pattern_matched="parser_overflow",
                    description=f"Python code too deeply nested to parse: {e}",
                    suggested_fix="Reduce nesting depth",
                )
            )
        except SyntaxError as e:
            violation = SecurityViolation(
                type="syntax_error",
                severity=SecurityLevel.MEDIUM,
                line_number=e.lineno,
                pattern_matched="syntax_error",
                description=f"Syntax error in Python code: {e.msg}",
                suggested_fix="Resolve syntax errors before validation",
            )
            violations.append(violation)
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning("AST analysis failed: %s", e)

        return violations

    async def _validate_python_imports(self, node) -> list[SecurityViolation]:
        """Validate Python import statements."""
        violations = []

        dangerous_modules = {
            "os",
            "sys",
            "subprocess",
            "shutil",
            "socket",
            "urllib",
            "urllib2",
            "httplib",
            "httplib2",
            "requests",
            "ftplib",
            "telnetlib",
            "smtplib",
            "poplib",
            "imaplib",
            "pickle",
            "marshal",
            "shelve",
            "dill",
            "base64",  # Can be used for code obfuscation
            "codecs",  # Can be used for encoding/decoding attacks
            "tempfile",  # Temporary file vulnerabilities
            "pty",  # Pseudo-terminal access
            "fcntl",  # File control operations
            "mmap",  # Memory mapping
            "ctypes",  # C library access
        }

        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in dangerous_modules:
                    violation = SecurityViolation(
                        type="dangerous_import",
                        severity=SecurityLevel.HIGH,
                        line_number=node.lineno,
                        pattern_matched=f"import {alias.name}",
                        description=f"Import of potentially dangerous module: {alias.name}",
                        suggested_fix=f"Consider safer alternatives to {alias.name}",
                    )
                    violations.append(violation)

        elif isinstance(node, ast.ImportFrom):
            if node.module in dangerous_modules:
                violation = SecurityViolation(
                    type="dangerous_import",
                    severity=SecurityLevel.HIGH,
                    line_number=node.lineno,
                    pattern_matched=f"from {node.module} import",
                    description=f"Import from potentially dangerous module: {node.module}",
                    suggested_fix=f"Consider safer alternatives to {node.module}",
                )
                violations.append(violation)

        return violations

    async def _validate_javascript_patterns(self, code: str) -> list[SecurityViolation]:
        """Validate JavaScript-specific patterns."""
        violations = []

        # Check for potentially dangerous global variable access
        global_patterns = [
            r"window\s*\[\s*[\"'][^\"']*[\"']\s*\]",
            r"this\s*\[\s*[\"'][^\"']*[\"']\s*\]",
            r"global\s*\[\s*[\"'][^\"']*[\"']\s*\]",
        ]

        lines = code.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern in global_patterns:
                if re.search(pattern, line):
                    violation = SecurityViolation(
                        type="dynamic_access",
                        severity=SecurityLevel.MEDIUM,
                        line_number=line_num,
                        pattern_matched=pattern,
                        description="Dynamic global property access detected",
                        suggested_fix="Use direct property access where possible",
                    )
                    violations.append(violation)

        return violations

    async def generate_sandbox_config(self, language: str, security_level: str) -> dict[str, Any]:
        """Generate secure container configuration for code execution."""

        # Get base configuration from security config
        base_config = self.sandbox_configs.get(security_level, self.sandbox_configs["medium"])

        # Language-specific configurations
        language_configs = {
            "python": {
                "image": "python:3.9-slim",
                "working_dir": "/app",
                "allowed_commands": ["python", "pip"],
                "environment": {
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                "entrypoint": ["python"],
            },
            "javascript": {
                "image": "node:18-alpine",
                "working_dir": "/app",
                "allowed_commands": ["node", "npm"],
                "environment": {"NODE_ENV": "sandbox"},
                "entrypoint": ["node"],
            },
            "js": {
                "image": "node:18-alpine",
                "working_dir": "/app",
                "allowed_commands": ["node", "npm"],
                "environment": {"NODE_ENV": "sandbox"},
                "entrypoint": ["node"],
            },
        }

        lang_config = language_configs.get(
            language.lower(),
            {
                "image": "ubuntu:20.04",
                "working_dir": "/app",
                "allowed_commands": [],
                "environment": {},
                "entrypoint": ["/bin/bash"],
            },
        )

        # Merge configurations
        sandbox_config = {
            **base_config,
            **lang_config,
            "security_level": security_level,
            "created_at": None,  # Will be set by container service
            "volumes": {
                "/tmp": ({"bind": "/tmp", "mode": "rw"} if not base_config.get("read_only") else {})
            },
            "capabilities": {
                "drop": ["ALL"],
                "add": (
                    [] if security_level in ["high", "critical"] else ["CHOWN", "DAC_OVERRIDE"]
                ),
            },
            "security_opt": (
                ["no-new-privileges:true"] if base_config.get("no_new_privileges") else []
            ),
            "tmpfs": (
                {"/tmp": "noexec,nosuid,size=100m"}
                if security_level in ["high", "critical"]
                else {}
            ),
        }

        logger.debug(
            "Generated sandbox config for %s at %s security level",
            language,
            security_level,
        )
        return sandbox_config

    async def validate_imports(self, code: str, language: str) -> list[dict[str, Any]]:
        """Validate imports against allowed/dangerous patterns."""

        import_violations = []

        if language.lower() == "python":
            import_violations = await self._analyze_python_imports(code)
        elif language.lower() in ["javascript", "js"]:
            import_violations = await self._analyze_javascript_imports(code)

        return [violation.model_dump() for violation in import_violations]

    async def _analyze_python_imports(self, code: str) -> list[SecurityViolation]:
        """Analyze Python imports for security issues."""
        violations = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    violations.extend(await self._validate_python_imports(node))

        except SyntaxError:
            # If code doesn't parse, try regex-based analysis
            import_patterns = [
                r"import\s+(\w+(?:\.\w+)*)",
                r"from\s+(\w+(?:\.\w+)*)\s+import",
            ]

            lines = code.splitlines()
            for line_num, line in enumerate(lines, 1):
                for pattern in import_patterns:
                    matches = re.findall(pattern, line)
                    for module in matches:
                        if self._is_dangerous_module(module):
                            violation = SecurityViolation(
                                type="dangerous_import",
                                severity=SecurityLevel.HIGH,
                                line_number=line_num,
                                pattern_matched=line.strip(),
                                description=f"Potentially dangerous module import: {module}",
                                suggested_fix=f"Review necessity of {module} import",
                            )
                            violations.append(violation)

        return violations

    async def _analyze_javascript_imports(self, code: str) -> list[SecurityViolation]:
        """Analyze JavaScript imports for security issues."""
        violations = []

        dangerous_modules = {
            "fs",
            "child_process",
            "cluster",
            "dgram",
            "dns",
            "net",
            "tls",
            "http",
            "https",
            "vm",
            "worker_threads",
            "os",
            "process",
        }

        # Patterns for different import styles
        import_patterns = [
            r"require\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
            r"import\s(?>.{0,300}?\sfrom\s{1,20}[\"'])([^\"'\n]{1,300})[\"']",
            r"import\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
        ]

        lines = code.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern in import_patterns:
                matches = re.findall(pattern, line)
                for module in matches:
                    module_name = module.split("/")[0]  # Get base module name
                    if module_name in dangerous_modules:
                        violation = SecurityViolation(
                            type="dangerous_import",
                            severity=SecurityLevel.HIGH,
                            line_number=line_num,
                            pattern_matched=line.strip(),
                            description=f"Potentially dangerous module import: {module}",
                            suggested_fix=f"Review necessity of {module} import",
                        )
                        violations.append(violation)

        return violations

    def _is_dangerous_module(self, module_name: str) -> bool:
        """Check if a module is considered dangerous."""
        dangerous_modules = {
            "os",
            "sys",
            "subprocess",
            "shutil",
            "socket",
            "urllib",
            "urllib2",
            "httplib",
            "httplib2",
            "requests",
            "ftplib",
            "telnetlib",
            "smtplib",
            "poplib",
            "imaplib",
            "pickle",
            "marshal",
            "shelve",
            "dill",
            "multiprocessing",
            "threading",
            "asyncio",
            "concurrent",
            "base64",
            "codecs",
            "tempfile",
            "pty",
            "fcntl",
            "mmap",
            "ctypes",
        }

        # Check if module or any parent module is dangerous
        module_parts = module_name.split(".")
        for i in range(len(module_parts)):
            partial_module = ".".join(module_parts[: i + 1])
            if partial_module in dangerous_modules:
                return True

        return False


# Factory function for creating SystemSecurityService instances
def create_security_service(
    cache_manager: Any | None = None,
) -> SystemSecurityService:
    """Create a SystemSecurityService instance with default configuration."""
    security_config = SystemSecurityConfig()
    return SystemSecurityService(security_config=security_config, cache_manager=cache_manager)
