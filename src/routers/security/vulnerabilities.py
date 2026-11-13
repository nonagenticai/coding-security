"""Vulnerability analysis + pattern discovery endpoints.

Covers ``/analyze-vulnerabilities`` (legacy, file-or-container) and
``/patterns`` (pattern catalog) — the AST/regex-based detector surface that
predates the container-scoped scanners.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import posixpath
import shutil
from pathlib import Path

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException

from auth.tenant import require_tenant
from models.common import ResponseStatus
from models.errors import (
    Error400Response,
    Error401Response,
    Error403Response,
    Error404Response,
    Error422Response,
    Error500Response,
)
from models.responses import bad_request, internal_error
from models.security_validation_api_models import SecurityPatternsResponse
from services.scan_runner import _materialize_codebase
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilitySeverity,
    VulnerabilityType,
    get_security_detector_async,
)
from services.security_scan_service import get_security_scan_service
from utils.container_validation import validate_and_get_container_for_tenant

from ._common import (
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
    _convert_result_to_model,
    _filter_results_by_severity,
    _validate_severity_filter,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/analyze-vulnerabilities",
    response_model=SecurityAnalysisResponse,
    operation_id="analyze_vulnerabilities",
    summary="Analyze Security Vulnerabilities (Legacy)",
    description="""
    **Comprehensive Security Vulnerability Analysis** - Detect security vulnerabilities, assess risk levels, and provide remediation guidance

    **Note:** This endpoint supports both file-based and container-based analysis. For new implementations,
    consider using the dedicated container endpoints: POST /security/scan/{container_name}

    ## Purpose
    Performs advanced security analysis across multiple code files to identify:
    - SQL injection vulnerabilities
    - Cross-site scripting (XSS) issues
    - Command injection flaws
    - Hardcoded credentials and secrets
    - Weak cryptographic implementations
    - Buffer overflow vulnerabilities
    - Authentication and authorization flaws
    - Input validation weaknesses

    ## Vulnerability Categories

    ### Injection Attacks (OWASP A03:2021)
    - **SQL Injection**: Unsafe database query construction
    - **Command Injection**: OS command execution with user input
    - **XSS**: Cross-site scripting through unsafe output
    - **LDAP/XML Injection**: Directory and XML parsing vulnerabilities

    ### Cryptographic Failures (OWASP A02:2021)
    - **Weak Algorithms**: MD5, SHA1, DES usage
    - **Hardcoded Secrets**: API keys, passwords in source code
    - **Insecure Random**: Weak random number generation
    - **Poor Key Management**: Insecure key storage and handling

    ### Memory Safety Issues (C/C++)
    - **Buffer Overflow**: Unsafe string functions
    - **Use After Free**: Memory management errors
    - **Null Pointer Dereference**: Unsafe pointer operations
    - **Integer Overflow**: Arithmetic boundary violations

    ### Authentication & Authorization (OWASP A07:2021)
    - **Hardcoded Credentials**: Static passwords and tokens
    - **Weak Session Management**: Insecure session handling
    - **Privilege Escalation**: Improper access controls
    - **Information Disclosure**: Sensitive data exposure
    """,
    responses={
        200: {
            "model": SecurityAnalysisResponse,
            "description": "Security analysis completed successfully - vulnerabilities detected and categorized",
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid parameters, missing required fields, or invalid severity filter",
        },
        401: {
            "model": Error401Response,
            "description": "Authentication required - missing or invalid API key/token",
        },
        403: {
            "model": Error403Response,
            "description": "Insufficient permissions - user lacks access to security analysis features",
        },
        404: {
            "model": Error404Response,
            "description": "Not found - container, files, or resources do not exist or are inaccessible",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error - request body validation failed or incompatible parameters",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - security analysis engine failure or unexpected error",
        },
    },
)
async def analyze_security_vulnerabilities(
    request: SecurityAnalysisRequest = Body(..., description="Security analysis request"),
    tenant_id: str = Depends(require_tenant),
) -> SecurityAnalysisResponse:
    """Perform comprehensive security vulnerability analysis."""

    temp_dir: str | None = None
    degraded_reasons: list[str] = []
    try:
        # Files are only ever read from the caller's tenant-scoped workspace.
        # A bare ``file_paths`` used to be opened on THIS pod's filesystem —
        # an arbitrary-file-read (``["/etc/passwd"]``) for any licensed caller.
        if not request.container_name:
            raise bad_request(
                "container_name is required: files are read only from the caller's "
                "workspace, never from the security service's own filesystem"
            )

        # Validate severity filter if provided
        _validate_severity_filter(request.severity_filter)

        escaping = _escaping_paths(request.file_paths)
        if escaping:
            raise bad_request(
                "file_paths must stay inside the workspace; refused: " + ", ".join(escaping[:10])
            )

        # Same source as POST /scan/{container}: the tenant-scoped container,
        # materialized to local disk when the workspace is remote. The old
        # path joined the request paths onto the container-side
        # codebase_path (/workspace/...) and handed them to a detector that
        # reads THIS pod's filesystem — every file failed to open and the
        # endpoint answered "success, 0 files, 0 vulnerabilities".
        container_info = await validate_and_get_container_for_tenant(
            request.container_name, tenant_id
        )
        original_root = container_info.codebase_path
        materialized = await _materialize_codebase(
            container_info, request.container_name, tenant_id
        )
        temp_dir = materialized.temp_dir
        if materialized.incomplete:
            degraded_reasons.append("workspace fetch was incomplete")
        valid_files, missing = _resolve_workspace_files(
            container_info.codebase_path, original_root, request.file_paths
        )
        if not request.file_paths:
            valid_files = await get_security_scan_service()._resolve_container_file_paths(
                container_info, None, request.max_files
            )
        if missing:
            degraded_reasons.append(
                f"{len(missing)} requested file(s) not found in the workspace: "
                + ", ".join(missing[:10])
            )

        # Get security detector and perform analysis. Async accessor so a
        # cold-cache first-build runs its blocking version-probes off-thread
        # instead of stalling the event loop (defense-in-depth if warm was
        # skipped; normally the startup pre-warm makes this an instant hit).
        detector = await get_security_detector_async()
        result = await detector.analyze_security_vulnerabilities(
            file_paths=valid_files,
            include_low_confidence=request.include_low_confidence,
            max_files=request.max_files,
        )

        # Filter by severity if requested
        if request.severity_filter:
            _filter_results_by_severity(result, request.severity_filter)

        # Convert to response model
        response_model = _convert_result_to_model(result)
        if result.total_files_analyzed == 0:
            degraded_reasons.append("no file could be examined: the result is not computed")
        elif result.files_failed_to_parse:
            degraded_reasons.append(f"{result.files_failed_to_parse} file(s) could not be read")
        # The detector names each cause (engine missing/failed, a long-span
        # check that timed out naming file:line and rule, ...): surface them.
        degraded_reasons.extend(r for r in result.degraded_reasons if r not in degraded_reasons)
        if result.scan_degraded and not degraded_reasons:
            degraded_reasons.append("a vulnerability engine failed; findings may be incomplete")
        degraded = bool(degraded_reasons) or result.scan_degraded
        response_model.scan_degraded = degraded
        response_model.degraded_reasons = degraded_reasons

        logger.info(
            "Security analysis %s: %d vulnerabilities found in %d files",
            "DEGRADED" if degraded else "completed",
            result.total_vulnerabilities_found,
            result.total_files_analyzed,
        )

        return SecurityAnalysisResponse(
            status=ResponseStatus.DEGRADED if degraded else ResponseStatus.SUCCESS,
            message=(
                f"Security analysis DEGRADED ({'; '.join(degraded_reasons)}): analyzed "
                f"{result.total_files_analyzed} files, found "
                f"{result.total_vulnerabilities_found} security vulnerabilities"
                if degraded
                else f"Analyzed {result.total_files_analyzed} files, "
                f"found {result.total_vulnerabilities_found} security vulnerabilities"
            ),
            result=response_model,
            request_id=str(
                hash(f"security_{len(valid_files)}_{result.total_vulnerabilities_found}")
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Security analysis failed: %s", e)
        raise internal_error(f"Security analysis failed: {str(e)}")
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _workspace_relative(requested: str, original_root: str) -> str:
    """``/workspace/a/b.py`` or ``a/b.py`` -> ``a/b.py`` (not yet normalised)."""
    prefix = original_root.rstrip("/") + "/"
    rel = requested[len(prefix) :] if requested.startswith(prefix) else requested
    return rel.lstrip("/")


def _escaping_paths(file_paths: list[str] | None, original_root: str = "/workspace") -> list[str]:
    """Request paths that lexically climb out of the workspace root (``..``)."""
    escaping: list[str] = []
    for requested in file_paths or []:
        normalised = posixpath.normpath(_workspace_relative(requested, original_root))
        if normalised == ".." or normalised.startswith("../") or "\x00" in requested:
            escaping.append(requested)
    return escaping


def _resolve_workspace_files(
    root: str, original_root: str, file_paths: list[str] | None
) -> tuple[list[str], list[str]]:
    """Resolve request paths (relative to the workspace root) under ``root``.

    Accepts ``t4/sqli.py`` and the container-absolute ``/workspace/t4/sqli.py``.
    A path that resolves outside ``root`` (traversal) or does not exist is
    returned in ``missing`` — never read, never silently dropped.
    """
    found: list[str] = []
    missing: list[str] = []
    real_root = os.path.realpath(root)
    for requested in file_paths or []:
        rel = _workspace_relative(requested, original_root)
        candidate = os.path.realpath(os.path.join(real_root, rel))
        inside = os.path.commonpath([candidate, real_root]) == real_root
        if inside and os.path.isfile(candidate):
            found.append(candidate)
        else:
            missing.append(requested)
    return found, missing


_SEMGREP_LANG_ALIASES = {
    "js": "javascript",
    "ts": "typescript",
    "py": "python",
    "c#": "csharp",
    "c++": "cpp",
    "rb": "ruby",
    "golang": "go",
}


@functools.cache
def _semgrep_pack_languages(ruleset: str) -> frozenset[str]:
    """Languages named by the rules of the baked semgrep pack (a file, or a dir of them).

    The registry has served the pack as JSON (2026-08) and as YAML (2026-10);
    ``yaml.safe_load`` reads both (YAML is a superset of JSON). Read once per
    process; a file that is not a rule pack contributes nothing. The image build
    asserts this finds languages in the baked pack (Dockerfile).
    """
    root = Path(ruleset)
    files = sorted(root.glob("*")) if root.is_dir() else [root] if root.is_file() else []
    languages: set[str] = set()
    for path in files:
        try:
            with path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        for rule in data.get("rules", []) if isinstance(data, dict) else []:
            for lang in rule.get("languages", []) if isinstance(rule, dict) else []:
                if not isinstance(lang, str):
                    continue
                name = _SEMGREP_LANG_ALIASES.get(lang.lower(), lang.lower())
                if name and name not in ("generic", "regex", "none"):
                    languages.add(name)
    return frozenset(languages)


async def _language_engines(detector) -> dict[str, list[str]]:  # noqa: ANN001
    """language -> engines that analyse it in a source scan, from the live dispatch."""
    from services.bandit_scanner import BanditScanner
    from services.semgrep_scanner import _EXT_TO_LANG, SemgrepScanner

    engines: dict[str, set[str]] = {}
    for pattern in detector.patterns:
        if pattern.language != "any":
            engines.setdefault(pattern.language, set()).add("pattern")
    bandit = await asyncio.to_thread(BanditScanner)
    if bandit.is_available():
        engines.setdefault("python", set()).add("bandit")
    semgrep = SemgrepScanner()
    if semgrep.is_available():
        routed = set(_EXT_TO_LANG.values())
        for lang in await asyncio.to_thread(_semgrep_pack_languages, semgrep.ruleset):
            if lang in routed:
                engines.setdefault(lang, set()).add("semgrep")
    return {lang: sorted(names) for lang, names in sorted(engines.items())}


def _dependency_ecosystems() -> dict[str, list[str]]:
    """ecosystem -> engines that check its dependencies, from what is installed/baked.

    Keys are the canonical ``ecosystem`` selector values (``pypi``, not OSV's
    ``PyPI``), so every advertised key is accepted back by the dependency
    list route. A baked OSV directory for an ecosystem the selector
    does not accept (e.g. ``Go``) is not advertised. Authoritative cargo-audit /
    cargo-deny run in the rust test runner, not here, so they are not listed.
    """
    from config.settings import get_settings
    from models.security_api_models import DEPENDENCY_ECOSYSTEMS, canonical_ecosystem

    out: dict[str, set[str]] = {}
    db_root = Path(get_settings().osv_offline_db_dir)
    if db_root.is_dir():
        for child in db_root.iterdir():
            key = canonical_ecosystem(child.name)
            if child.is_dir() and key in DEPENDENCY_ECOSYSTEMS:
                out.setdefault(key, set()).add("osv-offline")
    return {eco: sorted(names) for eco, names in sorted(out.items())}


@router.get(
    "/patterns",
    response_model=SecurityPatternsResponse,
    operation_id="list_security_patterns",
    summary="Security Vulnerability Patterns",
    description="""
    **Security Pattern Information** - Discover available vulnerability detection patterns

    ## Purpose
    Provides comprehensive information about security vulnerability patterns including:
    - Supported vulnerability types and detection rules
    - Language-specific security patterns
    - CWE and OWASP category mappings
    - Pattern confidence and accuracy metrics
    """,
    responses={
        200: {
            "description": "Security patterns retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "vulnerability_types": [
                            "sql_injection",
                            "xss",
                            "command_injection",
                        ],
                        "severity_levels": [
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "info",
                        ],
                        "confidence_levels": ["high", "medium", "low"],
                        "supported_languages": ["python", "java", "javascript", "go"],
                        "pattern_categories": {
                            "injection": ["sql_injection", "command_injection", "xss"],
                            "cryptography": [
                                "weak_cryptography",
                                "hardcoded_credentials",
                            ],
                        },
                        "total_patterns": 150,
                        "pattern_distribution": {
                            "python": 40,
                            "java": 35,
                            "javascript": 30,
                        },
                    }
                }
            },
        },
        401: {
            "model": Error401Response,
            "description": "Authentication required - missing or invalid credentials",
        },
        403: {
            "model": Error403Response,
            "description": "Insufficient permissions to access security pattern information",
        },
        404: {
            "model": Error404Response,
            "description": "Not found - No security patterns found or service unavailable",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - failed to retrieve security patterns",
        },
    },
)
async def get_security_patterns(
    tenant_id: str = Depends(require_tenant),
) -> SecurityPatternsResponse:
    """Get available security vulnerability patterns.

    Returns comprehensive information about security vulnerability patterns
    and detection capabilities organized by category.
    """

    try:
        detector = await get_security_detector_async()

        # Everything language-related below is DERIVED from what actually runs:
        # the detector's loaded patterns, bandit (python, when installed) and the
        # baked semgrep pack's rule languages (when semgrep is installed). This
        # used to be a hardcoded list of 9 languages (incl. rust/go/csharp) that
        # no in-process rule covered.
        language_engines = await _language_engines(detector)
        supported_languages = sorted(language_engines)
        pattern_langs: dict[str, set[str]] = {}
        for pattern in detector.patterns:
            vtype = getattr(pattern.vulnerability_type, "value", str(pattern.vulnerability_type))
            pattern_langs.setdefault(vtype, set()).add(pattern.language)

        patterns_list = []
        for pattern_type in VulnerabilityType:
            pattern_info = {
                "id": pattern_type.value,
                "name": pattern_type.value.replace("_", " ").title(),
                "type": pattern_type.value,
                "severity_levels": [s.value for s in VulnerabilitySeverity],
                "confidence_levels": [c.value for c in VulnerabilityConfidence],
                # Languages with an in-process rule for this type ("any" = every file).
                "supported_languages": sorted(pattern_langs.get(pattern_type.value, set())),
            }
            patterns_list.append(pattern_info)

        pattern_categories = {
            "injection": [
                "sql_injection",
                "command_injection",
                "xss",
                "ldap_injection",
                "xml_injection",
            ],
            "cryptography": [
                "weak_cryptography",
                "insecure_random",
                "hardcoded_credentials",
            ],
            "memory_safety": [
                "buffer_overflow",
                "use_after_free",
                "null_pointer_dereference",
            ],
            "authentication": [
                "hardcoded_credentials",
                "privilege_escalation",
                "information_disclosure",
            ],
            "input_validation": [
                "sql_injection",
                "xss",
                "command_injection",
                "path_traversal",
            ],
        }

        owasp_mapping = {
            "A01:2021 – Broken Access Control": [
                "privilege_escalation",
                "information_disclosure",
            ],
            "A02:2021 – Cryptographic Failures": [
                "weak_cryptography",
                "hardcoded_credentials",
            ],
            "A03:2021 – Injection": [
                "sql_injection",
                "command_injection",
                "xss",
                "ldap_injection",
            ],
            "A07:2021 – Identification and Authentication Failures": ["hardcoded_credentials"],
        }

        pattern_distribution: dict[str, int] = {}
        for pattern in detector.patterns:
            pattern_distribution[pattern.language] = (
                pattern_distribution.get(pattern.language, 0) + 1
            )

        return SecurityPatternsResponse(
            message="Security vulnerability patterns retrieved successfully",
            patterns=patterns_list,
            total_patterns=len(patterns_list),
            vulnerability_types=[t.value for t in VulnerabilityType],
            severity_levels=[s.value for s in VulnerabilitySeverity],
            confidence_levels=[c.value for c in VulnerabilityConfidence],
            supported_languages=supported_languages,
            pattern_categories=pattern_categories,
            pattern_distribution=pattern_distribution,
            owasp_mapping=owasp_mapping,
            language_engines=language_engines,
            dependency_ecosystems=_dependency_ecosystems(),
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error("Error retrieving security patterns: %s", e)
        raise internal_error(f"Error retrieving security patterns: {str(e)}")
