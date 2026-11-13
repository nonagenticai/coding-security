"""Security Validation API Response Models.

This module provides response models for security validation endpoints,
including code validation and sandbox configuration.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from models.common import SAFE_STRING_PATTERN, BaseResponse, ResponseStatus


class CodeSecurityValidationResponse(BaseResponse):
    """Response from code security validation operation.

    Attributes:
        status: Response status (success/error)
        validation: Detailed validation results
        language: Programming language of validated code
        execution_context: Context in which code will execute
    """

    status: ResponseStatus = ResponseStatus.SUCCESS
    validation: dict[str, Any] = Field(
        ...,
        description="Validation results including safety, violations, and risk scores",
    )
    language: str = Field(..., description="Programming language", pattern=SAFE_STRING_PATTERN)
    execution_context: str = Field(
        ...,
        description="Execution context (analysis, sandbox, production)",
        pattern=SAFE_STRING_PATTERN,
    )


class SandboxConfigResponse(BaseResponse):
    """Response containing sandbox configuration information.

    Attributes:
        status: Response status (success/error)
        config: Sandbox configuration settings
        language: Programming language for sandbox
        security_level: Security level (STRICT, STANDARD, RELAXED)
        description: Human-readable description
    """

    status: ResponseStatus = ResponseStatus.SUCCESS
    config: dict[str, Any] = Field(
        ..., description="Sandbox configuration with resource limits and permissions"
    )
    language: str = Field(..., description="Programming language", pattern=SAFE_STRING_PATTERN)
    security_level: str = Field(..., description="Security level", pattern=SAFE_STRING_PATTERN)
    description: str = Field(
        ..., description="Configuration description", pattern=SAFE_STRING_PATTERN
    )


class SecurityPatternsResponse(BaseResponse):
    """Response containing security vulnerability patterns information.

    Attributes:
        status: Response status (success/error)
        patterns: List of vulnerability patterns
        total_patterns: Total number of patterns available
        vulnerability_types: List of vulnerability types
        severity_levels: Available severity levels
        confidence_levels: Available confidence levels
        supported_languages: Languages with pattern support
        pattern_categories: Patterns grouped by category
        pattern_distribution: Distribution of patterns by language
        owasp_mapping: OWASP category mappings
    """

    status: ResponseStatus = ResponseStatus.SUCCESS
    patterns: list[dict[str, Any]] = Field(
        default_factory=list, description="List of vulnerability patterns"
    )
    total_patterns: int = Field(..., description="Total patterns available")
    vulnerability_types: list[str] = Field(default_factory=list, description="Vulnerability types")
    severity_levels: list[str] = Field(default_factory=list, description="Severity levels")
    confidence_levels: list[str] = Field(default_factory=list, description="Confidence levels")
    supported_languages: list[str] = Field(
        default_factory=list,
        description=(
            "Languages a source scan actually analyses with a language-specific engine "
            "(derived from the loaded pattern rules, bandit and the baked semgrep pack; "
            "see language_engines). Secret/'any' rules apply to every scanned file."
        ),
    )
    language_engines: dict[str, list[str]] = Field(
        default_factory=dict,
        description="language -> engines (pattern, bandit, semgrep) that analyse it on this pod",
    )
    dependency_ecosystems: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Dependency ecosystem -> engines on this pod that check it: osv-offline "
            "(baked OSV DB present for that ecosystem). Keys are the canonical "
            "`ecosystem` selector values (pypi, crates.io) accepted by the "
            "dependency list route."
        ),
    )
    pattern_categories: dict[str, list[str]] = Field(
        default_factory=dict, description="Patterns by category"
    )
    pattern_distribution: dict[str, int] = Field(
        default_factory=dict, description="Patterns by language"
    )
    owasp_mapping: dict[str, list[str]] = Field(
        default_factory=dict, description="OWASP category mappings"
    )
