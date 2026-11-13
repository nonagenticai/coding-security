"""Bug Hunter data models for error analysis and code remediation.

This module provides data structures for the Bug Hunter system, which analyzes
error logs, identifies bugs in code, and generates remediation suggestions. The models
support the full workflow from parsing errors to generating validated code modifications.

The Bug Hunter system uses these models to:
- Parse and categorize errors from various sources (logs, static analysis, runtime)
- Generate targeted code modifications to address identified issues
- Validate proposed changes for safety and correctness
- Provide comprehensive analysis results with confidence scoring

Classes:
    ErrorType: Enumeration of detectable error types across languages
    ParsedError: Structured representation of parsed errors with context
    CodeFix: Proposed code modification with explanation
    BugAnalysisResult: Complete analysis including errors and remediation
    FixValidationResult: Safety validation for proposed modifications

Example:
    ```python
    from bug_models import ErrorType, ParsedError, CodeFix, BugAnalysisResult

    # Parse an error
    error = ParsedError(
        error_type=ErrorType.IMPORT_ERROR,
        message="No module named 'requests'",
        file_path="app/main.py",
        line_number=5,
        function_name="fetch_data",
        stack_trace=[],
        confidence=0.95
    )

    # Generate a remediation
    fix = CodeFix(
        file_path="requirements.txt",
        line_number=None,
        original_code="",
        fixed_code="requests>=2.28.0\\n",
        explanation="Add missing 'requests' dependency",
        confidence=0.9,
        test_suggestion="Run 'pip install -r requirements.txt' to verify"
    )

    # Complete analysis result
    result = BugAnalysisResult(
        errors=[error],
        resolves=[fix],
        root_cause_analysis="Missing dependency declaration",
        fix_summary="Add requests to requirements.txt",
        estimated_effort="Low - single dependency addition",
        risk_assessment="Minimal risk - standard library addition"
    )
    ```
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic.dataclasses import dataclass


class ErrorType(Enum):
    """Enumeration of error types that can be detected and resolved."""

    SYNTAX_ERROR = "syntax_error"
    IMPORT_ERROR = "import_error"
    NAME_ERROR = "name_error"
    TYPE_ERROR = "type_error"
    ATTRIBUTE_ERROR = "attribute_error"
    INDEX_ERROR = "index_error"
    KEY_ERROR = "key_error"
    VALUE_ERROR = "value_error"
    RUNTIME_ERROR = "runtime_error"
    LOGIC_ERROR = "logic_error"
    PERFORMANCE_ERROR = "performance_error"


@dataclass
class ParsedError:
    """Structured representation of a parsed error from logs or code analysis."""

    error_type: ErrorType
    message: str
    file_path: str | None
    line_number: int | None
    function_name: str | None
    stack_trace: list[dict[str, Any]]
    confidence: float


@dataclass
class CodeFix:
    """Represents a proposed resolve for a code issue."""

    file_path: str
    line_number: int | None
    original_code: str
    fixed_code: str
    explanation: str
    confidence: float
    test_suggestion: str | None = None


@dataclass
class BugAnalysisResult:
    """Complete result of bug analysis including errors, resolves, and assessments."""

    errors: list[ParsedError]
    resolves: list[CodeFix]
    root_cause_analysis: str
    fix_summary: str
    estimated_effort: str
    risk_assessment: str


@dataclass
class BugFixValidationResult:
    """Result of validating a proposed resolve for safety and correctness."""

    is_safe: bool
    confidence: float
    warnings: list[str]
    suggestions: list[str]
    risk_level: str
