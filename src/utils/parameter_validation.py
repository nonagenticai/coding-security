"""Parameter validation utilities for API endpoints.

Provides validate_project_root and validate_string_parameter for use
by the system_dependencies router and other endpoints.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import HTTPException

logger = logging.getLogger(__name__)

# Null-like string values that should be treated as None in most cases
NULL_LIKE_VALUES = {"null", "none", "undefined", "nil", ""}

# Test paths allowed during schema testing
TEST_PATHS = {"/tmp/test", "/tmp/test-project", "/test/project"}


def validate_project_root(project_root: str | None, allow_none: bool = True) -> Path | None:
    """Validate a project_root parameter.

    Args:
        project_root: The project root path to validate
        allow_none: Whether None values are allowed

    Returns:
        Validated Path object or None if allowed

    Raises:
        HTTPException: 400 status for invalid project roots
    """
    if project_root is None:
        if allow_none:
            return None
        else:
            raise HTTPException(
                status_code=400,
                detail="Project root parameter is required",
            )

    # Special handling for test values
    if isinstance(project_root, str):
        # Check for null-like strings
        stripped = project_root.strip().lower()
        if stripped in NULL_LIKE_VALUES:
            if allow_none:
                return None
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Parameter 'project_root' received null-like value: '{project_root}'",
                )

        # For schema testing, allow some obviously test paths
        if project_root in TEST_PATHS:
            return Path(project_root)

    return validate_path_parameter(
        project_root,
        parameter_name="project_root",
        allow_none=allow_none,
        must_exist=False,
    )


def validate_path_parameter(
    parameter_value: str | None,
    parameter_name: str,
    allow_none: bool = True,
    must_exist: bool = False,
) -> Path | None:
    """Validate a path parameter.

    Args:
        parameter_value: The path string to validate
        parameter_name: Name of the parameter for error messages
        allow_none: Whether None values are allowed
        must_exist: Whether the path must exist on the filesystem

    Returns:
        Validated Path object or None

    Raises:
        HTTPException: 400 status for invalid paths
    """
    if parameter_value is None or (
        isinstance(parameter_value, str) and not parameter_value.strip()
    ):
        if allow_none:
            return None
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Parameter '{parameter_name}' is required and cannot be null or empty",
            )

    cleaned = parameter_value.strip()

    # Basic path validation
    if not cleaned.startswith("/") and not (len(cleaned) > 1 and cleaned[1] == ":"):
        raise HTTPException(
            status_code=400,
            detail=f"Parameter '{parameter_name}' must be an absolute path, got: {cleaned}",
        )

    path = Path(cleaned)

    if must_exist and not path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Path for '{parameter_name}' does not exist: {cleaned}",
        )

    return path


def validate_string_parameter(
    parameter_value: str | None,
    parameter_name: str,
    allow_none: bool = True,
    min_length: int = 0,
    max_length: int | None = None,
    allowed_values: set | None = None,
    allow_null_strings: bool = True,
) -> str | None:
    """Validate a string parameter.

    Args:
        parameter_value: The string parameter value to validate
        parameter_name: Name of the parameter for error messages
        allow_none: Whether None/empty values are allowed
        min_length: Minimum required length
        max_length: Maximum allowed length
        allowed_values: Set of allowed values (case-insensitive)
        allow_null_strings: Whether to allow "null" as a string value

    Returns:
        Validated string or None if None is allowed and value is None/empty

    Raises:
        HTTPException: 400 status for invalid parameters
    """
    # Check for null-like strings
    if parameter_value and isinstance(parameter_value, str) and not allow_null_strings:
        stripped = parameter_value.strip().lower()
        if stripped in NULL_LIKE_VALUES:
            raise HTTPException(
                status_code=400,
                detail=f"Parameter '{parameter_name}' received null-like value: '{parameter_value}'",
            )

    # Check for actual None/empty values
    if parameter_value is None or (
        isinstance(parameter_value, str) and not parameter_value.strip()
    ):
        if allow_none:
            return None
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Parameter '{parameter_name}' is required and cannot be null or empty",
            )

    # Trim whitespace
    cleaned_value = parameter_value.strip()

    # Check min_length
    if min_length > 0 and len(cleaned_value) < min_length:
        raise HTTPException(
            status_code=400,
            detail=f"Parameter '{parameter_name}' must be at least {min_length} characters long",
        )

    # Check max_length
    if max_length is not None and len(cleaned_value) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"Parameter '{parameter_name}' must not exceed {max_length} characters",
        )

    # Check allowed values (case-insensitive)
    if allowed_values is not None:
        if cleaned_value.lower() not in {v.lower() for v in allowed_values}:
            raise HTTPException(
                status_code=400,
                detail=f"Parameter '{parameter_name}' must be one of: {', '.join(sorted(allowed_values))}. Got: '{cleaned_value}'",
            )

    return cleaned_value
