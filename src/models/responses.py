"""Unified response helpers for consistent API responses.

This module provides standardized response helpers to ensure all API endpoints
return consistent response formats for both success and error cases.

Usage:
    from models.responses import success_response, error_response, not_found, bad_request, internal_error

    # Success response
    return success_response(data={"users": users}, message="Users retrieved")

    # Error responses
    raise not_found("Container", container_name)
    raise bad_request("Invalid input format")
    raise internal_error("Database connection failed")
"""

from typing import Any

from fastapi import HTTPException, status


def success_response(data: Any, message: str = "Success") -> dict:
    """Create a standardized success response.

    Args:
        data: The response data payload
        message: Optional success message

    Returns:
        Dict with standardized success format
    """
    return {
        "status": "success",
        "message": message,
        "data": data,
    }


def error_response(
    status_code: int,
    message: str,
    error_code: str = "INTERNAL_ERROR",
    details: dict | None = None,
) -> HTTPException:
    """Create a standardized error HTTPException.

    Args:
        status_code: HTTP status code
        message: Human-readable error message
        error_code: Machine-readable error code
        details: Additional error details

    Returns:
        HTTPException with standardized error format
    """
    return HTTPException(
        status_code=status_code,
        detail={
            "status": "error",
            "message": message,
            "error_code": error_code,
            "details": details or {},
        },
    )


def not_found(resource: str, identifier: str) -> HTTPException:
    """Create a 404 Not Found error.

    Args:
        resource: The type of resource that wasn't found (e.g., "Container", "Graph")
        identifier: The identifier that was searched for

    Returns:
        HTTPException with 404 status
    """
    return error_response(
        status_code=status.HTTP_404_NOT_FOUND,
        message=f"{resource} '{identifier}' not found",
        error_code=f"{resource.upper().replace(' ', '_')}_NOT_FOUND",
    )


def bad_request(message: str, details: dict | None = None) -> HTTPException:
    """Create a 400 Bad Request error.

    Args:
        message: Description of what was wrong with the request
        details: Additional error details

    Returns:
        HTTPException with 400 status
    """
    return error_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        message=message,
        error_code="BAD_REQUEST",
        details=details,
    )


def validation_error(message: str, field: str, details: dict | None = None) -> HTTPException:
    """Create a 422 Validation Error.

    Args:
        message: Description of the validation failure
        field: The field that failed validation
        details: Additional error details

    Returns:
        HTTPException with 422 status
    """
    return error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        message=message,
        error_code="VALIDATION_ERROR",
        details={"field": field, **(details or {})},
    )


def internal_error(message: str, details: dict | None = None) -> HTTPException:
    """Create a 500 Internal Server Error.

    Args:
        message: Description of the internal error
        details: Additional error details (exception info, etc.)

    Returns:
        HTTPException with 500 status
    """
    return error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        message=message,
        error_code="INTERNAL_ERROR",
        details=details,
    )


def unauthorized(message: str = "Authentication required") -> HTTPException:
    """Create a 401 Unauthorized error.

    Args:
        message: Description of the authentication failure

    Returns:
        HTTPException with 401 status
    """
    return error_response(
        status_code=status.HTTP_401_UNAUTHORIZED,
        message=message,
        error_code="UNAUTHORIZED",
    )


def forbidden(message: str = "Access denied") -> HTTPException:
    """Create a 403 Forbidden error.

    Args:
        message: Description of why access was denied

    Returns:
        HTTPException with 403 status
    """
    return error_response(
        status_code=status.HTTP_403_FORBIDDEN,
        message=message,
        error_code="FORBIDDEN",
    )


def conflict(resource: str, message: str) -> HTTPException:
    """Create a 409 Conflict error.

    Args:
        resource: The type of resource with the conflict
        message: Description of the conflict

    Returns:
        HTTPException with 409 status
    """
    return error_response(
        status_code=status.HTTP_409_CONFLICT,
        message=message,
        error_code=f"{resource.upper().replace(' ', '_')}_CONFLICT",
    )


def service_unavailable(
    message: str = "Service temporarily unavailable",
) -> HTTPException:
    """Create a 503 Service Unavailable error.

    Args:
        message: Description of why the service is unavailable

    Returns:
        HTTPException with 503 status
    """
    return error_response(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        message=message,
        error_code="SERVICE_UNAVAILABLE",
    )


def timeout_error(message: str = "Request timed out") -> HTTPException:
    """Create a 504 Gateway Timeout error.

    Args:
        message: Description of what timed out

    Returns:
        HTTPException with 504 status
    """
    return error_response(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        message=message,
        error_code="TIMEOUT",
    )


def rate_limited(message: str = "Rate limit exceeded") -> HTTPException:
    """Create a 429 Too Many Requests error.

    Args:
        message: Description of the rate limit

    Returns:
        HTTPException with 429 status
    """
    return error_response(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        message=message,
        error_code="RATE_LIMITED",
    )
