"""Error Response Models for the coding-security API.

This module contains standardized error response models that ensure consistent
error handling across all API endpoints.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from models.common import SAFE_STRING_PATTERN, ResponseStatus


class StandardErrorResponse(BaseModel):
    """Standard error response format for all API errors.

    Attributes:
        status (ResponseStatus): Always 'error' for error responses
        message (str): Human-readable error description
        timestamp (datetime): ISO 8601 timestamp of when the error occurred
        request_id (str): Unique identifier for request tracking
        path (str): API endpoint path where the error occurred
        error_code (Optional[str]): Machine-readable error code
        details (Optional[Dict[str, Any]]): Additional error information
    """

    status: ResponseStatus = Field(
        default=ResponseStatus.ERROR,
        description="Response status (always 'error' for error responses)",
    )
    message: str = Field(
        ..., pattern=SAFE_STRING_PATTERN, description="Human-readable error message"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="ISO 8601 timestamp of when the error occurred",
    )
    request_id: str = Field(
        ...,
        pattern=SAFE_STRING_PATTERN,
        description="Unique request identifier for tracking",
    )
    path: str = Field(
        ...,
        pattern=SAFE_STRING_PATTERN,
        description="API endpoint path where the error occurred",
    )
    error_code: str | None = Field(
        None,
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code for programmatic handling",
    )
    details: dict[str, Any] | None = Field(None, description="Additional error context and details")

    @field_serializer("timestamp")
    def serialize_timestamp(self, timestamp: datetime) -> str:
        """Serialize timestamp to ISO 8601 format with timezone information."""
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp.isoformat()

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "error",
                "message": "Resource not found",
                "timestamp": "2025-01-12T10:30:00.000Z",
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "path": "/api/security/scan",
                "error_code": "RESOURCE_NOT_FOUND",
                "details": {
                    "resource_type": "container",
                    "resource_id": "my-container",
                },
            }
        }
    )


class APIValidationErrorDetail(BaseModel):
    """Detailed information about a specific field validation error."""

    field: str = Field(..., pattern=SAFE_STRING_PATTERN, description="Field that failed validation")
    message: str = Field(..., pattern=SAFE_STRING_PATTERN, description="Validation error message")
    type: str = Field(..., pattern=SAFE_STRING_PATTERN, description="Type of validation error")
    input: Any = Field(None, description="The invalid input value")


class ValidationErrorResponse(StandardErrorResponse):
    """Specialized error response for request validation failures."""

    status: ResponseStatus = Field(default=ResponseStatus.ERROR, description="Response status")
    message: str = Field(
        default="Request validation failed",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="VALIDATION_ERROR",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )
    validation_errors: list[APIValidationErrorDetail] = Field(
        ..., description="List of validation errors"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "error",
                "message": "Request validation failed",
                "timestamp": "2025-01-12T10:30:00.000Z",
                "request_id": "550e8400-e29b-41d4-a716-446655440000",
                "path": "/api/security/validate",
                "error_code": "VALIDATION_ERROR",
                "validation_errors": [
                    {
                        "field": "code",
                        "message": "Field required",
                        "type": "missing",
                        "input": None,
                    }
                ],
            }
        }
    )


# Predefined error responses for common HTTP status codes
class Error400Response(StandardErrorResponse):
    """Bad Request (400) error response model."""

    message: str = Field(
        default="Bad request",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="BAD_REQUEST",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )


class Error401Response(StandardErrorResponse):
    """Unauthorized (401) error response model."""

    message: str = Field(
        default="Authentication required",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="UNAUTHORIZED",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )


class Error403Response(StandardErrorResponse):
    """Forbidden (403) error response model."""

    message: str = Field(
        default="Insufficient permissions",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="FORBIDDEN",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )


class Error404Response(StandardErrorResponse):
    """Not Found (404) error response model."""

    message: str = Field(
        default="Resource not found",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="NOT_FOUND",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )


class Error422Response(ValidationErrorResponse):
    """Unprocessable Entity (422) error response for validation failures."""


class Error500Response(StandardErrorResponse):
    """Internal Server Error (500) response model."""

    message: str = Field(
        default="Internal server error",
        pattern=SAFE_STRING_PATTERN,
        description="Human-readable error message",
    )
    # Preserve the non-null Pydantic field in specialized error schemas.
    error_code: str = Field(  # ty: ignore[incompatible-mutable-override]
        default="INTERNAL_ERROR",
        pattern=SAFE_STRING_PATTERN,
        description="Machine-readable error code",
    )


# Aliases for backwards compatibility
APIError = StandardErrorResponse
NotFoundError = Error404Response
InternalServerError = Error500Response
