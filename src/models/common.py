"""Common API Models for the coding-security service.

This module contains shared Pydantic models used across all API endpoints.
These models provide a consistent structure for API responses, error handling,
and health monitoring throughout the application.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Safe string pattern: reject control characters except common whitespace
SAFE_STRING_PATTERN = r"^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$"


class ResponseStatus(StrEnum):
    """Enumeration of standard API response status values.

    Attributes:
        SUCCESS: Operation completed successfully without errors
        DEGRADED: Operation returned a PARTIAL/incomplete result — some step
            errored, timed out or was unavailable. The payload is usable but
            MUST NOT be read as a complete result. For a scanner this is the
            difference between "found nothing" and "did not look", so a
            consumer keying only on ``status`` never sees a failed scan as a
            clean pass.
        ERROR: Operation failed with an error condition
        PENDING: Operation has been queued but not yet started
        RUNNING: Operation is currently executing
        COMPLETED: Long-running operation has finished successfully
        FAILED: Long-running operation has terminated with failure
    """

    SUCCESS = "success"
    DEGRADED = "degraded"
    ERROR = "error"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BaseResponse(BaseModel):
    """Base response model providing standard fields for all API responses.

    Attributes:
        status (ResponseStatus): The operation status indicating success or failure
        message (str): Human-readable description of the operation result
        timestamp (datetime): UTC timestamp when the response was generated
        request_id (str): Unique identifier for request tracking and correlation
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "success",
                "message": "Operation completed successfully",
                "timestamp": "2025-07-13T10:30:00Z",
                "request_id": "req_12345",
            }
        }
    )

    status: ResponseStatus = Field(..., description="Response status")
    message: str = Field(..., description="Human-readable message", pattern=SAFE_STRING_PATTERN)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Response timestamp",
    )
    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        min_length=1,
        description="Unique request identifier",
    )


class SuccessResponse(BaseResponse):
    """Standard success response format with optional data payload.

    Attributes:
        status (ResponseStatus): Always set to SUCCESS for successful responses
        data (Optional[Dict[str, Any]]): Optional payload containing response data
    """

    status: ResponseStatus = ResponseStatus.SUCCESS
    data: dict[str, Any] | None = Field(None, description="Response data")


class PaginationParams(BaseModel):
    """Standard pagination parameters for list endpoints.

    Attributes:
        page (int): Page number to retrieve (1-based indexing)
        limit (int): Number of items per page (default: 50, max: 1000)
    """

    model_config = ConfigDict(json_schema_extra={"example": {"page": 1, "limit": 20}})

    page: int = Field(1, ge=1, description="Page number (1-based)")
    limit: int = Field(50, ge=1, le=1000, description="Items per page")


class PaginatedResponse(SuccessResponse):
    """Response format for paginated list endpoints.

    Attributes:
        pagination (Dict[str, Any]): Metadata about pagination state
        items (List[Any]): The actual items for the current page
    """

    pagination: dict[str, Any] = Field(..., description="Pagination metadata")
    items: list[Any] = Field(..., description="Response items")

    @field_validator("pagination")
    @classmethod
    def validate_pagination(cls, v):
        """Validate the pagination dictionary contains required keys."""
        required_keys = {"page", "limit", "total", "pages"}
        if not all(key in v for key in required_keys):
            raise ValueError(f"Pagination must contain: {required_keys}")
        return v


class HealthStatus(StrEnum):
    """Enumeration of system and component health status values."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentHealth(BaseModel):
    """Health status information for individual system components."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Database",
                "status": "healthy",
                "message": "All connections active",
                "last_check": "2025-07-13T10:30:00Z",
                "metrics": {"connections": 15, "response_time_ms": 12.5},
            }
        }
    )

    name: str = Field(..., min_length=1, pattern=SAFE_STRING_PATTERN, description="Component name")
    status: HealthStatus = Field(..., description="Health status")
    message: str | None = Field(None, pattern=SAFE_STRING_PATTERN, description="Status message")
    last_check: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Last health check",
    )
    metrics: dict[str, Any] | None = Field(None, description="Component metrics")
