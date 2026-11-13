"""Models package for the coding-security service.

Provides all Pydantic models for API requests, responses, and domain objects.
"""

from models.common import (
    SAFE_STRING_PATTERN,
    BaseResponse,
    ComponentHealth,
    HealthStatus,
    PaginatedResponse,
    PaginationParams,
    ResponseStatus,
    SuccessResponse,
)
from models.errors import (
    APIValidationErrorDetail,
    Error400Response,
    Error401Response,
    Error403Response,
    Error404Response,
    Error422Response,
    Error500Response,
    StandardErrorResponse,
    ValidationErrorResponse,
)
from models.responses import (
    bad_request,
    conflict,
    error_response,
    forbidden,
    internal_error,
    not_found,
    rate_limited,
    service_unavailable,
    success_response,
    timeout_error,
    unauthorized,
    validation_error,
)
from models.security_models import (
    OSVPackageInfo,
    OSVVulnerability,
    PackageInfo,
    SecurityLevel,
    SecurityReportRequest,
    SecurityScanRequest,
    SecurityValidationRequest,
    SecurityValidationResult,
    SecurityViolation,
    VulnerabilityScanResult,
)

__all__ = [
    # Common models
    "SAFE_STRING_PATTERN",
    "ResponseStatus",
    "BaseResponse",
    "SuccessResponse",
    "PaginationParams",
    "PaginatedResponse",
    "HealthStatus",
    "ComponentHealth",
    # Error models
    "StandardErrorResponse",
    "APIValidationErrorDetail",
    "ValidationErrorResponse",
    "Error400Response",
    "Error401Response",
    "Error403Response",
    "Error404Response",
    "Error422Response",
    "Error500Response",
    # Response helpers
    "success_response",
    "error_response",
    "not_found",
    "bad_request",
    "validation_error",
    "internal_error",
    "unauthorized",
    "forbidden",
    "conflict",
    "service_unavailable",
    "timeout_error",
    "rate_limited",
    # Security models
    "SecurityLevel",
    "SecurityViolation",
    "SecurityValidationRequest",
    "SecurityValidationResult",
    "SecurityScanRequest",
    "SecurityReportRequest",
    "VulnerabilityScanResult",
    "OSVPackageInfo",
    "OSVVulnerability",
    "PackageInfo",
]
