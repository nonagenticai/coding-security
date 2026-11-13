"""Code-security validation + sandbox-config endpoints.

Covers the legacy ``/validate`` and ``/sandbox-config/{language}/{security_level}``
routes — the per-snippet validation surface that predates the container-scan
endpoints.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from auth.tenant import require_tenant
from dependencies import get_security_service
from models.common import ResponseStatus
from models.errors import (
    Error400Response,
    Error401Response,
    Error403Response,
    Error404Response,
    Error422Response,
    Error500Response,
)
from models.responses import internal_error, not_found
from models.security_models import (
    SecurityValidationRequest,
    SecurityValidationResult,
)
from models.security_validation_api_models import (
    CodeSecurityValidationResponse,
    SandboxConfigResponse,
)
from services.security_service import SecurityLanguageNotCoveredError, SystemSecurityService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/validate",
    response_model=CodeSecurityValidationResponse,
    operation_id="validate_code_security",
    summary="Validate Code Security",
    description="""
    **Validate code for potential security vulnerabilities before execution.**

    Performs comprehensive security analysis including:
    - Detection of dangerous operations (file I/O, network access, process execution)
    - Identification of injection vulnerabilities (SQL, command, code injection)
    - Analysis of import statements for dangerous modules
    - Risk scoring based on threat severity
    - Sandbox configuration recommendations

    Returns a detailed security assessment with risk scores and remediation suggestions.
    """,
    responses={
        200: {
            "model": SecurityValidationResult,
            "description": "Security validation completed successfully",
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid input format or parameters",
        },
        401: {
            "model": Error401Response,
            "description": "Authentication required - missing or invalid credentials",
        },
        403: {
            "model": Error403Response,
            "description": "Insufficient permissions to validate code security",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error - request body contains invalid data",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - security validation failed",
        },
    },
)
async def validate_code_security(
    request: SecurityValidationRequest,
    security_service: SystemSecurityService = Depends(get_security_service),
    tenant_id: str = Depends(require_tenant),
):
    """Validate code for security issues."""
    try:
        result = await security_service.validate_code_security(request, tenant_id=tenant_id)

        # Wrap the result in the expected format
        validation = {
            "is_safe": result.is_safe,
            "violations": result.violations,
            "risk_score": result.risk_score,
            "risk_level": (
                "low" if result.risk_score < 30 else "medium" if result.risk_score < 70 else "high"
            ),
            "sandbox_config": result.sandbox_config,
            "analysis_degraded": result.analysis_degraded,
            "degraded_reasons": result.degraded_reasons,
        }

        execution_context = (
            request.context.get("execution_context", "analysis") if request.context else "analysis"
        )

        return CodeSecurityValidationResponse(
            status=(
                ResponseStatus.DEGRADED if result.analysis_degraded else ResponseStatus.SUCCESS
            ),
            message=(
                f"Code security validation DEGRADED for {request.language}: "
                + "; ".join(result.degraded_reasons)
                if result.analysis_degraded
                else f"Code security validation completed for {request.language}"
            ),
            validation=validation,
            language=request.language,
            execution_context=execution_context,
        )
    except HTTPException:
        raise
    except SecurityLanguageNotCoveredError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except ValueError as e:
        # Handle container not found or other validation errors
        raise not_found("Resource", str(e))
    except Exception as e:
        raise internal_error(str(e))


@router.get(
    "/sandbox-config/{language}/{security_level}",
    response_model=SandboxConfigResponse,
    operation_id="get_sandbox_config",
    summary="Sandbox Configuration",
    description="""
    **Get recommended sandbox configuration for safe code execution.**

    Returns language-specific sandbox settings based on security level:
    - **STRICT**: Maximum isolation, no external access
    - **STANDARD**: Balanced security with limited resource access
    - **RELAXED**: Minimal restrictions for trusted code

    Configuration includes:
    - Allowed/blocked system calls
    - Resource limits (CPU, memory, disk)
    - Network access policies
    - File system permissions
    - Environment variable filtering
    """,
    responses={
        200: {
            "description": "Sandbox configuration retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "language": "python",
                        "security_level": "STANDARD",
                        "allowed_modules": ["math", "datetime", "json"],
                        "blocked_modules": ["os", "subprocess", "socket"],
                        "resource_limits": {
                            "cpu_time": 30,
                            "memory_mb": 512,
                            "disk_mb": 100,
                        },
                        "network_access": False,
                        "file_system_access": "readonly",
                    }
                }
            },
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid language or security level",
        },
        401: {
            "model": Error401Response,
            "description": "Authentication required - missing or invalid credentials",
        },
        403: {
            "model": Error403Response,
            "description": "Insufficient permissions to access sandbox configurations",
        },
        404: {
            "model": Error404Response,
            "description": "Language or security level not found",
        },
        422: {
            "model": Error422Response,
            "description": "Invalid parameters - language or security level format error",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error - failed to generate sandbox configuration",
        },
    },
)
async def get_sandbox_config(
    language: str,
    security_level: str,
    security_service: SystemSecurityService = Depends(get_security_service),
    tenant_id: str = Depends(require_tenant),
):
    """Get sandbox configuration for language and security level."""
    try:
        sandbox_config = await security_service.generate_sandbox_config(language, security_level)

        # Wrap in the expected format with resource_limits
        config = {
            **sandbox_config,
            "resource_limits": {
                "memory_limit": sandbox_config.get("memory_limit", "512m"),
                "cpu_limit": sandbox_config.get("cpu_limit", "1.0"),
                "disk_limit": sandbox_config.get("disk_limit", "1g"),
                "execution_timeout": sandbox_config.get("execution_timeout", 30),
                "network_access": not (sandbox_config.get("network") == "none"),
                "filesystem_access": not sandbox_config.get("read_only", False),
            },
        }

        return SandboxConfigResponse(
            message=f"Sandbox configuration retrieved for {language}",
            config=config,
            language=language,
            security_level=security_level,
            description=f"Sandbox configuration for {language} at {security_level} security level",
        )
    except Exception as e:
        raise internal_error(str(e))
