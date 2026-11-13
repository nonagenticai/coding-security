"""
API endpoints for system dependency detection and management.
"""

# Removed to fix TypeAdapter error with Request parameter
# from __future__ import annotations

import logging
import platform
import re
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from auth.tenant import require_tenant
from models.errors import (
    Error400Response,
    Error404Response,
    Error422Response,
    Error500Response,
)
from models.responses import (
    bad_request,
    error_response,
    internal_error,
)
from services.system_dependency_manager import (
    DependencyType,
    PackageManager,
    SystemDependencyManager,
)
from utils.parameter_validation import (
    validate_project_root,
    validate_string_parameter,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class SystemPackage(BaseModel):
    """Model for system package information."""

    package_manager: str = Field(..., description="Package manager type (apt, yum, brew, etc.)")
    packages: list[str] = Field(..., description="List of package names for this package manager")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "package_manager": "apt",
                "packages": ["libxml2-dev", "libxslt1-dev"],
            }
        }
    )


class DependencyInfo(BaseModel):
    """Model for dependency information."""

    name: str = Field(..., description="Name of the dependency")
    description: str = Field(
        ..., description="Human-readable description of what this dependency provides"
    )
    dependency_type: str = Field(
        ..., description="Type of dependency (build, runtime, development, etc.)"
    )
    is_installed: bool = Field(
        ..., description="Whether this dependency is currently installed on the system"
    )
    system_packages: dict[str, list[str]] = Field(
        ..., description="Mapping of package managers to their respective package names"
    )
    test_command: str | None = Field(
        None, description="Command to test if the dependency is available"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "lxml",
                "description": "XML processing libraries",
                "dependency_type": "build",
                "is_installed": False,
                "system_packages": {
                    "apt": ["libxml2-dev", "libxslt1-dev"],
                    "yum": ["libxml2-devel", "libxslt-devel"],
                    "brew": ["libxml2", "libxslt"],
                },
                "test_command": "xml2-config --version",
            }
        }
    )


class DependencyDetectionResponse(BaseModel):
    """Response model for dependency detection."""

    detected_package_manager: str | None = Field(
        None,
        description="Package manager detected on the system (apt, yum, brew, etc.)",
    )
    project_root: str = Field(
        ..., description="Absolute path to the project root directory that was scanned"
    )
    total_dependencies_checked: int = Field(
        ..., description="Total number of dependencies that were checked"
    )
    missing_dependencies: list[DependencyInfo] = Field(
        ...,
        description="List of dependencies that are missing and need to be installed",
    )
    installed_dependencies: list[DependencyInfo] = Field(
        ..., description="List of dependencies that are already installed on the system"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detected_package_manager": "apt",
                "project_root": "/home/user/myproject",
                "total_dependencies_checked": 3,
                "missing_dependencies": [
                    {
                        "name": "lxml",
                        "description": "XML processing libraries",
                        "dependency_type": "build",
                        "is_installed": False,
                        "system_packages": {"apt": ["libxml2-dev", "libxslt1-dev"]},
                        "test_command": "xml2-config --version",
                    }
                ],
                "installed_dependencies": [
                    {
                        "name": "Pillow",
                        "description": "Image processing libraries",
                        "dependency_type": "build",
                        "is_installed": True,
                        "system_packages": {"apt": ["libjpeg-dev", "zlib1g-dev", "libpng-dev"]},
                        "test_command": None,
                    }
                ],
            }
        }
    )


class InstallScriptResponse(BaseModel):
    """Response model for installation script generation."""

    script_content: str = Field(
        ..., description="Shell script content for installing missing dependencies"
    )
    package_manager: str = Field(
        ..., description="Package manager used in the script (apt, yum, brew, etc.)"
    )
    dependencies_count: int = Field(
        ..., description="Number of dependencies included in the installation script"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "script_content": "#!/bin/bash\n\n# Install system dependencies\nsudo apt-get update\nsudo apt-get install -y libxml2-dev libxslt1-dev\nsudo apt-get install -y libpq-dev\n",
                "package_manager": "apt",
                "dependencies_count": 2,
            }
        }
    )


class DockerfileSnippetResponse(BaseModel):
    """Response model for Dockerfile snippet generation."""

    snippet: str = Field(
        ..., description="Dockerfile snippet content for installing system dependencies"
    )
    dependencies_included: list[str] = Field(
        ..., description="List of dependencies included in the Dockerfile snippet"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "snippet": "# Install system dependencies\nRUN apt-get update && apt-get install -y \\\n    libxml2-dev \\\n    libxslt1-dev \\\n    libpq-dev \\\n    && rm -rf /var/lib/apt/lists/*",
                "dependencies_included": ["python3-dev", "build-essential"],
            }
        }
    )


class CIConfigResponse(BaseModel):
    """Response model for CI configuration generation."""

    platform: str = Field(
        ...,
        description="CI platform the configuration was generated for (github, gitlab)",
    )
    configuration: str = Field(
        ..., description="CI configuration content for installing system dependencies"
    )
    dependencies_included: list[str] = Field(
        ..., description="List of dependencies included in the CI configuration"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "platform": "github",
                "configuration": "name: Install Dependencies\nrun: |\n  sudo apt-get update\n  sudo apt-get install -y libxml2-dev libxslt1-dev\n  sudo apt-get install -y libpq-dev",
                "dependencies_included": ["python3-dev"],
            }
        }
    )


class GenerateScriptRequest(BaseModel):
    """Request model for generating installation scripts with specific dependencies."""

    dependencies: list[str] | None = Field(
        None,
        description="List of specific dependency names to include in the script. If not provided, dependencies will be auto-detected from the project.",
    )

    model_config = ConfigDict(
        json_schema_extra={"example": {"dependencies": ["python3-dev", "build-essential"]}}
    )


class GenerateDockerfileRequest(BaseModel):
    """Request model for generating Dockerfile snippets with specific dependencies."""

    dependencies: list[str] | None = Field(
        None,
        description="List of specific dependency names to include in the Dockerfile. If not provided, dependencies will be auto-detected from the project.",
    )

    model_config = ConfigDict(
        json_schema_extra={"example": {"dependencies": ["python3-dev", "build-essential"]}}
    )


class GenerateCIConfigRequest(BaseModel):
    """Request model for generating CI configuration with specific dependencies."""

    dependencies: list[str] | None = Field(
        None,
        description="List of specific dependency names to include in the CI config. If not provided, dependencies will be auto-detected from the project.",
    )

    model_config = ConfigDict(json_schema_extra={"example": {"dependencies": ["python3-dev"]}})


class DetectDependenciesQueryParams(BaseModel):
    """Query parameters for dependency detection endpoint with validation."""

    project_root: str | None = Field(
        None,
        description="Absolute path to the project root directory to scan",
    )
    include_optional: bool = Field(
        False,
        description="Whether to include optional dependencies",
    )
    fast_mode: bool = Field(
        False,
        description="Skip installation checks for faster response",
    )

    @field_validator("project_root")
    @classmethod
    def validate_project_root_path(cls, v: str | None) -> str | None:
        """Validate project_root is a valid absolute path if provided."""
        if v is None:
            return v
        # Reject null-like string values
        if v.lower() in ("null", "none", "undefined", ""):
            return None
        # Validate it looks like an absolute path
        if not v.startswith("/") and not (len(v) > 1 and v[1] == ":"):
            raise ValueError(f"project_root must be an absolute path, got: {v}")
        return v

    model_config = ConfigDict(extra="forbid")  # Reject unknown parameters


def validate_query_params_for_detect(request: Request) -> DetectDependenciesQueryParams:
    """Validate query parameters for detect endpoint using Pydantic model.

    This approach avoids TypeAdapter ForwardRef issues by using a dedicated
    Pydantic model with extra='forbid' to reject unknown parameters.

    Args:
        request: FastAPI Request object

    Returns:
        Validated query parameters

    Raises:
        HTTPException: 400 if unknown parameters are provided, 422 for validation errors
    """
    query_params = dict(request.query_params)

    # Known parameters for this endpoint
    known_params = {"project_root", "include_optional", "fast_mode", "tenant_id"}

    # Check for unknown parameters
    unknown_params = set(query_params.keys()) - known_params
    if unknown_params:
        raise bad_request(
            f"Unknown query parameters: {', '.join(sorted(unknown_params))}. "
            f"Allowed parameters: {', '.join(sorted(known_params - {'tenant_id'}))}"
        )

    try:
        # Parse and validate known parameters
        return DetectDependenciesQueryParams(
            project_root=query_params.get("project_root"),
            include_optional=query_params.get("include_optional", "false").lower()
            in ("true", "1", "yes"),
            fast_mode=query_params.get("fast_mode", "false").lower() in ("true", "1", "yes"),
        )
    except ValueError as e:
        raise error_response(
            status_code=422,
            message=f"Invalid parameter value: {str(e)}",
            error_code="VALIDATION_ERROR",
        )


@router.get(
    "/detect",
    response_model=DependencyDetectionResponse,
    operation_id="detect_system_dependencies",
    summary="Detect system dependencies",
    description="Analyze the project to detect required system dependencies based on package files (requirements.txt, package.json, etc.) and determine which are missing from the current system",
    responses={
        200: {
            "model": DependencyDetectionResponse,
            "description": "Successfully detected dependencies",
            "content": {
                "application/json": {
                    "example": {
                        "detected_package_manager": "apt",
                        "project_root": "/home/user/myproject",
                        "total_dependencies_checked": 5,
                        "missing_dependencies": [
                            {
                                "name": "lxml",
                                "description": "XML processing libraries",
                                "dependency_type": "build",
                                "is_installed": False,
                                "system_packages": {"apt": ["libxml2-dev", "libxslt1-dev"]},
                                "test_command": "xml2-config --version",
                            }
                        ],
                        "installed_dependencies": [
                            {
                                "name": "Pillow",
                                "description": "Image processing libraries",
                                "dependency_type": "build",
                                "is_installed": True,
                                "system_packages": {
                                    "apt": ["libjpeg-dev", "zlib1g-dev", "libpng-dev"]
                                },
                                "test_command": None,
                            }
                        ],
                    }
                }
            },
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - project root directory does not exist or invalid parameters",
        },
        404: {
            "model": Error404Response,
            "description": "Project root directory not found",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error in request parameters",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error during dependency detection or analysis",
        },
    },
)
async def detect_dependencies(
    request: Request,
    project_root: str | None = Query(
        None,
        description="Absolute path to the project root directory to scan. If not provided, uses current working directory",
    ),
    include_optional: bool = Query(
        False,
        description="Whether to include optional dependencies in the detection process. Optional dependencies are typically development or testing tools",
    ),
    fast_mode: bool = Query(
        False,
        description="Skip installation checks for faster response. Only detects which dependencies are defined in the project, not their installation status",
    ),
    tenant_id: str = Depends(require_tenant),
) -> DependencyDetectionResponse:
    """Detect system dependencies required by the project.

    This endpoint analyzes the project directory for package files (requirements.txt,
    package.json, etc.) and determines which system-level dependencies are required
    but missing from the current system.

    Args:
        request: The FastAPI request object for query parameter validation
        project_root: Path to the project directory to analyze
        include_optional: Whether to include optional/development dependencies
        fast_mode: Skip installation checks for faster response

    Returns:
        DependencyDetectionResponse: Information about detected, missing, and installed dependencies

    Raises:
        HTTPException:
            - 400: If project root directory doesn't exist or unknown query parameters are provided
            - 404: If project root directory is not found
            - 422: If request parameters are invalid
            - 500: If dependency detection fails
    """
    try:
        # Validate query parameters - rejects unknown parameters with 400 error
        # Uses Pydantic model approach to avoid TypeAdapter ForwardRef issues with OpenAPI schema
        validated_params = validate_query_params_for_detect(request)

        # Use validated parameters (prefer validated values over raw query params)
        project_root = validated_params.project_root
        include_optional = validated_params.include_optional
        fast_mode = validated_params.fast_mode

        # Validate project_root parameter
        validated_root = validate_project_root(project_root, allow_none=True)
        if validated_root:
            root_path = validated_root
        else:
            # Use current working directory but limit scanning depth for performance
            root_path = Path.cwd()
            # For testing environments, use a more limited scan
            if not any(
                (root_path / f).exists()
                for f in ["requirements.txt", "pyproject.toml", "package.json"]
            ):
                logger.debug("No dependency files in current directory, using lightweight scan")

        # Check if path exists after validation
        if not root_path.exists():
            raise bad_request(f"Project root directory does not exist: {root_path}")

        manager = SystemDependencyManager()

        # Check if no package manager is available and warn user
        if not manager.package_manager:
            logger.warning(f"No supported package manager detected on system: {platform.system()}")

        # Detect all dependencies
        try:
            missing_deps = manager.detect_required_dependencies(
                root_path,
                include_optional=include_optional,
                fast_mode=fast_mode,
            )
        except Exception as e:
            logger.error(f"Error during dependency detection: {e}")
            raise internal_error(f"Failed to analyze project dependencies: {str(e)}")

        # Categorize dependencies
        missing_info = []
        installed_info = []
        processed_deps = set()

        # Process detected dependencies
        for dep_name in manager.detected_dependencies:
            # Handle normalized package names
            normalized_names = [
                dep_name,
                dep_name.replace("-", "_"),
                dep_name.replace("_", "-"),
            ]

            for norm_name in normalized_names:
                if norm_name in manager.DEPENDENCY_MAP and norm_name not in processed_deps:
                    dep = manager.DEPENDENCY_MAP[norm_name]
                    processed_deps.add(norm_name)

                    try:
                        dep_info = DependencyInfo(
                            name=dep.name,
                            description=dep.description,
                            dependency_type=dep.dependency_type.value,
                            is_installed=dep not in missing_deps,
                            system_packages={
                                pm.value: packages
                                for pm, packages in dep.packages.items()
                                if packages  # Only include non-empty package lists
                            },
                            test_command=dep.test_command,
                        )

                        if dep in missing_deps:
                            missing_info.append(dep_info)
                        else:
                            installed_info.append(dep_info)
                    except Exception as e:
                        logger.warning(f"Error processing dependency {dep.name}: {e}")
                    break

        # Ensure stable ordering for consistent results
        missing_info.sort(key=lambda x: x.name)
        installed_info.sort(key=lambda x: x.name)

        return DependencyDetectionResponse(
            detected_package_manager=(
                manager.package_manager.value if manager.package_manager else None
            ),
            project_root=str(root_path.resolve()),  # Use absolute path
            total_dependencies_checked=len(processed_deps),
            missing_dependencies=missing_info,
            installed_dependencies=installed_info,
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error(f"Error detecting dependencies: {e}")
        raise internal_error(f"Failed to detect dependencies: {str(e)}")


@router.post(
    "/generate-script",
    response_model=InstallScriptResponse,
    operation_id="generate_install_script",
    summary="Generate installation script",
    description="Generate a shell script to install missing system dependencies using the detected package manager (apt, yum, brew, etc.)",
    responses={
        200: {
            "model": InstallScriptResponse,
            "description": "Successfully generated installation script",
            "content": {
                "application/json": {
                    "example": {
                        "script_content": "#!/bin/bash\n\n# Install system dependencies\nsudo apt-get update\nsudo apt-get install -y libxml2-dev libxslt1-dev\nsudo apt-get install -y libpq-dev\n",
                        "package_manager": "apt",
                        "dependencies_count": 2,
                    }
                }
            },
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - no supported package manager detected on this system or project root directory does not exist",
        },
        404: {
            "model": Error404Response,
            "description": "Project root directory not found",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error in request parameters",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error during script generation or dependency detection",
        },
    },
)
async def generate_install_script(
    request: GenerateScriptRequest | None = Body(
        None, description="Optional request body with specific dependencies to include"
    ),
    project_root: str | None = Query(
        None,
        description="Absolute path to the project root directory to analyze. If not provided, uses current working directory",
    ),
    include_optional: bool = Query(
        False,
        description="Whether to include optional dependencies in the generated installation script",
    ),
    tenant_id: str = Depends(require_tenant),
) -> InstallScriptResponse:
    """Generate installation script for missing dependencies.

    Creates a shell script that can be executed to install all missing system
    dependencies using the detected package manager (apt, yum, brew, etc.).

    Args:
        project_root: Path to the project directory to analyze
        include_optional: Whether to include optional dependencies in the script

    Returns:
        InstallScriptResponse: Generated shell script content and metadata

    Raises:
        HTTPException:
            - 400: If no supported package manager is detected
            - 404: If project root directory is not found
            - 422: If request parameters are invalid
            - 500: If script generation fails
    """
    try:
        # Validate project_root parameter
        validated_root = validate_project_root(project_root, allow_none=True)
        root_path = validated_root if validated_root else Path.cwd()

        manager = SystemDependencyManager()

        if not manager.package_manager:
            # Provide more helpful error message
            system_info = platform.system()
            available_managers = {
                "Linux": "apt, yum, dnf, pacman, apk, zypper",
                "Darwin": "brew",
                "Windows": "choco",
            }.get(system_info, "unknown")

            raise bad_request(
                f"No supported package manager detected on {system_info}. Available managers: {available_managers}"
            )

        # Get dependencies to process
        if request and request.dependencies:
            # Use specific dependencies from request
            dependencies_to_install = []
            for dep_name in request.dependencies:
                if dep_name in manager.DEPENDENCY_MAP:
                    dependencies_to_install.append(manager.DEPENDENCY_MAP[dep_name])
                else:
                    # For dependencies not in our map, create a simple dependency object
                    # but validate the package name first
                    if dep_name and re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", dep_name):
                        from services.system_dependency_manager import (
                            SystemDependency,
                        )

                        simple_dep = SystemDependency(
                            name=dep_name,
                            description=f"System package: {dep_name}",
                            dependency_type=DependencyType.BUILD,
                            packages={
                                PackageManager.APT: [dep_name],
                                PackageManager.YUM: [dep_name],
                                PackageManager.DNF: [dep_name],
                                PackageManager.BREW: [dep_name],
                                PackageManager.PACMAN: [dep_name],
                                PackageManager.APK: [dep_name],
                                PackageManager.ZYPPER: [dep_name],
                            },
                            test_command=None,
                        )
                        dependencies_to_install.append(simple_dep)
                    else:
                        logger.warning(f"Skipping invalid package name: {dep_name}")
        else:
            # Auto-detect dependencies from project
            dependencies_to_install = manager.detect_required_dependencies(
                root_path,
                include_optional=include_optional,
            )

        # Generate script with error handling
        try:
            script_content = manager.generate_install_script(dependencies_to_install)
            if not script_content:
                raise bad_request(
                    "Unable to generate installation script - no compatible dependencies found"
                )
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            raise internal_error(f"Failed to generate installation script: {str(e)}")

        return InstallScriptResponse(
            script_content=script_content,
            package_manager=manager.package_manager.value,
            dependencies_count=len(dependencies_to_install),
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error(f"Error generating install script: {e}")
        raise internal_error(f"Failed to generate install script: {str(e)}")


@router.post(
    "/generate-dockerfile",
    response_model=DockerfileSnippetResponse,
    operation_id="generate_dockerfile_snippet",
    summary="Generate Dockerfile snippet",
    description="Generate a Dockerfile snippet for installing system dependencies in a containerized environment using apt package manager",
    responses={
        200: {
            "model": DockerfileSnippetResponse,
            "description": "Successfully generated Dockerfile snippet",
            "content": {
                "application/json": {
                    "example": {
                        "snippet": "# Install system dependencies\nRUN apt-get update && apt-get install -y \\\n    libxml2-dev \\\n    libxslt1-dev \\\n    libpq-dev \\\n    && rm -rf /var/lib/apt/lists/*",
                        "dependencies_included": 2,
                    }
                }
            },
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - invalid parameters or no dependencies found",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error in request parameters",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error during snippet generation or dependency detection",
        },
    },
)
async def generate_dockerfile_snippet(
    request: GenerateDockerfileRequest | None = Body(
        None, description="Optional request body with specific dependencies to include"
    ),
    include_all: bool = Query(
        False,
        description="If true, includes all known dependencies in the snippet. If false, only includes dependencies detected from the current project",
    ),
    tenant_id: str = Depends(require_tenant),
) -> DockerfileSnippetResponse:
    """Generate Dockerfile snippet for system dependencies.

    Creates a Dockerfile snippet that can be included in a Docker build to install
    required system dependencies. Uses apt package manager for container compatibility.

    Args:
        include_all: Whether to include all known dependencies or just detected ones

    Returns:
        DockerfileSnippetResponse: Dockerile snippet content and dependency count

    Raises:
        HTTPException:
            - 400: If invalid parameters are provided
            - 422: If request parameters fail validation
            - 500: If snippet generation fails
    """
    try:
        manager = SystemDependencyManager()

        # Get dependencies to process
        if request and request.dependencies:
            # Use specific dependencies from request
            dependencies = []
            for dep_name in request.dependencies:
                if dep_name in manager.DEPENDENCY_MAP:
                    dependencies.append(manager.DEPENDENCY_MAP[dep_name])
                else:
                    # For dependencies not in our map, create a simple dependency object
                    from services.system_dependency_manager import SystemDependency

                    simple_dep = SystemDependency(
                        name=dep_name,
                        description=f"System package: {dep_name}",
                        dependency_type=DependencyType.BUILD,
                        packages={
                            PackageManager.APT: [dep_name],
                            PackageManager.YUM: [dep_name],
                            PackageManager.DNF: [dep_name],
                            PackageManager.BREW: [dep_name],
                            PackageManager.PACMAN: [dep_name],
                            PackageManager.APK: [dep_name],
                            PackageManager.ZYPPER: [dep_name],
                        },
                        test_command=None,
                    )
                    dependencies.append(simple_dep)
        elif include_all:
            # Use all known dependencies
            dependencies = list(manager.DEPENDENCY_MAP.values())
        else:
            # Detect missing dependencies from current project
            root_path = Path.cwd()
            dependencies = manager.detect_required_dependencies(root_path)

        # Generate snippet
        snippet = manager.generate_dockerfile_snippet(dependencies)

        return DockerfileSnippetResponse(
            snippet=snippet,
            dependencies_included=[dep.name for dep in dependencies],
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error(f"Error generating Dockerfile snippet: {e}")
        raise internal_error(f"Failed to generate Dockerfile snippet: {str(e)}")


@router.post(
    "/generate-ci-config",
    response_model=CIConfigResponse,
    operation_id="generate_ci_config",
    summary="Generate CI configuration",
    description="Generate CI/CD configuration for installing system dependencies on supported platforms (GitHub Actions, GitLab CI)",
    responses={
        200: {
            "model": CIConfigResponse,
            "description": "Successfully generated CI configuration",
            "content": {
                "application/json": {
                    "example": {
                        "platform": "github",
                        "configuration": "name: Install Dependencies\nrun: |\n  sudo apt-get update\n  sudo apt-get install -y libxml2-dev libxslt1-dev\n  sudo apt-get install -y libpq-dev",
                        "dependencies_included": 2,
                    }
                }
            },
        },
        400: {
            "model": Error400Response,
            "description": "Bad request - unsupported CI platform (must be 'github' or 'gitlab') or project root directory does not exist",
        },
        404: {
            "model": Error404Response,
            "description": "Project root directory not found",
        },
        422: {
            "model": Error422Response,
            "description": "Validation error in request parameters - invalid platform or project_root format",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error during CI config generation or dependency detection",
        },
    },
)
async def generate_ci_config(
    request: GenerateCIConfigRequest | None = Body(
        None, description="Optional request body with specific dependencies to include"
    ),
    platform: str = Query(
        ...,
        description="CI platform to generate configuration for",
        pattern="^(github|gitlab)$",
        json_schema_extra={"enum": ["github", "gitlab"]},
    ),
    project_root: str | None = Query(
        None,
        description="Absolute path to the project root directory to analyze. If not provided, uses current working directory",
    ),
    tenant_id: str = Depends(require_tenant),
) -> CIConfigResponse:
    """Generate CI configuration for system dependencies.

    Creates CI/CD configuration that can be used in GitHub Actions or GitLab CI
    to install required system dependencies during the build process.

    Args:
        platform: CI platform ('github' or 'gitlab')
        project_root: Path to the project directory to analyze

    Returns:
        CIConfigResponse: Generated CI configuration and metadata

    Raises:
        HTTPException:
            - 400: If unsupported CI platform or invalid parameters
            - 404: If project root directory is not found
            - 422: If request parameters fail validation
            - 500: If CI config generation fails
    """
    try:
        # Validate platform parameter
        validated_platform = validate_string_parameter(
            platform,
            parameter_name="platform",
            allow_none=False,
            allowed_values={"github", "gitlab"},
        )

        # Validate project_root parameter
        validated_root = validate_project_root(project_root, allow_none=True)
        root_path = validated_root if validated_root else Path.cwd()

        manager = SystemDependencyManager()

        # Get dependencies to process
        if request and request.dependencies:
            # Use specific dependencies from request
            dependencies_to_install = []
            for dep_name in request.dependencies:
                if dep_name in manager.DEPENDENCY_MAP:
                    dependencies_to_install.append(manager.DEPENDENCY_MAP[dep_name])
                else:
                    # For dependencies not in our map, create a simple dependency object
                    from services.system_dependency_manager import SystemDependency

                    simple_dep = SystemDependency(
                        name=dep_name,
                        description=f"System package: {dep_name}",
                        dependency_type=DependencyType.BUILD,
                        packages={
                            PackageManager.APT: [dep_name],
                            PackageManager.YUM: [dep_name],
                            PackageManager.DNF: [dep_name],
                            PackageManager.BREW: [dep_name],
                            PackageManager.PACMAN: [dep_name],
                            PackageManager.APK: [dep_name],
                            PackageManager.ZYPPER: [dep_name],
                        },
                        test_command=None,
                    )
                    dependencies_to_install.append(simple_dep)
        else:
            # Auto-detect dependencies from project
            dependencies_to_install = manager.detect_required_dependencies(root_path)

        # Generate CI config
        assert validated_platform is not None  # allow_none=False guarantees non-None
        config = manager.generate_ci_config(validated_platform, dependencies_to_install)

        return CIConfigResponse(
            platform=validated_platform,
            configuration=config,
            dependencies_included=[dep.name for dep in dependencies_to_install],
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error(f"Error generating CI config: {e}")
        raise internal_error(f"Failed to generate CI config: {str(e)}")


@router.get(
    "/list-known",
    response_model=list[DependencyInfo],
    operation_id="list_known_system_dependencies",
    summary="List known dependencies",
    description="List all known system dependencies that can be detected and managed by this service, including their installation status",
    responses={
        200: {
            "model": list[DependencyInfo],
            "description": "Successfully retrieved list of known dependencies",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "name": "lxml",
                            "description": "XML processing libraries",
                            "dependency_type": "build",
                            "is_installed": False,
                            "system_packages": {
                                "apt": ["libxml2-dev", "libxslt1-dev"],
                                "yum": ["libxml2-devel", "libxslt-devel"],
                                "brew": ["libxml2", "libxslt"],
                            },
                            "test_command": "xml2-config --version",
                        },
                        {
                            "name": "psycopg2",
                            "description": "PostgreSQL client libraries",
                            "dependency_type": "build",
                            "is_installed": True,
                            "system_packages": {
                                "apt": ["libpq-dev"],
                                "yum": ["postgresql-devel"],
                                "brew": ["postgresql"],
                            },
                            "test_command": "pg_config --version",
                        },
                    ]
                }
            },
        },
        404: {
            "model": Error404Response,
            "description": "Dependency configuration not found",
        },
        500: {
            "model": Error500Response,
            "description": "Internal server error during dependency listing or installation status checking",
        },
    },
)
async def list_known_dependencies(
    tenant_id: str = Depends(require_tenant),
) -> list[DependencyInfo]:
    """List all known system dependencies.

    Returns a comprehensive list of all system dependencies that this service
    can detect and manage, along with their current installation status.

    Returns:
        List[DependencyInfo]: List of all known dependencies with their details

    Raises:
        HTTPException:
            - 404: If dependency configuration is not found
            - 500: If dependency listing or status checking fails
    """
    try:
        manager = SystemDependencyManager()

        dependencies = []
        for dep in manager.DEPENDENCY_MAP.values():
            dep_info = DependencyInfo(
                name=dep.name,
                description=dep.description,
                dependency_type=dep.dependency_type.value,
                is_installed=manager._is_dependency_installed(dep),
                system_packages={pm.value: packages for pm, packages in dep.packages.items()},
                test_command=dep.test_command,
            )
            dependencies.append(dep_info)

        return dependencies

    except HTTPException:
        # Re-raise HTTPExceptions (like parameter validation errors) without modification
        raise
    except Exception as e:
        logger.error(f"Error listing known dependencies: {e}")
        raise internal_error(f"Failed to list known dependencies: {str(e)}")
