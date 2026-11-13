"""Container models for the security microservice.

Minimal container models needed by the security service.
These mirror the monolith's container_models but only include what's needed here.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class ContainerStatus(StrEnum):
    """Container status enumeration"""

    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    REMOVING = "removing"


class ContainerInfo(BaseModel):
    """Information model for container instances."""

    container_name: str
    api_endpoint: str = Field(
        ..., description="Deprecated alias for the public/gateway-facing endpoint"
    )
    internal_endpoint: str = Field(
        default="", description="Direct runtime-reachable endpoint for internal probes"
    )
    public_endpoint: str = Field(default="", description="Client-facing or gateway-facing endpoint")
    code_graph_id: str = ""
    codebase_path: str
    repo_url: str
    branch: str
    status: ContainerStatus
    description: str | None = None
    tenant_id: str | None = None
    pr_number: int | None = None
    provision_type: str | None = None

    @model_validator(mode="after")
    def sync_endpoint_fields(self):
        if not self.public_endpoint:
            self.public_endpoint = self.api_endpoint
        if not self.api_endpoint:
            self.api_endpoint = self.public_endpoint or self.internal_endpoint
        return self
