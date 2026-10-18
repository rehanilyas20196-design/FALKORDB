
"""
GraphGuard AI - Common API Schemas.

Reusable Pydantic models for API responses, pagination,
health checks, and standardized error handling.
"""

from datetime import datetime, timezone
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


DataT = TypeVar("DataT")


class APIResponse(BaseModel, Generic[DataT]):
    """Standard successful API response."""

    success: bool = True
    message: str = "Request completed successfully."
    data: DataT | None = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(
        from_attributes=True,
    )


class PaginationParams(BaseModel):
    """Validated pagination parameters."""

    page: int = Field(
        default=1,
        ge=1,
        description="Page number, starting from 1.",
    )
    page_size: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Number of records per page.",
    )

    @property
    def offset(self) -> int:
        """Calculate the database offset for this page."""
        return (self.page - 1) * self.page_size


class PaginationMetadata(BaseModel):
    """Pagination details for a list response."""

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)
    total_items: int = Field(default=0, ge=0)
    total_pages: int = Field(default=0, ge=0)
    has_next: bool = False
    has_previous: bool = False


class PaginatedResponse(BaseModel, Generic[DataT]):
    """Standard response for paginated records."""

    success: bool = True
    message: str = "Records retrieved successfully."
    items: list[DataT] = Field(default_factory=list)
    pagination: PaginationMetadata
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(
        from_attributes=True,
    )


class ErrorDetail(BaseModel):
    """Details about an individual API error."""

    field: str | None = None
    message: str
    code: str | None = None


class ErrorResponse(BaseModel):
    """Standard error response."""

    success: bool = False
    error: str = "Request failed."
    message: str = "An error occurred while processing the request."
    details: list[ErrorDetail] = Field(default_factory=list)
    request_id: str | None = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


HealthStatus = Literal["healthy", "degraded", "unhealthy"]


class ComponentHealth(BaseModel):
    """Health status of an individual component."""

    name: str
    status: HealthStatus
    message: str | None = None
    response_time_ms: float | None = Field(default=None, ge=0)


class HealthResponse(BaseModel):
    """Overall API health-check response."""

    status: HealthStatus = "healthy"
    service: str = "GraphGuard AI"
    version: str = "1.0.0"
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    uptime_seconds: float | None = Field(default=None, ge=0)
    components: list[ComponentHealth] = Field(default_factory=list)


class MessageResponse(BaseModel):
    """Simple response for successful operations."""

    success: bool = True
    message: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class IDResponse(BaseModel):
    """Response containing a resource identifier."""

    success: bool = True
    id: str
    message: str = "Resource processed successfully."


class BulkOperationResult(BaseModel):
    """Result of processing multiple records."""

    total: int = Field(default=0, ge=0)
    succeeded: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    errors: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(
        extra="forbid",
    )
