
"""
GraphGuard AI - Security Event Schemas.

Defines validated request and response models for security events.
Compatible with Pydantic v2 and FastAPI.
"""

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


EventSeverity = Literal["low", "medium", "high", "critical"]

EventCategory = Literal[
    "authentication",
    "network",
    "endpoint",
    "privilege",
    "file",
    "application",
    "cloud",
    "other",
]


class SecurityEventBase(BaseModel):
    """Common fields for a security event."""

    event_type: str = Field(
        ...,
        min_length=2,
        max_length=150,
        description="Type of security event, such as login_failure.",
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
        description="Human-readable explanation of the event.",
    )

    category: EventCategory = Field(
        default="other",
        description="Broad category of the security event.",
    )

    severity: EventSeverity = Field(
        default="medium",
        description="Severity assigned to the event.",
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time at which the event occurred.",
    )

    username: str | None = Field(
        default=None,
        max_length=255,
        description="Account associated with the event.",
    )

    source_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Originating IPv4 or IPv6 address.",
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Destination IPv4 or IPv6 address.",
    )

    source_host: str | None = Field(
        default=None,
        max_length=255,
        description="Originating hostname.",
    )

    destination_host: str | None = Field(
        default=None,
        max_length=255,
        description="Destination hostname.",
    )

    action: str | None = Field(
        default=None,
        max_length=255,
        description="Action associated with the event.",
    )

    outcome: str | None = Field(
        default=None,
        max_length=100,
        description="Outcome such as success, failure, or denied.",
    )

    protocol: str | None = Field(
        default=None,
        max_length=50,
        description="Network or application protocol, if applicable.",
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Relevant network port, if applicable.",
    )

    process_name: str | None = Field(
        default=None,
        max_length=255,
        description="Process associated with the event.",
    )

    command: str | None = Field(
        default=None,
        max_length=5000,
        description="Command associated with the event, if available.",
    )

    source: str | None = Field(
        default=None,
        max_length=255,
        description="System or integration that produced the event.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional event-specific information.",
    )

    @field_validator(
        "event_type",
        "description",
        "username",
        "source_host",
        "destination_host",
        "action",
        "outcome",
        "protocol",
        "process_name",
        "command",
        "source",
        mode="before",
    )
    @classmethod
    def strip_text_fields(cls, value: Any) -> Any:
        """Trim surrounding whitespace from text values."""
        if isinstance(value, str):
            value = value.strip()
        return value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        """Validate IP addresses while allowing missing values."""
        if value is None or not value.strip():
            return None

        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Must be a valid IPv4 or IPv6 address") from exc

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Normalize timestamps to UTC."""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)


class SecurityEventCreate(SecurityEventBase):
    """Request body for ingesting a security event."""

    event_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Optional event identifier; generated when omitted.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()
            if not value:
                raise ValueError("event_id cannot be empty")
        return value


class SecurityEventResponse(SecurityEventBase):
    """Security event returned by the API."""

    event_id: str
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time at which GraphGuard AI received the event.",
    )

    model_config = ConfigDict(from_attributes=True)


class SecurityEventBatchCreate(BaseModel):
    """Request for ingesting multiple events in one operation."""

    events: list[SecurityEventCreate] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Batch of security events to ingest.",
    )

    model_config = ConfigDict(extra="forbid")


class SecurityEventBatchResponse(BaseModel):
    """Result of a batch event-ingestion request."""

    total_received: int = Field(default=0, ge=0)
    total_accepted: int = Field(default=0, ge=0)
    total_rejected: int = Field(default=0, ge=0)
    events: list[SecurityEventResponse] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)


class SecurityEventFilter(BaseModel):
    """Filters for searching security events."""

    event_type: str | None = Field(default=None, max_length=150)
    category: EventCategory | None = None
    severity: EventSeverity | None = None
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)

    start_time: datetime | None = None
    end_time: datetime | None = None

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)

    model_config = ConfigDict(extra="forbid")

    @field_validator("start_time", "end_time")
    @classmethod
    def normalize_filter_timestamp(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_filter_ip(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None or not value.strip():
            return None

        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("Must be a valid IPv4 or IPv6 address") from exc


def create_event_id() -> str:
    """Generate a unique security event identifier."""
    return f"EVT-{uuid4().hex[:12].upper()}"
