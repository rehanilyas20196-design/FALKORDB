
"""
GraphGuard AI - Alert Schemas.

Defines validated request and response models for security alerts.
Compatible with Pydantic v2 and FastAPI.
"""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


AlertSeverity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal[
    "open",
    "investigating",
    "resolved",
    "dismissed",
]


class AlertBase(BaseModel):
    """Fields shared by alert creation and response models."""

    title: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description="Short title describing the security alert.",
    )
    description: str = Field(
        ...,
        min_length=3,
        max_length=5000,
        description="Explanation of the suspicious activity.",
    )
    severity: AlertSeverity = Field(
        default="medium",
        description="Alert severity.",
    )
    risk_score: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Risk score from 0 to 100.",
    )

    rule_id: str | None = Field(
        default=None,
        max_length=100,
        description="Identifier of the detection rule that generated the alert.",
    )
    rule_name: str | None = Field(
        default=None,
        max_length=200,
        description="Name of the detection rule.",
    )

    event_id: str | None = Field(
        default=None,
        max_length=200,
        description="Identifier of the related security event.",
    )
    username: str | None = Field(
        default=None,
        max_length=255,
        description="Account associated with the alert, if known.",
    )
    source_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Source IPv4 or IPv6 address, if known.",
    )
    destination_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Destination IPv4 or IPv6 address, if known.",
    )
    source_host: str | None = Field(
        default=None,
        max_length=255,
        description="Source hostname, if known.",
    )
    destination_host: str | None = Field(
        default=None,
        max_length=255,
        description="Destination hostname, if known.",
    )

    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting evidence for the alert.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Labels for grouping and filtering alerts.",
    )

    @field_validator(
        "title",
        "description",
        "rule_id",
        "rule_name",
        "event_id",
        "username",
        "source_ip",
        "destination_ip",
        "source_host",
        "destination_host",
        mode="before",
    )
    @classmethod
    def strip_text_fields(cls, value: Any) -> Any:
        """Remove surrounding whitespace from text fields."""
        if isinstance(value, str):
            value = value.strip()

        return value

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        """Trim tags and remove empty or duplicate values."""
        normalized: list[str] = []
        seen: set[str] = set()

        for tag in value:
            cleaned = tag.strip()

            if not cleaned:
                continue

            key = cleaned.casefold()

            if key not in seen:
                normalized.append(cleaned)
                seen.add(key)

        return normalized


class AlertCreate(AlertBase):
    """Request schema for creating a new alert."""

    alert_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Optional alert identifier; generated when omitted.",
    )
    status: AlertStatus = Field(
        default="open",
        description="Initial alert status.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("alert_id")
    @classmethod
    def validate_alert_id(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()

            if not value:
                raise ValueError("alert_id cannot be empty")

        return value


class AlertUpdate(BaseModel):
    """Request schema for updating an existing alert."""

    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(
        default=None,
        min_length=3,
        max_length=5000,
    )
    severity: AlertSeverity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    status: AlertStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=255)
    resolution_note: str | None = Field(default=None, max_length=5000)
    tags: list[str] | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator(
        "title",
        "description",
        "assigned_to",
        "resolution_note",
        mode="before",
    )
    @classmethod
    def strip_optional_text(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()

        return value

    @field_validator("tags")
    @classmethod
    def normalize_optional_tags(
        cls,
        value: list[str] | None,
    ) -> list[str] | None:
        if value is None:
            return None

        normalized: list[str] = []
        seen: set[str] = set()

        for tag in value:
            cleaned = tag.strip()

            if cleaned and cleaned.casefold() not in seen:
                normalized.append(cleaned)
                seen.add(cleaned.casefold())

        return normalized


class AlertResponse(AlertBase):
    """Alert returned by the API."""

    alert_id: str
    status: AlertStatus = "open"

    assigned_to: str | None = None
    resolution_note: str | None = None

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime | None = None
    resolved_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    """Paginated collection of alerts."""

    items: list[AlertResponse] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)
    has_next: bool = False


class AlertFilter(BaseModel):
    """Validated filters for listing alerts."""

    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    rule_id: str | None = Field(default=None, max_length=100)

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)


def create_alert_id() -> str:
    """Generate a unique alert identifier."""
    return f"ALT-{uuid4().hex[:12].upper()}"
