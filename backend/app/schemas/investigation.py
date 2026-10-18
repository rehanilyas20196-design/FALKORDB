
"""
GraphGuard AI - Investigation Schemas.

Pydantic models for investigating security alerts, recording findings,
assessing risk, and recommending response actions.

These schemas describe investigation data. They do not execute
containment actions or independently verify malicious activity.
"""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


InvestigationStatus = Literal[
    "pending",
    "in_progress",
    "completed",
    "failed",
]

InvestigationSeverity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]

FindingConfidence = Literal[
    "low",
    "medium",
    "high",
]

RecommendationPriority = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


class InvestigationFinding(BaseModel):
    """A finding produced during an investigation."""

    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3, max_length=5000)

    severity: InvestigationSeverity = "medium"
    confidence: FindingConfidence = "medium"

    evidence: dict[str, Any] = Field(default_factory=dict)
    related_event_ids: list[str] = Field(default_factory=list)
    related_node_ids: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    @field_validator("title", "description")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class InvestigationRecommendation(BaseModel):
    """A suggested action for an analyst to review."""

    action: str = Field(..., min_length=3, max_length=200)
    rationale: str = Field(..., min_length=3, max_length=3000)

    priority: RecommendationPriority = "medium"
    requires_approval: bool = True
    automated: bool = False

    related_finding: str | None = Field(default=None, max_length=200)

    model_config = ConfigDict(extra="forbid")

    @field_validator("action", "rationale", "related_finding")
    @classmethod
    def strip_text(cls, value: str | None) -> str | None:
        if value is not None:
            return value.strip()
        return value


class InvestigationCreate(BaseModel):
    """Request to start an investigation."""

    alert_id: str = Field(..., min_length=1, max_length=200)
    assigned_to: str | None = Field(default=None, max_length=255)

    objectives: list[str] = Field(
        default_factory=list,
        max_length=30,
        description="Questions or objectives for the investigation.",
    )

    include_graph_analysis: bool = True
    include_related_events: bool = True
    include_ai_analysis: bool = True

    model_config = ConfigDict(extra="forbid")

    @field_validator("alert_id", "assigned_to")
    @classmethod
    def strip_optional_text(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()
        return value

    @field_validator("objectives")
    @classmethod
    def normalize_objectives(cls, value: list[str]) -> list[str]:
        cleaned = []

        for objective in value:
            objective = objective.strip()
            if objective:
                cleaned.append(objective)

        return cleaned


class InvestigationUpdate(BaseModel):
    """Request to update investigation progress or findings."""

    status: InvestigationStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=255)
    summary: str | None = Field(default=None, max_length=10000)

    findings: list[InvestigationFinding] | None = None
    recommendations: list[InvestigationRecommendation] | None = None

    risk_score: int | None = Field(default=None, ge=0, le=100)
    conclusion: str | None = Field(default=None, max_length=10000)

    model_config = ConfigDict(extra="forbid")

    @field_validator("assigned_to", "summary", "conclusion")
    @classmethod
    def strip_text(cls, value: str | None) -> str | None:
        if value is not None:
            return value.strip()
        return value


class InvestigationResponse(BaseModel):
    """Investigation record returned by the API."""

    investigation_id: str = Field(
        default_factory=lambda: f"INV-{uuid4().hex[:12].upper()}"
    )
    alert_id: str

    status: InvestigationStatus = "pending"
    assigned_to: str | None = None

    summary: str | None = None
    findings: list[InvestigationFinding] = Field(default_factory=list)
    recommendations: list[InvestigationRecommendation] = Field(
        default_factory=list
    )

    risk_score: int = Field(default=0, ge=0, le=100)
    conclusion: str | None = None

    related_event_ids: list[str] = Field(default_factory=list)
    related_node_ids: list[str] = Field(default_factory=list)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class InvestigationListResponse(BaseModel):
    """Paginated list of investigations."""

    items: list[InvestigationResponse] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=200)
    has_next: bool = False


class InvestigationRequest(BaseModel):
    """Request to analyze an alert without creating a full record."""

    alert_id: str | None = Field(default=None, max_length=200)
    alert: dict[str, Any] | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    @field_validator("alert_id")
    @classmethod
    def strip_alert_id(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()
        return value


class InvestigationAnalysisResponse(BaseModel):
    """Analysis result returned by an investigation agent."""

    success: bool = True
    alert_id: str | None = None

    summary: str
    severity: InvestigationSeverity = "medium"
    risk_score: int = Field(default=0, ge=0, le=100)

    findings: list[InvestigationFinding] = Field(default_factory=list)
    recommendations: list[InvestigationRecommendation] = Field(
        default_factory=list
    )

    related_event_ids: list[str] = Field(default_factory=list)
    related_node_ids: list[str] = Field(default_factory=list)

    analysis_source: Literal[
        "rules",
        "ai",
        "hybrid",
        "unknown",
    ] = "unknown"

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(from_attributes=True)
