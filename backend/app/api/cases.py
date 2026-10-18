
"""
GraphGuard AI - Cases API

Provides endpoints for creating, listing, viewing, and updating
security investigation cases.

NOTE:
This initial version uses in-memory storage for development.
Cases will be lost when the backend restarts.
Connect this router to case_service.py and persistent storage
before using it for real incidents.
"""

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field


router = APIRouter(prefix="/cases", tags=["Cases"])


CaseStatus = Literal[
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
]

CaseSeverity = Literal[
    "critical",
    "high",
    "medium",
    "low",
]


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: CaseSeverity = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    assigned_to: str | None = Field(default=None, max_length=200)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    alert_ids: list[str] | None = Field(default=None, max_length=100)
    assigned_to: str | None = Field(default=None, max_length=200)
    investigation_notes: str | None = Field(default=None, max_length=10000)


class CaseResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: CaseSeverity
    status: CaseStatus
    alert_ids: list[str]
    assigned_to: str | None
    investigation_notes: str
    created_at: str
    updated_at: str


# Temporary development storage. This is not persistent.
_cases: dict[str, dict] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/health")
def cases_health() -> dict:
    """Check that the Cases API is available."""
    return {
        "success": True,
        "service": "GraphGuard AI Cases API",
        "storage": "in_memory_development_only",
        "case_count": len(_cases),
    }


@router.post("", response_model=CaseResponse, status_code=201)
def create_case(request: CaseCreate) -> dict:
    """Create a new security investigation case."""

    now = _now()
    case_id = str(uuid4())

    case = {
        "id": case_id,
        "title": request.title.strip(),
        "description": request.description.strip(),
        "severity": request.severity,
        "status": "open",
        "alert_ids": request.alert_ids,
        "assigned_to": request.assigned_to,
        "investigation_notes": "",
        "created_at": now,
        "updated_at": now,
    }

    _cases[case_id] = case
    return case


@router.get("", response_model=list[CaseResponse])
def list_cases(
    status: CaseStatus | None = None,
    severity: CaseSeverity | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict]:
    """List cases, optionally filtered by status or severity."""

    results = list(_cases.values())

    if status is not None:
        results = [case for case in results if case["status"] == status]

    if severity is not None:
        results = [
            case for case in results
            if case["severity"] == severity
        ]

    results.sort(key=lambda case: case["created_at"], reverse=True)
    return results[:limit]


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str) -> dict:
    """Retrieve one case by its ID."""

    case = _cases.get(case_id)

    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    return case


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, request: CaseUpdate) -> dict:
    """Update case details, status, assignment, or investigation notes."""

    case = _cases.get(case_id)

    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    changes = request.model_dump(exclude_unset=True)

    for field, value in changes.items():
        if field == "title" and value is not None:
            value = value.strip()
            if not value:
                raise HTTPException(
                    status_code=422,
                    detail="Case title cannot be empty",
                )

        if field == "description" and value is not None:
            value = value.strip()

        if field == "investigation_notes" and value is not None:
            value = value.strip()

        case[field] = value

    case["updated_at"] = _now()
    return case
