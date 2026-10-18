
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger("graphguard.events")

router = APIRouter(
    prefix="/events",
    tags=["Events"],
)


# --------------------------------------------------
# REQUEST AND RESPONSE SCHEMAS
# --------------------------------------------------

class SecurityEventCreate(BaseModel):
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type of security event",
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Host, user, or system that generated the event",
    )
    severity: str = Field(
        default="medium",
        description="Event severity: low, medium, high, or critical",
    )
    description: str = Field(
        default="",
        max_length=5000,
    )
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(BaseModel):
    event_id: str
    event_type: str
    source: str
    severity: str
    description: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------
# TEMPORARY EVENT STORAGE
# --------------------------------------------------
# This is in-memory storage for initial development.
# Events disappear when the backend restarts.
# Replace this with FalkorDB persistence before production.

_events: dict[str, dict[str, Any]] = {}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


# --------------------------------------------------
# CREATE EVENT
# --------------------------------------------------

@router.post(
    "/",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_event(event: SecurityEventCreate):
    severity = event.severity.strip().lower()

    if severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Invalid severity. Choose low, medium, high, or critical."
            ),
        )

    event_id = str(uuid.uuid4())

    event_data = {
        "event_id": event_id,
        "event_type": event.event_type.strip(),
        "source": event.source.strip(),
        "severity": severity,
        "description": event.description,
        "user": event.user,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "timestamp": event.timestamp or datetime.now(timezone.utc),
        "metadata": event.metadata,
    }

    _events[event_id] = event_data

    logger.info(
        "Security event created: id=%s type=%s severity=%s",
        event_id,
        event_data["event_type"],
        severity,
    )

    return event_data


# --------------------------------------------------
# LIST EVENTS
# --------------------------------------------------

@router.get("/", response_model=list[SecurityEventResponse])
async def list_events(
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    results = list(_events.values())

    if severity:
        normalized_severity = severity.strip().lower()

        if normalized_severity not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid severity filter.",
            )

        results = [
            item
            for item in results
            if item["severity"] == normalized_severity
        ]

    if event_type:
        results = [
            item
            for item in results
            if item["event_type"].lower() == event_type.strip().lower()
        ]

    results.sort(
        key=lambda item: item["timestamp"],
        reverse=True,
    )

    return results[:limit]


# --------------------------------------------------
# GET EVENT BY ID
# --------------------------------------------------

@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event(event_id: str):
    event = _events.get(event_id)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' was not found.",
        )

    return event


# --------------------------------------------------
# DELETE EVENT
# --------------------------------------------------

@router.delete("/{event_id}")
async def delete_event(event_id: str):
    event = _events.pop(event_id, None)

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' was not found.",
        )

    logger.info("Security event deleted: id=%s", event_id)

    return {
        "status": "success",
        "message": "Event deleted successfully.",
        "event_id": event_id,
    }


# --------------------------------------------------
# EVENT API HEALTH
# --------------------------------------------------

@router.get("/health/status")
async def event_api_health():
    return {
        "status": "healthy",
        "service": "GraphGuard Events API",
        "events_in_memory": len(_events),
    }
