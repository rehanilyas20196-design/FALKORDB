"""
GraphGuard AI - Audit API

Read-only endpoints that expose the existing audit service
(backend/app/services/audit_service.py), which records events as JSON
Lines in logs/audit.jsonl.

These endpoints are read-only. They never write or delete audit records.
"""

import logging

from fastapi import APIRouter, Query

from backend.app.services.audit_service import audit_service

logger = logging.getLogger("graphguard.audit")

router = APIRouter(prefix="/audit", tags=["Audit"])


# --------------------------------------------------
# AUDIT HEALTH
# --------------------------------------------------

@router.get("/health")
async def audit_health() -> dict:
    """Report whether the audit log is available and writable."""
    return audit_service.health_check()


# --------------------------------------------------
# LIST AUDIT EVENTS
# --------------------------------------------------

@router.get("")
async def list_audit_events(
    limit: int = Query(default=100, ge=1, le=1000),
    actor: str | None = Query(default=None, max_length=200),
    action: str | None = Query(default=None, max_length=200),
    status: str | None = Query(default=None, max_length=100),
) -> dict:
    """
    List recent audit events, newest first.

    All filters are optional. Results are read directly from the audit
    log file written by the audit service.
    """
    events = audit_service.get_recent_events(
        limit=limit,
        actor=actor,
        action=action,
        status=status,
    )

    return {
        "events": events,
        "count": len(events),
        "limit": limit,
        "filters": {
            "actor": actor,
            "action": action,
            "status": status,
        },
    }
