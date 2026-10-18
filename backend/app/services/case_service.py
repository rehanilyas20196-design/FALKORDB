
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from backend.app.db.repositories import (
    alert_repository,
    case_repository,
)

logger = logging.getLogger("graphguard.case_service")


class CaseService:
    """Manage security cases and their related alerts."""

    VALID_STATUSES = {
        "open",
        "in_progress",
        "pending",
        "resolved",
        "closed",
    }

    VALID_PRIORITIES = {
        "low",
        "medium",
        "high",
        "critical",
    }

    def __init__(self) -> None:
        self.case_repo = case_repository
        self.alert_repo = alert_repository

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _clean_text(
        value: Any,
        field_name: str,
        max_length: int = 500,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string.")

        return value.strip()[:max_length]

    @staticmethod
    def _normalize_case_id(case_id: str) -> str:
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("case_id must be a non-empty string.")

        return case_id.strip()

    @staticmethod
    def _normalize_alert_id(alert_id: str) -> str:
        if not isinstance(alert_id, str) or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string.")

        return alert_id.strip()

    @staticmethod
    def _normalize_priority(priority: str) -> str:
        normalized = str(priority).strip().lower()

        if normalized not in CaseService.VALID_PRIORITIES:
            raise ValueError(
                "Priority must be low, medium, high, or critical."
            )

        return normalized

    @staticmethod
    def _normalize_status(status: str) -> str:
        normalized = str(status).strip().lower()

        if normalized not in CaseService.VALID_STATUSES:
            raise ValueError(
                "Status must be open, in_progress, pending, "
                "resolved, or closed."
            )

        return normalized

    @staticmethod
    def _case_id_from_record(record: Any) -> str | None:
        if not isinstance(record, dict):
            return None

        value = (
            record.get("case_id")
            or record.get("id")
        )

        return str(value) if value is not None else None

    def create_case(
        self,
        title: str,
        description: str = "",
        created_by: str = "system",
        priority: str = "medium",
        assigned_to: str | None = None,
        alert_ids: list[str] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a security case and optionally link existing alerts."""
        title = self._clean_text(title, "title", 200)
        description = description.strip() if description else ""

        created_by = self._clean_text(
            created_by,
            "created_by",
            150,
        )
        priority = self._normalize_priority(priority)

        if assigned_to is not None:
            assigned_to = self._clean_text(
                assigned_to,
                "assigned_to",
                150,
            )

        case_id = f"CASE-{uuid4().hex[:12].upper()}"
        timestamp = self._now()

        clean_tags = []
        for tag in tags or []:
            if isinstance(tag, str) and tag.strip():
                clean_tags.append(tag.strip()[:80])

        case_data = {
            "case_id": case_id,
            "title": title,
            "description": description[:5000],
            "status": "open",
            "priority": priority,
            "created_by": created_by,
            "assigned_to": assigned_to,
            "alert_ids": [],
            "tags": clean_tags,
            "metadata": metadata or {},
            "created_at": timestamp,
            "updated_at": timestamp,
            "resolved_at": None,
        }

        try:
            created = self.case_repo.create_case(case_data)

            if isinstance(created, dict):
                case_data.update(created)

            for alert_id in alert_ids or []:
                self.link_alert(
                    case_id=case_id,
                    alert_id=alert_id,
                )

            result = self.get_case(case_id)

            return result or case_data

        except Exception:
            logger.exception("Failed to create case %s", case_id)
            raise

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Retrieve one case by its identifier."""
        case_id = self._normalize_case_id(case_id)

        try:
            case = self.case_repo.get_case(case_id)

            if not case:
                return None

            return case

        except Exception:
            logger.exception("Failed to retrieve case %s", case_id)
            raise

    def list_cases(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        priority: str | None = None,
        assigned_to: str | None = None,
    ) -> dict[str, Any]:
        """List cases with optional filters."""
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))

        if status is not None:
            status = self._normalize_status(status)

        if priority is not None:
            priority = self._normalize_priority(priority)

        try:
            result = self.case_repo.list_cases(
                limit=limit,
                offset=offset,
            )

            if isinstance(result, dict):
                items = result.get(
                    "items",
                    result.get("cases", []),
                )
            elif isinstance(result, list):
                items = result
            else:
                items = []

            if not isinstance(items, list):
                items = []

            if status is not None:
                items = [
                    item for item in items
                    if item.get("status") == status
                ]

            if priority is not None:
                items = [
                    item for item in items
                    if item.get("priority") == priority
                ]

            if assigned_to is not None:
                items = [
                    item for item in items
                    if item.get("assigned_to") == assigned_to
                ]

            return {
                "items": items,
                "total": len(items),
                "limit": limit,
                "offset": offset,
            }

        except Exception:
            logger.exception("Failed to list security cases")
            raise

    def update_case(
        self,
        case_id: str,
        updates: dict[str, Any],
        updated_by: str = "system",
    ) -> dict[str, Any]:
        """
        Update case fields.

        Only fields supported by the repository's update method
        can be persisted. This implementation checks for that method
        rather than assuming it exists.
        """
        case_id = self._normalize_case_id(case_id)

        if not isinstance(updates, dict) or not updates:
            raise ValueError("Provide at least one field to update.")

        allowed_fields = {
            "title",
            "description",
            "status",
            "priority",
            "assigned_to",
            "tags",
            "metadata",
        }

        unknown_fields = set(updates) - allowed_fields

        if unknown_fields:
            raise ValueError(
                f"Unsupported fields: {', '.join(sorted(unknown_fields))}"
            )

        existing = self.get_case(case_id)

        if existing is None:
            raise ValueError(f"Case '{case_id}' was not found.")

        clean_updates: dict[str, Any] = dict(updates)

        if "title" in clean_updates:
            clean_updates["title"] = self._clean_text(
                clean_updates["title"],
                "title",
                200,
            )

        if "description" in clean_updates:
            clean_updates["description"] = str(
                clean_updates["description"]
            ).strip()[:5000]

        if "status" in clean_updates:
            clean_updates["status"] = self._normalize_status(
                clean_updates["status"]
            )

            if clean_updates["status"] in {"resolved", "closed"}:
                clean_updates["resolved_at"] = self._now()
            else:
                clean_updates["resolved_at"] = None

        if "priority" in clean_updates:
            clean_updates["priority"] = self._normalize_priority(
                clean_updates["priority"]
            )

        if "assigned_to" in clean_updates:
            assignee = clean_updates["assigned_to"]

            clean_updates["assigned_to"] = (
                self._clean_text(assignee, "assigned_to", 150)
                if assignee is not None
                else None
            )

        if "tags" in clean_updates:
            tags = clean_updates["tags"]

            if not isinstance(tags, list):
                raise ValueError("tags must be a list.")

            clean_updates["tags"] = [
                tag.strip()[:80]
                for tag in tags
                if isinstance(tag, str) and tag.strip()
            ]

        clean_updates["updated_at"] = self._now()

        update_method = getattr(self.case_repo, "update_case", None)

        if not callable(update_method):
            raise NotImplementedError(
                "The case repository does not implement update_case(). "
                "Add repository support before updating persisted cases."
            )

        try:
            update_method(case_id, clean_updates)

            logger.info(
                "Case %s updated by %s",
                case_id,
                updated_by,
            )

            result = self.get_case(case_id)

            if result is None:
                raise RuntimeError(
                    "The case update completed, but the case could "
                    "not be retrieved afterward."
                )

            return result

        except Exception:
            logger.exception("Failed to update case %s", case_id)
            raise

    def link_alert(
        self,
        case_id: str,
        alert_id: str,
    ) -> dict[str, Any]:
        """Link an existing alert to an existing case."""
        case_id = self._normalize_case_id(case_id)
        alert_id = self._normalize_alert_id(alert_id)

        case = self.get_case(case_id)

        if case is None:
            raise ValueError(f"Case '{case_id}' was not found.")

        alert = self.alert_repo.get_alert(alert_id)

        if alert is None:
            raise ValueError(f"Alert '{alert_id}' was not found.")

        try:
            self.case_repo.link_alert_to_case(case_id, alert_id)

            logger.info(
                "Linked alert %s to case %s",
                alert_id,
                case_id,
            )

            return {
                "success": True,
                "case_id": case_id,
                "alert_id": alert_id,
                "message": "Alert linked to case.",
            }

        except Exception:
            logger.exception(
                "Failed to link alert %s to case %s",
                alert_id,
                case_id,
            )
            raise

    def get_case_alerts(
        self,
        case_id: str,
    ) -> dict[str, Any]:
        """Retrieve the case and resolve its linked alerts."""
        case_id = self._normalize_case_id(case_id)

        case = self.get_case(case_id)

        if case is None:
            raise ValueError(f"Case '{case_id}' was not found.")

        alert_ids = case.get("alert_ids", [])
        alerts = []

        for alert_id in alert_ids:
            alert = self.alert_repo.get_alert(str(alert_id))

            if alert is not None:
                alerts.append(alert)

        return {
            "case_id": case_id,
            "alerts": alerts,
            "total": len(alerts),
        }

    def assign_case(
        self,
        case_id: str,
        assigned_to: str,
        updated_by: str = "system",
    ) -> dict[str, Any]:
        """Assign a case to an analyst."""
        return self.update_case(
            case_id=case_id,
            updates={"assigned_to": assigned_to},
            updated_by=updated_by,
        )

    def resolve_case(
        self,
        case_id: str,
        resolution_note: str = "",
        updated_by: str = "system",
    ) -> dict[str, Any]:
        """Mark a case as resolved and retain its resolution note."""
        updates: dict[str, Any] = {
            "status": "resolved",
            "metadata": {
                "resolution_note": resolution_note[:5000],
                "resolved_by": updated_by,
                "resolved_at": self._now(),
            },
        }

        return self.update_case(
            case_id=case_id,
            updates=updates,
            updated_by=updated_by,
        )

    def get_statistics(self) -> dict[str, Any]:
        """Calculate case statistics from the cases returned by the repo."""
        result = self.list_cases(limit=200, offset=0)
        cases = result["items"]

        stats = {
            "total": len(cases),
            "open": 0,
            "in_progress": 0,
            "pending": 0,
            "resolved": 0,
            "closed": 0,
            "low_priority": 0,
            "medium_priority": 0,
            "high_priority": 0,
            "critical_priority": 0,
        }

        for case in cases:
            status = case.get("status")
            priority = case.get("priority")

            if status in stats:
                stats[status] += 1

            if priority in self.VALID_PRIORITIES:
                stats[f"{priority}_priority"] += 1

        return stats


# Shared service instance
case_service = CaseService()
