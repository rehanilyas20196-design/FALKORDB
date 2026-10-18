
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

logger = logging.getLogger("graphguard.audit")


class AuditService:
    """
    Records application audit events.

    Events are written as JSON Lines to a local audit log.
    This implementation is suitable for development and demos.
    For production, use durable centralized storage with access
    controls, retention policies, and tamper protection.
    """

    def __init__(self, log_path: str | None = None) -> None:
        configured_path = log_path or os.getenv(
            "AUDIT_LOG_PATH",
            "logs/audit.jsonl",
        )

        self.log_path = Path(configured_path)
        self._lock = RLock()

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.exception("Could not create the audit log directory.")
            raise

    @staticmethod
    def _utc_now() -> str:
        """Return the current UTC time in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_value(value: Any) -> Any:
        """Convert values into JSON-safe data."""
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            if isinstance(value, dict):
                return {
                    str(key): AuditService._safe_value(item)
                    for key, item in value.items()
                }

            if isinstance(value, (list, tuple, set)):
                return [
                    AuditService._safe_value(item)
                    for item in value
                ]

            return str(value)

    @staticmethod
    def _clean_text(
        value: Any,
        default: str = "unknown",
        max_length: int = 500,
    ) -> str:
        """Normalize text fields before storing them."""
        if value is None:
            return default

        text = str(value).strip()

        if not text:
            return default

        return text[:max_length]

    def record_event(
        self,
        action: str,
        actor: str = "system",
        resource_type: str = "application",
        resource_id: str | None = None,
        status: str = "success",
        details: dict[str, Any] | None = None,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Record one audit event.

        Never pass passwords, API keys, access tokens, or other secrets
        in details. Only include information appropriate for audit logs.
        """
        event = {
            "audit_id": str(uuid4()),
            "timestamp": self._utc_now(),
            "action": self._clean_text(action),
            "actor": self._clean_text(actor),
            "resource_type": self._clean_text(resource_type),
            "resource_id": (
                self._clean_text(resource_id)
                if resource_id is not None
                else None
            ),
            "status": self._clean_text(status, max_length=100),
            "source_ip": (
                self._clean_text(source_ip, max_length=100)
                if source_ip is not None
                else None
            ),
            "request_id": (
                self._clean_text(request_id, max_length=150)
                if request_id is not None
                else None
            ),
            "details": self._safe_value(details or {}),
        }

        line = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        try:
            with self._lock:
                with self.log_path.open(
                    "a",
                    encoding="utf-8",
                ) as audit_file:
                    audit_file.write(line + "\n")
                    audit_file.flush()

            logger.info(
                "Audit event recorded: action=%s actor=%s status=%s",
                event["action"],
                event["actor"],
                event["status"],
            )

        except OSError:
            logger.exception(
                "Failed to write audit event: action=%s",
                event["action"],
            )
            raise

        return event

    def log_authentication(
        self,
        actor: str,
        success: bool,
        source_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record a successful or failed authentication attempt."""
        return self.record_event(
            action="authentication",
            actor=actor,
            resource_type="session",
            status="success" if success else "failure",
            source_ip=source_ip,
            details=details,
        )

    def log_alert_action(
        self,
        actor: str,
        alert_id: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an action performed on a security alert."""
        return self.record_event(
            action=action,
            actor=actor,
            resource_type="alert",
            resource_id=alert_id,
            details=details,
        )

    def log_investigation_action(
        self,
        actor: str,
        investigation_id: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an action performed on an investigation."""
        return self.record_event(
            action=action,
            actor=actor,
            resource_type="investigation",
            resource_id=investigation_id,
            details=details,
        )

    def log_admin_action(
        self,
        actor: str,
        action: str,
        resource_type: str = "configuration",
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an administrative action."""
        return self.record_event(
            action=action,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )

    def get_recent_events(
        self,
        limit: int = 100,
        actor: str | None = None,
        action: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Read recent audit events, newest first.

        This is a local-file implementation. It reads the file on each
        call and is intended for small development/demo audit logs.
        """
        safe_limit = max(1, min(int(limit), 1000))
        events: list[dict[str, Any]] = []

        with self._lock:
            if not self.log_path.exists():
                return []

            try:
                with self.log_path.open(
                    "r",
                    encoding="utf-8",
                ) as audit_file:
                    for line in audit_file:
                        line = line.strip()

                        if not line:
                            continue

                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            logger.warning(
                                "Skipping malformed audit log line."
                            )
                            continue

                        if actor and item.get("actor") != actor:
                            continue

                        if action and item.get("action") != action:
                            continue

                        if status and item.get("status") != status:
                            continue

                        events.append(item)

            except OSError:
                logger.exception("Could not read the audit log.")
                raise

        events.sort(
            key=lambda item: item.get("timestamp", ""),
            reverse=True,
        )

        return events[:safe_limit]

    def get_event(self, audit_id: str) -> dict[str, Any] | None:
        """Find one audit event by its ID."""
        for event in self.get_recent_events(limit=1000):
            if event.get("audit_id") == audit_id:
                return event

        return None

    def health_check(self) -> dict[str, Any]:
        """Report whether the audit log directory is writable."""
        try:
            self.log_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            writable = (
                self.log_path.exists()
                and os.access(self.log_path, os.W_OK)
            ) or os.access(self.log_path.parent, os.W_OK)

            return {
                "service": "audit",
                "status": "healthy" if writable else "degraded",
                "log_path": str(self.log_path),
                "writable": writable,
            }

        except OSError as exc:
            return {
                "service": "audit",
                "status": "unhealthy",
                "log_path": str(self.log_path),
                "writable": False,
                "error": str(exc),
            }


# Shared service instance for the application.
audit_service = AuditService()