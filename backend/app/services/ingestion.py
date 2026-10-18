
import logging
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from uuid import uuid4

from backend.app.db.repositories import event_repository

logger = logging.getLogger("graphguard.ingestion")


class IngestionService:
    """
    Ingest, validate, normalize, and optionally persist security events.

    Supports single-event ingestion and batch ingestion.
    Database persistence uses the existing event repository.
    """

    ALLOWED_SEVERITIES = {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }

    ALLOWED_CATEGORIES = {
        "authentication",
        "network",
        "endpoint",
        "privilege",
        "file",
        "application",
        "cloud",
        "other",
    }

    def __init__(self, repository: Any = None) -> None:
        self.repository = repository or event_repository

    # ---------------------------------------------------------
    # Basic helpers
    # ---------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _text(
        value: Any,
        field_name: str,
        max_length: int = 1000,
        required: bool = False,
    ) -> str | None:
        if value is None:
            if required:
                raise ValueError(f"{field_name} is required.")
            return None

        if not isinstance(value, (str, int, float)):
            raise ValueError(f"{field_name} must be text.")

        text = str(value).strip()

        if required and not text:
            raise ValueError(f"{field_name} cannot be empty.")

        if len(text) > max_length:
            raise ValueError(
                f"{field_name} exceeds {max_length} characters."
            )

        return text or None

    @staticmethod
    def _normalize_timestamp(value: Any) -> str:
        """Parse a timestamp and normalize it to UTC."""
        if value is None or value == "":
            return datetime.now(timezone.utc).isoformat()

        if isinstance(value, (int, float)):
            try:
                parsed = datetime.fromtimestamp(
                    value,
                    tz=timezone.utc,
                )
            except (ValueError, OverflowError, OSError) as exc:
                raise ValueError("Invalid Unix timestamp.") from exc

            return parsed.isoformat()

        if not isinstance(value, str):
            raise ValueError(
                "timestamp must be an ISO timestamp or Unix timestamp."
            )

        try:
            parsed = datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                "timestamp must be a valid ISO 8601 timestamp."
            ) from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _normalize_ip(
        value: Any,
        field_name: str,
    ) -> str | None:
        if value is None or value == "":
            return None

        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be an IP address.")

        value = value.strip()

        try:
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError(
                f"{field_name} is not a valid IP address."
            ) from exc

    @staticmethod
    def _safe_metadata(value: Any) -> dict[str, Any]:
        if value is None:
            return {}

        if not isinstance(value, dict):
            raise ValueError("metadata must be an object.")

        # Confirm that metadata can be represented as JSON.
        import json

        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "metadata must contain JSON-serializable values."
            ) from exc

        return value

    # ---------------------------------------------------------
    # Validation and normalization
    # ---------------------------------------------------------

    def normalize_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Validate and normalize an incoming security event.

        Unknown fields are retained in metadata so useful source
        information is not silently discarded.
        """
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        data = dict(event)

        event_type = self._text(
            data.get("event_type") or data.get("type"),
            "event_type",
            max_length=150,
            required=True,
        )

        severity = str(
            data.get("severity", "medium")
        ).strip().lower()

        if severity not in self.ALLOWED_SEVERITIES:
            raise ValueError(
                "severity must be info, low, medium, high, or critical."
            )

        category = str(
            data.get("category", "other")
        ).strip().lower()

        if category not in self.ALLOWED_CATEGORIES:
            category = "other"

        event_id = self._text(
            data.get("event_id"),
            "event_id",
            max_length=150,
        ) or f"EVT-{uuid4().hex[:12].upper()}"

        known_fields = {
            "event_id",
            "event_type",
            "type",
            "description",
            "category",
            "severity",
            "timestamp",
            "received_at",
            "username",
            "source_ip",
            "destination_ip",
            "source_host",
            "destination_host",
            "action",
            "outcome",
            "protocol",
            "port",
            "process_name",
            "command",
            "source",
            "metadata",
        }

        extra_fields = {
            key: value
            for key, value in data.items()
            if key not in known_fields
        }

        metadata = self._safe_metadata(data.get("metadata"))
        metadata.update(extra_fields)

        port = data.get("port")

        if port is not None:
            try:
                port = int(port)
            except (TypeError, ValueError) as exc:
                raise ValueError("port must be an integer.") from exc

            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535.")

        normalized = {
            "event_id": event_id,
            "event_type": event_type,
            "description": self._text(
                data.get("description"),
                "description",
                max_length=5000,
            ) or "",
            "category": category,
            "severity": severity,
            "timestamp": self._normalize_timestamp(
                data.get("timestamp")
            ),
            "received_at": self._now(),
            "username": self._text(
                data.get("username"),
                "username",
                max_length=200,
            ),
            "source_ip": self._normalize_ip(
                data.get("source_ip"),
                "source_ip",
            ),
            "destination_ip": self._normalize_ip(
                data.get("destination_ip"),
                "destination_ip",
            ),
            "source_host": self._text(
                data.get("source_host"),
                "source_host",
                max_length=255,
            ),
            "destination_host": self._text(
                data.get("destination_host"),
                "destination_host",
                max_length=255,
            ),
            "action": self._text(
                data.get("action"),
                "action",
                max_length=200,
            ),
            "outcome": self._text(
                data.get("outcome"),
                "outcome",
                max_length=100,
            ),
            "protocol": self._text(
                data.get("protocol"),
                "protocol",
                max_length=50,
            ),
            "port": port,
            "process_name": self._text(
                data.get("process_name"),
                "process_name",
                max_length=255,
            ),
            "command": self._text(
                data.get("command"),
                "command",
                max_length=2000,
            ),
            "source": self._text(
                data.get("source"),
                "source",
                max_length=200,
            ) or "api",
            "metadata": metadata,
        }

        return normalized

    # ---------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------

    def _persist_event(
        self,
        event: dict[str, Any],
    ) -> Any:
        """Save a normalized event through the configured repository."""
        create_method = getattr(
            self.repository,
            "create_event",
            None,
        )

        if not callable(create_method):
            raise RuntimeError(
                "The configured event repository does not "
                "implement create_event()."
            )

        return create_method(event)

    # ---------------------------------------------------------
    # Ingest a single event
    # ---------------------------------------------------------

    def ingest_event(
        self,
        event: dict[str, Any],
        persist: bool = True,
    ) -> dict[str, Any]:
        """
        Validate and ingest one event.

        When persist=True, success requires the repository operation
        to complete without raising an exception.
        """
        try:
            normalized = self.normalize_event(event)

            if persist:
                stored_result = self._persist_event(normalized)

                if stored_result is False:
                    raise RuntimeError(
                        "The repository reported that the event "
                        "was not saved."
                    )

                if stored_result is None:
                    logger.warning(
                        "Repository returned None after creating "
                        "event %s; verify persistence behavior.",
                        normalized["event_id"],
                    )

            logger.info(
                "Event ingested: event_id=%s type=%s persisted=%s",
                normalized["event_id"],
                normalized["event_type"],
                persist,
            )

            return {
                "success": True,
                "message": (
                    "Event ingested."
                    if persist
                    else "Event validated and normalized; not persisted."
                ),
                "persisted": persist,
                "event": normalized,
            }

        except (ValueError, TypeError) as exc:
            logger.warning("Event validation failed: %s", exc)

            return {
                "success": False,
                "message": "Event validation failed.",
                "error": str(exc),
                "persisted": False,
            }

        except Exception as exc:
            logger.exception("Event ingestion failed.")

            return {
                "success": False,
                "message": "Event ingestion failed.",
                "error": str(exc),
                "persisted": False,
            }

    # ---------------------------------------------------------
    # Ingest a batch
    # ---------------------------------------------------------

    def ingest_events(
        self,
        events: list[dict[str, Any]],
        persist: bool = True,
    ) -> dict[str, Any]:
        """
        Ingest a batch of events individually.

        Each event has its own result, so one invalid event does not
        prevent the remaining events from being processed.
        """
        if not isinstance(events, list):
            return {
                "success": False,
                "message": "events must be a list.",
                "total": 0,
                "succeeded": 0,
                "failed": 0,
                "results": [],
            }

        results = [
            self.ingest_event(event, persist=persist)
            for event in events
        ]

        succeeded = sum(
            1 for result in results if result["success"]
        )
        failed = len(results) - succeeded

        return {
            "success": failed == 0,
            "message": (
                "All events processed."
                if failed == 0
                else "Some events could not be processed."
            ),
            "total": len(events),
            "succeeded": succeeded,
            "failed": failed,
            "persisted": persist and failed == 0,
            "results": results,
            "timestamp": self._now(),
        }

    # ---------------------------------------------------------
    # Health check
    # ---------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """Report whether the ingestion service has a repository."""
        available = self.repository is not None

        return {
            "service": "ingestion",
            "status": "healthy" if available else "unhealthy",
            "repository_configured": available,
            "timestamp": self._now(),
        }


# Shared service instance
ingestion_service = IngestionService()
