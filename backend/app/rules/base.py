
"""
GraphGuard AI - Base security detection rule.

All detection rules should inherit from BaseDetectionRule
and implement the detect() method.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class BaseDetectionRule(ABC):
    """
    Abstract base class for security detection rules.

    Each rule:
    - Has a unique rule ID and readable name.
    - Defines its severity and description.
    - Evaluates security events.
    - Returns standardized alert dictionaries.
    """

    RULE_ID = "BASE-000"
    RULE_NAME = "Base Detection Rule"
    DESCRIPTION = "Base class for security detection rules."
    DEFAULT_SEVERITY = "medium"

    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(
        self,
        enabled: bool = True,
        severity: str | None = None,
    ) -> None:
        self.enabled = enabled
        self.severity = (
            severity.lower()
            if severity is not None
            else self.DEFAULT_SEVERITY
        )

        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Choose from: {', '.join(sorted(self.VALID_SEVERITIES))}"
            )

    @abstractmethod
    def detect(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate one security event and return zero or more alerts.

        Implement this method in each concrete rule.
        """
        raise NotImplementedError

    def evaluate(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Safely evaluate an event using this rule.

        Disabled rules return no alerts. Invalid event input raises
        ValueError instead of silently hiding malformed data.
        """
        if not self.enabled:
            return []

        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        try:
            return self.detect(event)
        except (ValueError, TypeError):
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Detection rule {self.RULE_ID} failed: {exc}"
            ) from exc

    def create_alert(
        self,
        event: dict[str, Any],
        title: str,
        description: str,
        severity: str | None = None,
        risk_score: int = 50,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create a standardized alert from a detected event.

        risk_score is an integer from 0 to 100.
        """
        alert_severity = (
            severity.lower()
            if severity is not None
            else self.severity
        )

        if alert_severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid alert severity: {alert_severity}"
            )

        if (
            isinstance(risk_score, bool)
            or not isinstance(risk_score, int)
            or not 0 <= risk_score <= 100
        ):
            raise ValueError("risk_score must be an integer from 0 to 100")

        now = datetime.now(timezone.utc).isoformat()

        return {
            "alert_id": str(uuid4()),
            "rule_id": self.RULE_ID,
            "rule_name": self.RULE_NAME,
            "title": title,
            "description": description,
            "severity": alert_severity,
            "risk_score": risk_score,
            "status": "open",
            "event_id": event.get("event_id"),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "username": event.get("username"),
            "detected_at": now,
            "evidence": evidence or {},
        }

    def get_metadata(self) -> dict[str, Any]:
        """Return descriptive information about this rule."""
        return {
            "rule_id": self.RULE_ID,
            "name": self.RULE_NAME,
            "description": self.DESCRIPTION,
            "severity": self.severity,
            "enabled": self.enabled,
        }

    def enable(self) -> None:
        """Enable this detection rule."""
        self.enabled = True

    def disable(self) -> None:
        """Disable this detection rule."""
        self.enabled = False

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"rule_id={self.RULE_ID!r}, "
            f"enabled={self.enabled})"
        )
