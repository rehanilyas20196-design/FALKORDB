
"""
GraphGuard AI - Brute Force Detection Rule.

Detects repeated failed login attempts grouped by username and
source IP address. Supports both individual event evaluation and
batch analysis of multiple events.

Expected event fields may include:
    event_id, event_type, description, username, source_ip,
    timestamp, failed_attempts, and status.

This rule generates alerts only. It does not block accounts or IPs.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.app.rules.base import BaseDetectionRule


class BruteForceRule(BaseDetectionRule):
    """Detect repeated failed login attempts."""

    RULE_ID = "AUTH-001"
    RULE_NAME = "Brute Force Detection"
    DESCRIPTION = (
        "Detects repeated failed login attempts from the same "
        "source IP or against the same username."
    )
    DEFAULT_SEVERITY = "high"

    def __init__(
        self,
        enabled: bool = True,
        severity: str | None = None,
        threshold: int = 5,
        window_minutes: int = 10,
        critical_threshold: int = 15,
    ) -> None:
        super().__init__(enabled=enabled, severity=severity)

        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or threshold < 2
        ):
            raise ValueError("threshold must be an integer of at least 2")

        if (
            isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or window_minutes < 1
        ):
            raise ValueError("window_minutes must be a positive integer")

        if (
            isinstance(critical_threshold, bool)
            or not isinstance(critical_threshold, int)
            or critical_threshold < threshold
        ):
            raise ValueError(
                "critical_threshold must be greater than or equal to threshold"
            )

        self.threshold = threshold
        self.window_minutes = window_minutes
        self.critical_threshold = critical_threshold

    @staticmethod
    def _text(value: Any) -> str:
        """Convert a value to normalized lowercase text."""
        if value is None:
            return ""
        return str(value).strip().lower()

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        """
        Parse an ISO timestamp.

        Naive timestamps are interpreted as UTC. Unsupported or missing
        timestamps return None rather than crashing detection.
        """
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                parsed = datetime.fromtimestamp(value, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                return None
        elif isinstance(value, str):
            value = value.strip()

            if not value:
                return None

            try:
                parsed = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError:
                return None
        else:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @classmethod
    def _is_failed_login(cls, event: dict[str, Any]) -> bool:
        """
        Decide whether an event represents a failed login.

        Supports common event names and explicit result/status fields.
        Avoids treating every event containing the word 'login' as failed.
        """
        event_type = cls._text(event.get("event_type"))
        description = cls._text(event.get("description"))
        action = cls._text(event.get("action"))
        outcome = cls._text(
            event.get("outcome", event.get("result", event.get("status")))
        )

        login_related = any(
            word in event_type or word in action
            for word in ("login", "logon", "authentication", "auth")
        )

        failed_outcome = outcome in {
            "failed",
            "failure",
            "denied",
            "rejected",
            "unsuccessful",
            "invalid_password",
            "invalid credentials",
        }

        failed_description = any(
            phrase in description
            for phrase in (
                "failed login",
                "login failed",
                "login failure",
                "failed logon",
                "authentication failed",
                "authentication failure",
                "invalid password",
                "invalid credentials",
                "authentication denied",
            )
        )

        failed_event_type = any(
            phrase in event_type
            for phrase in (
                "login_failed",
                "failed_login",
                "logon_failed",
                "authentication_failure",
                "auth_failure",
            )
        )

        explicit_success = outcome in {
            "success",
            "successful",
            "passed",
            "authenticated",
        }

        if explicit_success:
            return False

        return (
            (login_related and failed_outcome)
            or failed_description
            or failed_event_type
        )

    def _risk_severity(self, attempts: int) -> tuple[str, int]:
        """Map the number of failed attempts to severity and risk score."""
        if attempts >= self.critical_threshold:
            return "critical", min(100, 90 + attempts - self.critical_threshold)

        if attempts >= self.threshold * 2:
            return "high", min(89, 75 + attempts - self.threshold * 2)

        return self.severity, min(74, 55 + attempts - self.threshold)

    def detect(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate one event.

        An event can trigger an alert if it explicitly reports a
        failed-attempt count at or above the threshold.

        For detection across multiple separate events, use detect_batch().
        """
        if not self._is_failed_login(event):
            return []

        attempts = event.get("failed_attempts", event.get("attempt_count", 1))

        try:
            attempts = int(attempts)
        except (TypeError, ValueError):
            return []

        if isinstance(event.get("failed_attempts"), bool):
            return []

        if attempts < self.threshold:
            return []

        username = event.get("username") or "unknown"
        source_ip = event.get("source_ip") or "unknown"
        severity, risk_score = self._risk_severity(attempts)

        alert = self.create_alert(
            event=event,
            title="Possible brute-force login attack",
            description=(
                f"Detected {attempts} failed login attempts associated "
                f"with username '{username}' and source IP '{source_ip}'."
            ),
            severity=severity,
            risk_score=risk_score,
            evidence={
                "failed_attempts": attempts,
                "username": username,
                "source_ip": source_ip,
                "threshold": self.threshold,
                "window_minutes": self.window_minutes,
                "detection_method": "single_event_attempt_count",
            },
        )

        return [alert]

    def detect_batch(
        self,
        events: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Analyze multiple events within a sliding time window.

        Groups failed logins by (username, source_ip). An alert is
        generated when the group reaches the configured threshold.

        Events without parseable timestamps are skipped for window-based
        analysis because their age cannot be reliably determined.
        """
        if not self.enabled:
            return []

        if not isinstance(events, list):
            raise ValueError("events must be a list of dictionaries")

        current_time = now or datetime.now(timezone.utc)

        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        current_time = current_time.astimezone(timezone.utc)
        window_start = current_time - timedelta(minutes=self.window_minutes)

        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for event in events:
            if not isinstance(event, dict):
                continue

            if not self._is_failed_login(event):
                continue

            event_time = self._parse_timestamp(event.get("timestamp"))

            if event_time is None:
                continue

            if event_time < window_start or event_time > current_time:
                continue

            username = str(event.get("username") or "unknown").strip()
            source_ip = str(event.get("source_ip") or "unknown").strip()

            grouped[(username, source_ip)].append(event)

        alerts: list[dict[str, Any]] = []

        for (username, source_ip), matching_events in grouped.items():
            attempts = len(matching_events)

            if attempts < self.threshold:
                continue

            severity, risk_score = self._risk_severity(attempts)

            latest_event = max(
                matching_events,
                key=lambda item: self._parse_timestamp(item.get("timestamp"))
                or datetime.min.replace(tzinfo=timezone.utc),
            )

            event_ids = [
                item.get("event_id")
                for item in matching_events
                if item.get("event_id") is not None
            ]

            alerts.append(
                self.create_alert(
                    event=latest_event,
                    title="Repeated failed login attempts detected",
                    description=(
                        f"Detected {attempts} failed login events within "
                        f"{self.window_minutes} minutes for username "
                        f"'{username}' from source IP '{source_ip}'."
                    ),
                    severity=severity,
                    risk_score=risk_score,
                    evidence={
                        "username": username,
                        "source_ip": source_ip,
                        "failed_attempts": attempts,
                        "threshold": self.threshold,
                        "window_minutes": self.window_minutes,
                        "event_ids": event_ids,
                        "detection_method": "batch_sliding_window",
                    },
                )
            )

        return alerts


# Ready-to-use default instance.
brute_force_rule = BruteForceRule()
