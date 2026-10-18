
"""
GraphGuard AI - Suspicious Login Detection Rule.

Detects potentially suspicious authentication patterns:
- Logins from explicitly flagged unusual locations
- Logins from new or unrecognized devices
- Logins during unusual hours when that information is provided
- Successful logins following repeated failed login attempts
- Explicitly flagged suspicious authentication events

This is a heuristic rule. It does not independently establish malicious
activity and does not block users or devices.
"""

from datetime import datetime, timezone
from typing import Any

from backend.app.rules.base import BaseDetectionRule


class SuspiciousLoginRule(BaseDetectionRule):
    """Detect suspicious authentication events."""

    RULE_ID = "AUTH-003"
    RULE_NAME = "Suspicious Login Detection"
    DESCRIPTION = (
        "Detects potentially suspicious logins using authentication "
        "outcomes, device and location indicators, login timing, "
        "and preceding failed attempts."
    )
    DEFAULT_SEVERITY = "medium"

    def __init__(
        self,
        enabled: bool = True,
        severity: str | None = None,
        failed_attempt_threshold: int = 5,
        critical_failed_attempt_threshold: int = 10,
        unusual_hour_start: int = 0,
        unusual_hour_end: int = 5,
    ) -> None:
        super().__init__(enabled=enabled, severity=severity)

        if (
            isinstance(failed_attempt_threshold, bool)
            or not isinstance(failed_attempt_threshold, int)
            or failed_attempt_threshold < 1
        ):
            raise ValueError(
                "failed_attempt_threshold must be a positive integer"
            )

        if (
            isinstance(critical_failed_attempt_threshold, bool)
            or not isinstance(critical_failed_attempt_threshold, int)
            or critical_failed_attempt_threshold < failed_attempt_threshold
        ):
            raise ValueError(
                "critical_failed_attempt_threshold must be greater than "
                "or equal to failed_attempt_threshold"
            )

        if (
            isinstance(unusual_hour_start, bool)
            or not isinstance(unusual_hour_start, int)
            or not 0 <= unusual_hour_start <= 23
        ):
            raise ValueError("unusual_hour_start must be between 0 and 23")

        if (
            isinstance(unusual_hour_end, bool)
            or not isinstance(unusual_hour_end, int)
            or not 0 <= unusual_hour_end <= 23
        ):
            raise ValueError("unusual_hour_end must be between 0 and 23")

        self.failed_attempt_threshold = failed_attempt_threshold
        self.critical_failed_attempt_threshold = (
            critical_failed_attempt_threshold
        )
        self.unusual_hour_start = unusual_hour_start
        self.unusual_hour_end = unusual_hour_end

    @staticmethod
    def _normalize(value: Any) -> str:
        """Normalize a value for case-insensitive comparison."""
        if value is None:
            return ""
        return str(value).strip().lower()

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        """Parse ISO-8601 or Unix timestamps into UTC."""
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                parsed = datetime.fromtimestamp(value, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                return None
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(
                    value.strip().replace("Z", "+00:00")
                )
            except ValueError:
                return None
        else:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @classmethod
    def _is_login_event(cls, event: dict[str, Any]) -> bool:
        """Return True if the event appears related to authentication."""
        text = " ".join(
            cls._normalize(event.get(field))
            for field in (
                "event_type",
                "action",
                "description",
                "activity",
            )
        )

        return any(
            keyword in text
            for keyword in (
                "login",
                "logon",
                "authentication",
                "auth_success",
                "auth_failure",
                "sign-in",
                "signin",
            )
        )

    @classmethod
    def _is_successful_login(cls, event: dict[str, Any]) -> bool:
        """Determine whether an authentication event indicates success."""
        event_type = cls._normalize(event.get("event_type"))
        action = cls._normalize(event.get("action"))
        outcome = cls._normalize(
            event.get(
                "outcome",
                event.get("result", event.get("status")),
            )
        )

        # An explicit failed outcome must never be interpreted as success.
        if outcome in {
            "failed",
            "failure",
            "denied",
            "rejected",
            "unsuccessful",
        }:
            return False

        if outcome in {"success", "successful", "passed", "authenticated"}:
            return True

        text = f"{event_type} {action}"

        return any(
            marker in text
            for marker in (
                "login_success",
                "successful_login",
                "successful logon",
                "auth_success",
                "authentication_success",
                "login successful",
                "logon_success",
            )
        )

    def _collect_indicators(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Collect suspicious indicators and their explanations."""
        indicators: list[dict[str, Any]] = []

        event_type = self._normalize(event.get("event_type"))
        action = self._normalize(event.get("action"))
        description = self._normalize(event.get("description"))

        combined_text = f"{event_type} {action} {description}"

        # Explicit flags should be supplied by a trusted detector or
        # a verified upstream enrichment process.
        if event.get("is_suspicious") is True:
            indicators.append({
                "type": "explicit_suspicious_flag",
                "description": "The event was explicitly flagged as suspicious.",
            })

        if event.get("unusual_location") is True:
            indicators.append({
                "type": "unusual_location",
                "description": "The event was flagged as coming from an unusual location.",
            })

        if event.get("new_device") is True:
            indicators.append({
                "type": "new_device",
                "description": "The event was flagged as originating from a new device.",
            })

        if event.get("impossible_travel") is True:
            indicators.append({
                "type": "impossible_travel",
                "description": "The event was flagged for a possible impossible-travel pattern.",
            })

        if event.get("unusual_time") is True:
            indicators.append({
                "type": "unusual_time",
                "description": "The event was flagged as occurring at an unusual time.",
            })

        if event.get("mfa_failed") is True:
            indicators.append({
                "type": "mfa_failure",
                "description": "The event indicates a failed multi-factor authentication check.",
            })

        # Optional timing heuristic. This uses the timestamp's UTC hour.
        # It is not a substitute for the user's normal login baseline.
        timestamp = self._parse_timestamp(event.get("timestamp"))

        if timestamp is not None:
            hour = timestamp.hour

            if self.unusual_hour_start < self.unusual_hour_end:
                is_unusual_hour = (
                    self.unusual_hour_start <= hour < self.unusual_hour_end
                )
            elif self.unusual_hour_start > self.unusual_hour_end:
                # Supports windows crossing midnight.
                is_unusual_hour = (
                    hour >= self.unusual_hour_start
                    or hour < self.unusual_hour_end
                )
            else:
                # Equal start/end means no time-based window is configured.
                is_unusual_hour = False

            if is_unusual_hour and event.get("successful") is True:
                indicators.append({
                    "type": "unusual_login_hour",
                    "description": (
                        f"Successful login occurred at UTC hour {hour}, "
                        "within the configured unusual-hours window."
                    ),
                })

        # Recognize explicit suspicious event labels without treating
        # every ordinary login as suspicious.
        explicit_markers = (
            "impossible_travel",
            "impossible travel",
            "suspicious_login",
            "suspicious login",
            "account_takeover",
            "account takeover",
        )

        if any(marker in combined_text for marker in explicit_markers):
            indicators.append({
                "type": "suspicious_event_label",
                "description": (
                    "The event type or description contains a known "
                    "suspicious-authentication indicator."
                ),
            })

        return indicators

    def _calculate_risk(
        self,
        indicator_count: int,
        failed_attempts: int,
        successful_login: bool,
    ) -> tuple[str, int]:
        """Estimate severity and risk score from available evidence."""
        score = 40 + min(indicator_count, 4) * 10

        if successful_login and failed_attempts >= self.failed_attempt_threshold:
            score += 15

        if failed_attempts >= self.critical_failed_attempt_threshold:
            score += 20

        score = min(100, score)

        if score >= 90:
            return "critical", score

        if score >= 75:
            return "high", score

        if score >= 55:
            return "medium", score

        return self.severity, score

    def detect(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate a single login event.

        A successful login following repeated failures can trigger an
        alert when the upstream event supplies failed_attempts.
        """
        if not self.enabled:
            return []

        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        if not self._is_login_event(event):
            # Explicit suspicious labels may also be handled when the
            # event type itself identifies a suspicious login.
            event_text = " ".join(
                self._normalize(event.get(field))
                for field in ("event_type", "action", "description")
            )

            if not any(
                marker in event_text
                for marker in (
                    "suspicious_login",
                    "suspicious login",
                    "impossible_travel",
                    "impossible travel",
                    "account_takeover",
                    "account takeover",
                )
            ):
                return []

        indicators = self._collect_indicators(event)

        failed_attempts = event.get("failed_attempts", 0)

        if (
            isinstance(failed_attempts, bool)
            or not isinstance(failed_attempts, int)
            or failed_attempts < 0
        ):
            failed_attempts = 0

        successful_login = (
            self._is_successful_login(event)
            or event.get("successful") is True
        )

        if (
            successful_login
            and failed_attempts >= self.failed_attempt_threshold
        ):
            indicators.append({
                "type": "success_after_repeated_failures",
                "description": (
                    f"A successful login followed {failed_attempts} "
                    "reported failed attempts."
                ),
            })

        if not indicators:
            return []

        severity, risk_score = self._calculate_risk(
            indicator_count=len(indicators),
            failed_attempts=failed_attempts,
            successful_login=successful_login,
        )

        username = event.get("username") or "unknown"
        source_ip = event.get("source_ip") or "unknown"

        return [
            self.create_alert(
                event=event,
                title="Potentially suspicious login detected",
                description=(
                    f"Potentially suspicious authentication activity was "
                    f"detected for account '{username}' from source "
                    f"'{source_ip}'. Further investigation is required."
                ),
                severity=severity,
                risk_score=risk_score,
                evidence={
                    "username": username,
                    "source_ip": source_ip,
                    "successful_login": successful_login,
                    "failed_attempts": failed_attempts,
                    "indicators": indicators,
                    "timestamp": event.get("timestamp"),
                    "detection_method": "single_event_heuristics",
                },
            )
        ]

    def detect_batch(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Evaluate multiple authentication events.

        This method evaluates each event individually. To correlate a
        successful login with earlier failed logins, the incoming events
        should already include a failed_attempts count calculated by an
        upstream service or correlation step.
        """
        if not self.enabled:
            return []

        if not isinstance(events, list):
            raise ValueError("events must be a list of dictionaries")

        alerts: list[dict[str, Any]] = []

        for event in events:
            if not isinstance(event, dict):
                continue

            alerts.extend(self.detect(event))

        return alerts

    def get_metadata(self) -> dict[str, Any]:
        """Return rule metadata and configured thresholds."""
        metadata = super().get_metadata()

        metadata.update({
            "failed_attempt_threshold": self.failed_attempt_threshold,
            "critical_failed_attempt_threshold": (
                self.critical_failed_attempt_threshold
            ),
            "unusual_hour_start_utc": self.unusual_hour_start,
            "unusual_hour_end_utc": self.unusual_hour_end,
        })

        return metadata


# Ready-to-use default instance.
suspicious_login_rule = SuspiciousLoginRule()
