
"""
GraphGuard AI - Lateral Movement Detection Rule.

Detects potentially suspicious movement between hosts using security
events such as remote logins, remote execution, and administrative
access across multiple systems.

This is a heuristic detection rule. It does not prove malicious activity.
It generates alerts for investigation and never executes containment.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.app.rules.base import BaseDetectionRule


class LateralMovementRule(BaseDetectionRule):
    """Detect potentially suspicious movement between hosts."""

    RULE_ID = "NETWORK-002"
    RULE_NAME = "Lateral Movement Detection"
    DESCRIPTION = (
        "Detects accounts accessing multiple hosts or suspicious "
        "remote execution and administrative activity."
    )
    DEFAULT_SEVERITY = "high"

    # Event types or action names associated with remote access.
    REMOTE_ACCESS_KEYWORDS = (
        "remote_login",
        "remote logon",
        "remote_access",
        "remote access",
        "rdp",
        "ssh",
        "winrm",
        "psexec",
        "wmi",
        "remote_execution",
        "remote execution",
        "lateral_movement",
        "lateral movement",
        "smb",
        "admin_share",
    )

    ADMIN_KEYWORDS = (
        "privilege_escalation",
        "privilege escalation",
        "admin_login",
        "administrator login",
        "remote_execution",
        "remote execution",
        "psexec",
        "winrm",
        "wmi",
    )

    def __init__(
        self,
        enabled: bool = True,
        severity: str | None = None,
        min_unique_hosts: int = 3,
        window_minutes: int = 15,
        critical_unique_hosts: int = 5,
    ) -> None:
        super().__init__(enabled=enabled, severity=severity)

        if (
            isinstance(min_unique_hosts, bool)
            or not isinstance(min_unique_hosts, int)
            or min_unique_hosts < 2
        ):
            raise ValueError("min_unique_hosts must be at least 2")

        if (
            isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or window_minutes < 1
        ):
            raise ValueError("window_minutes must be a positive integer")

        if (
            isinstance(critical_unique_hosts, bool)
            or not isinstance(critical_unique_hosts, int)
            or critical_unique_hosts < min_unique_hosts
        ):
            raise ValueError(
                "critical_unique_hosts must be >= min_unique_hosts"
            )

        self.min_unique_hosts = min_unique_hosts
        self.window_minutes = window_minutes
        self.critical_unique_hosts = critical_unique_hosts

    @staticmethod
    def _normalize(value: Any) -> str:
        """Normalize text values for matching."""
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
    def _event_text(cls, event: dict[str, Any]) -> str:
        """Combine relevant event fields into searchable text."""
        fields = (
            "event_type",
            "action",
            "description",
            "command",
            "protocol",
            "activity",
        )
        return " ".join(
            cls._normalize(event.get(field))
            for field in fields
            if event.get(field) is not None
        )

    @classmethod
    def _is_remote_access(cls, event: dict[str, Any]) -> bool:
        """Return True when an event indicates remote access activity."""
        text = cls._event_text(event)
        return any(keyword in text for keyword in cls.REMOTE_ACCESS_KEYWORDS)

    @classmethod
    def _is_admin_activity(cls, event: dict[str, Any]) -> bool:
        """Return True when an event suggests administrative activity."""
        text = cls._event_text(event)
        return any(keyword in text for keyword in cls.ADMIN_KEYWORDS)

    @staticmethod
    def _get_host(event: dict[str, Any]) -> str | None:
        """Extract a destination or target host identifier."""
        for field in (
            "destination_host",
            "target_host",
            "dest_host",
            "hostname",
            "host",
            "destination_ip",
        ):
            value = event.get(field)
            if value is not None and str(value).strip():
                return str(value).strip()

        return None

    @staticmethod
    def _get_source_host(event: dict[str, Any]) -> str | None:
        """Extract a source host identifier."""
        for field in ("source_host", "src_host", "origin_host"):
            value = event.get(field)
            if value is not None and str(value).strip():
                return str(value).strip()

        return None

    def _risk(
        self,
        unique_hosts: int,
        admin_activity: bool,
        remote_events: int,
    ) -> tuple[str, int]:
        """Estimate severity and risk based on observed behavior."""
        score = 50 + max(0, unique_hosts - self.min_unique_hosts) * 8
        score += min(remote_events, 5) * 3

        if admin_activity:
            score += 12

        if unique_hosts >= self.critical_unique_hosts:
            return "critical", min(100, max(90, score))

        if score >= 75:
            return "high", min(89, score)

        return self.severity, min(74, score)

    def detect(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate one event for explicit lateral-movement indicators.

        One event alone normally cannot establish movement across multiple
        hosts. Events can trigger this method when they explicitly identify
        lateral movement or include multiple distinct target hosts.
        """
        if not self.enabled:
            return []

        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        text = self._event_text(event)

        explicit_indicator = (
            "lateral_movement" in text
            or "lateral movement" in text
        )

        hosts_value = event.get("target_hosts")
        distinct_hosts = set()

        if isinstance(hosts_value, (list, tuple, set)):
            distinct_hosts = {
                str(host).strip()
                for host in hosts_value
                if host is not None and str(host).strip()
            }

        current_host = self._get_host(event)
        if current_host:
            distinct_hosts.add(current_host)

        if not explicit_indicator and len(distinct_hosts) < self.min_unique_hosts:
            return []

        if not explicit_indicator and not self._is_remote_access(event):
            return []

        count = max(len(distinct_hosts), self.min_unique_hosts)
        admin_activity = self._is_admin_activity(event)
        severity, score = self._risk(count, admin_activity, 1)

        return [
            self.create_alert(
                event=event,
                title="Potential lateral movement detected",
                description=(
                    "The event contains indicators of lateral movement "
                    "or remote access across multiple hosts. Investigate "
                    "the source account, target systems, and authentication "
                    "history to determine whether the activity is authorized."
                ),
                severity=severity,
                risk_score=score,
                evidence={
                    "source_host": self._get_source_host(event),
                    "target_hosts": sorted(distinct_hosts),
                    "unique_host_count": len(distinct_hosts),
                    "remote_access_indicator": self._is_remote_access(event),
                    "administrative_activity": admin_activity,
                    "detection_method": "single_event_indicator",
                    "window_minutes": self.window_minutes,
                },
            )
        ]

    def detect_batch(
        self,
        events: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Analyze events over a sliding time window.

        Groups remote-access events by username. A group triggers an alert
        when the account accesses enough distinct destination hosts.

        Events with missing or invalid timestamps are skipped.
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

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for event in events:
            if not isinstance(event, dict):
                continue

            if not self._is_remote_access(event):
                continue

            timestamp = self._parse_timestamp(event.get("timestamp"))

            if timestamp is None:
                continue

            if timestamp < window_start or timestamp > current_time:
                continue

            username = str(event.get("username") or "").strip()

            # Without an account identifier, grouping is less reliable.
            if not username:
                continue

            host = self._get_host(event)
            source_host = self._get_source_host(event)

            if not host:
                continue

            # A source host alone is not proof of lateral movement.
            if source_host and source_host.lower() == host.lower():
                continue

            grouped[username].append(event)

        alerts: list[dict[str, Any]] = []

        for username, user_events in grouped.items():
            host_names = {
                self._get_host(event)
                for event in user_events
                if self._get_host(event)
            }

            if len(host_names) < self.min_unique_hosts:
                continue

            remote_events = len(user_events)
            admin_activity = any(
                self._is_admin_activity(event)
                for event in user_events
            )

            severity, score = self._risk(
                unique_hosts=len(host_names),
                admin_activity=admin_activity,
                remote_events=remote_events,
            )

            latest_event = max(
                user_events,
                key=lambda event: (
                    self._parse_timestamp(event.get("timestamp"))
                    or datetime.min.replace(tzinfo=timezone.utc)
                ),
            )

            event_ids = [
                event.get("event_id")
                for event in user_events
                if event.get("event_id") is not None
            ]

            alerts.append(
                self.create_alert(
                    event=latest_event,
                    title="Potential lateral movement across hosts",
                    description=(
                        f"Account '{username}' generated {remote_events} "
                        f"remote-access events involving {len(host_names)} "
                        f"distinct destination hosts within "
                        f"{self.window_minutes} minutes. Verify whether "
                        "the activity matches normal administrative behavior."
                    ),
                    severity=severity,
                    risk_score=score,
                    evidence={
                        "username": username,
                        "target_hosts": sorted(host_names),
                        "unique_host_count": len(host_names),
                        "remote_event_count": remote_events,
                        "administrative_activity": admin_activity,
                        "event_ids": event_ids,
                        "window_minutes": self.window_minutes,
                        "detection_method": "batch_sliding_window",
                    },
                )
            )

        return alerts

    def get_metadata(self) -> dict[str, Any]:
        """Return rule metadata and configured thresholds."""
        metadata = super().get_metadata()
        metadata.update(
            {
                "min_unique_hosts": self.min_unique_hosts,
                "window_minutes": self.window_minutes,
                "critical_unique_hosts": self.critical_unique_hosts,
            }
        )
        return metadata


# Ready-to-use default instance.
lateral_movement_rule = LateralMovementRule()
