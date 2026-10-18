
"""
GraphGuard AI - Investigation Agent

Responsibilities:
- Investigate security alerts.
- Analyze evidence and related events.
- Identify possible attack patterns.
- Calculate an investigation risk score.
- Recommend investigation and containment actions.

This version works without an external AI API.
"""

from datetime import datetime, timezone
from typing import Any
import uuid


class InvestigationAgent:
    """Investigates security alerts and produces structured findings."""

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.agent_name = "investigation_agent"

    @staticmethod
    def _get_value(
        data: dict[str, Any],
        *keys: str,
        default: Any = None,
    ) -> Any:
        """Return the first available value from alternative field names."""
        for key in keys:
            value = data.get(key)
            if value is not None:
                return value
        return default

    @staticmethod
    def _normalise_severity(severity: Any) -> str:
        """Normalise severity labels."""
        value = str(severity or "medium").strip().lower()

        if value in {"critical", "high", "medium", "low", "info"}:
            return value

        return "medium"

    @staticmethod
    def _calculate_risk_score(
        severity: str,
        evidence_count: int,
        related_event_count: int,
        suspicious_indicators: int,
    ) -> int:
        """Calculate a simple, explainable risk score from 0 to 100."""
        severity_scores = {
            "critical": 90,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10,
        }

        score = severity_scores.get(severity, 50)
        score += min(evidence_count * 3, 12)
        score += min(related_event_count * 2, 10)
        score += min(suspicious_indicators * 4, 12)

        return min(score, 100)

    def investigate_alert(
        self,
        alert: dict[str, Any],
        related_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Investigate one alert using its evidence and related events.

        Expected alert example:
        {
            "id": "alert-001",
            "title": "Multiple failed logins",
            "severity": "high",
            "description": "Repeated login failures",
            "evidence": [{"ip": "192.0.2.10"}]
        }
        """
        if not isinstance(alert, dict):
            raise TypeError("alert must be a dictionary")

        related_events = related_events or []

        alert_id = self._get_value(alert, "id", "alert_id")
        title = str(
            self._get_value(alert, "title", "name", default="Untitled alert")
        )
        description = str(alert.get("description") or "")
        severity = self._normalise_severity(alert.get("severity"))

        evidence = alert.get("evidence") or []
        if not isinstance(evidence, list):
            evidence = [evidence]

        # Collect useful indicators from the alert and its related events.
        indicators: set[str] = set()
        suspicious_indicators: list[str] = []

        for item in [alert, *related_events]:
            if not isinstance(item, dict):
                continue

            for field in (
                "source_ip",
                "src_ip",
                "ip",
                "username",
                "user",
                "hostname",
                "host",
                "destination_ip",
                "dest_ip",
            ):
                value = item.get(field)
                if value is not None and str(value).strip():
                    indicators.add(f"{field}={str(value).strip()}")

            event_type = str(
                self._get_value(item, "event_type", "type", default="")
            ).lower()

            if any(
                keyword in event_type
                for keyword in (
                    "failed_login",
                    "privilege_escalation",
                    "suspicious",
                    "malware",
                    "exfiltration",
                    "lateral_movement",
                )
            ):
                suspicious_indicators.append(
                    f"Suspicious event type: {event_type}"
                )

        # Look for patterns in related events.
        failed_logins = 0
        privilege_events = 0
        outbound_bytes = 0

        for event in related_events:
            if not isinstance(event, dict):
                continue

            event_type = str(
                self._get_value(event, "event_type", "type", default="")
            ).lower()

            outcome = str(event.get("outcome") or "").lower()

            if (
                "failed_login" in event_type
                or "login_failed" in event_type
                or (
                    "login" in event_type
                    and outcome in {"failed", "failure", "denied"}
                )
            ):
                failed_logins += 1

            if any(
                keyword in event_type
                for keyword in (
                    "privilege_escalation",
                    "role_elevated",
                    "admin_granted",
                )
            ):
                privilege_events += 1

            transferred = self._get_value(
                event,
                "bytes_out",
                "outbound_bytes",
                "data_transferred_bytes",
                default=0,
            )

            try:
                outbound_bytes += max(0, int(transferred))
            except (ValueError, TypeError):
                pass

        findings: list[dict[str, str]] = []

        if failed_logins >= 5:
            findings.append(
                {
                    "type": "brute_force_pattern",
                    "severity": "high",
                    "description": (
                        f"{failed_logins} failed login events were found. "
                        "This may indicate a brute-force attempt."
                    ),
                }
            )

        if privilege_events:
            findings.append(
                {
                    "type": "privilege_escalation_pattern",
                    "severity": "high",
                    "description": (
                        f"{privilege_events} privilege-related events were "
                        "found. Verify whether the changes were authorised."
                    ),
                }
            )

        if outbound_bytes >= 100 * 1024 * 1024:
            findings.append(
                {
                    "type": "large_outbound_transfer",
                    "severity": "high",
                    "description": (
                        "Related events show at least 100 MiB of outbound "
                        "data. Review the destination and authorisation."
                    ),
                }
            )

        if not findings:
            findings.append(
                {
                    "type": "initial_review",
                    "severity": severity,
                    "description": (
                        "No additional predefined attack pattern was confirmed. "
                        "Review the original alert and validate its evidence."
                    ),
                }
            )

        recommended_actions = [
            "Validate the alert against the original event records.",
            "Check whether the affected account and source IP are authorised.",
            "Review related events before closing the investigation.",
        ]

        if failed_logins >= 5:
            recommended_actions.append(
                "Review authentication logs and apply account protections "
                "according to your incident-response policy."
            )

        if privilege_events:
            recommended_actions.append(
                "Verify administrative changes and revoke unauthorised "
                "privileges through an approved response process."
            )

        if outbound_bytes >= 100 * 1024 * 1024:
            recommended_actions.append(
                "Inspect outbound transfer records and investigate the "
                "destination before deciding on containment."
            )

        risk_score = self._calculate_risk_score(
            severity=severity,
            evidence_count=len(evidence),
            related_event_count=len(related_events),
            suspicious_indicators=len(suspicious_indicators),
        )

        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 35:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "investigation_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "title": f"Investigation: {title}",
            "status": "completed",
            "severity": severity,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": (
                f"Investigated '{title}' using {len(evidence)} evidence "
                f"item(s) and {len(related_events)} related event(s). "
                f"Found {len(findings)} investigation finding(s)."
            ),
            "original_description": description,
            "findings": findings,
            "indicators": sorted(indicators),
            "metrics": {
                "evidence_count": len(evidence),
                "related_event_count": len(related_events),
                "failed_login_count": failed_logins,
                "privilege_event_count": privilege_events,
                "outbound_bytes": outbound_bytes,
            },
            "recommended_actions": recommended_actions,
            "requires_human_review": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "agent": self.agent_name,
            "version": self.VERSION,
        }

    def investigate_alerts(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Investigate multiple alerts."""
        return [
            self.investigate_alert(alert)
            for alert in alerts
        ]


# Reusable instance for the application.
investigation_agent = InvestigationAgent()
