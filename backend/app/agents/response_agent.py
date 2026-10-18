
"""
GraphGuard AI - Response Agent

Responsibilities:
- Evaluate security investigation results.
- Prioritize threats.
- Recommend defensive response actions.
- Explain why each action is recommended.
- Require human approval before remediation.

This version uses Python's standard library only.
"""

from datetime import datetime, timezone
from typing import Any
import uuid


class ResponseAgent:
    """Creates a defensive response plan for security findings."""

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.agent_name = "response_agent"

    @staticmethod
    def _normalise_severity(value: Any) -> str:
        severity = str(value or "medium").strip().lower()

        if severity in {"critical", "high", "medium", "low", "info"}:
            return severity

        return "medium"

    @staticmethod
    def _get_value(
        data: dict[str, Any],
        *keys: str,
        default: Any = None,
    ) -> Any:
        for key in keys:
            value = data.get(key)
            if value is not None:
                return value
        return default

    @staticmethod
    def _determine_priority(
        severity: str,
        risk_score: int,
    ) -> str:
        """Determine response priority using severity and risk score."""

        if severity == "critical" or risk_score >= 90:
            return "P1"
        if severity == "high" or risk_score >= 70:
            return "P2"
        if severity == "medium" or risk_score >= 40:
            return "P3"
        return "P4"

    @staticmethod
    def _action(
        action_type: str,
        title: str,
        description: str,
        reason: str,
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Create a structured, approval-required response action."""

        return {
            "action_id": str(uuid.uuid4()),
            "type": action_type,
            "title": title,
            "description": description,
            "reason": reason,
            "priority": priority,
            "status": "pending_approval",
            "requires_human_approval": True,
            "automated": False,
        }

    def create_response_plan(
        self,
        alert: dict[str, Any],
        investigation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build a response plan from an alert and optional investigation.

        This method does not execute remediation actions.
        """

        if not isinstance(alert, dict):
            raise TypeError("alert must be a dictionary")

        if investigation is not None and not isinstance(investigation, dict):
            raise TypeError("investigation must be a dictionary or None")

        investigation = investigation or {}

        alert_id = self._get_value(alert, "id", "alert_id")
        title = str(
            self._get_value(
                alert,
                "title",
                "name",
                default="Security alert",
            )
        )

        severity = self._normalise_severity(
            investigation.get("severity") or alert.get("severity")
        )

        raw_score = investigation.get("risk_score", alert.get("risk_score", 50))

        try:
            risk_score = max(0, min(100, int(raw_score)))
        except (ValueError, TypeError):
            risk_score = 50

        priority = self._determine_priority(severity, risk_score)

        findings = investigation.get("findings") or []
        if not isinstance(findings, list):
            findings = []

        finding_types = {
            str(item.get("type", "")).lower()
            for item in findings
            if isinstance(item, dict)
        }

        recommended_actions: list[dict[str, Any]] = []

        # Every alert receives basic triage and evidence-preservation steps.
        recommended_actions.append(
            self._action(
                action_type="triage",
                title="Validate and triage the alert",
                description=(
                    "Review the original alert, affected assets, timestamps, "
                    "and available event records."
                ),
                reason=(
                    "Confirming the alert reduces false positives and helps "
                    "determine the appropriate response."
                ),
                priority="urgent" if priority == "P1" else "high",
            )
        )

        recommended_actions.append(
            self._action(
                action_type="evidence_preservation",
                title="Preserve relevant security evidence",
                description=(
                    "Preserve relevant logs and investigation records "
                    "according to the organisation's retention policy."
                ),
                reason=(
                    "Evidence helps incident responders validate the incident "
                    "and reconstruct what happened."
                ),
            )
        )

        if (
            "brute_force_pattern" in finding_types
            or "failed_login" in finding_types
            or "multiple_failed_logins" in finding_types
        ):
            recommended_actions.append(
                self._action(
                    action_type="account_protection",
                    title="Review account protection",
                    description=(
                        "Verify the affected account, inspect authentication "
                        "logs, and consider approved protective controls."
                    ),
                    reason=(
                        "Repeated failed logins can indicate password "
                        "guessing or another authentication threat."
                    ),
                    priority="high",
                )
            )

        if (
            "privilege_escalation_pattern" in finding_types
            or "privilege_escalation" in finding_types
        ):
            recommended_actions.append(
                self._action(
                    action_type="access_review",
                    title="Review privileged access changes",
                    description=(
                        "Verify recent role changes and administrative grants. "
                        "Revoke unauthorised privileges only through an "
                        "approved process."
                    ),
                    reason=(
                        "Unexpected privilege changes may allow an attacker "
                        "to gain additional access."
                    ),
                    priority="urgent",
                )
            )

        if (
            "large_outbound_transfer" in finding_types
            or "data_exfiltration" in finding_types
        ):
            recommended_actions.append(
                self._action(
                    action_type="data_transfer_review",
                    title="Investigate unusual outbound data",
                    description=(
                        "Review transfer volume, destination, affected systems, "
                        "and whether the transfer was authorised."
                    ),
                    reason=(
                        "Unusual outbound traffic may indicate data theft, "
                        "but legitimate transfers must also be considered."
                    ),
                    priority="high",
                )
            )

        if (
            "lateral_movement" in finding_types
            or "lateral_movement_pattern" in finding_types
        ):
            recommended_actions.append(
                self._action(
                    action_type="network_investigation",
                    title="Investigate possible lateral movement",
                    description=(
                        "Review authentication activity between hosts, "
                        "remote access records, and related network events."
                    ),
                    reason=(
                        "Movement between systems may indicate that an "
                        "intruder is expanding access."
                    ),
                    priority="high",
                )
            )

        # High-risk incidents receive an escalation recommendation.
        if priority in {"P1", "P2"}:
            recommended_actions.append(
                self._action(
                    action_type="incident_escalation",
                    title="Escalate to the security response team",
                    description=(
                        "Notify the authorised incident responder and follow "
                        "the organisation's incident-response procedure."
                    ),
                    reason=(
                        f"The alert has priority {priority}, severity "
                        f"{severity}, and a risk score of {risk_score}."
                    ),
                    priority="urgent" if priority == "P1" else "high",
                )
            )

        return {
            "response_id": str(uuid.uuid4()),
            "alert_id": alert_id,
            "title": f"Response plan: {title}",
            "status": "awaiting_human_review",
            "severity": severity,
            "risk_score": risk_score,
            "priority": priority,
            "summary": (
                f"Created {len(recommended_actions)} recommended response "
                f"actions for '{title}'. No remediation was executed."
            ),
            "actions": recommended_actions,
            "requires_human_approval": True,
            "automated_execution": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "agent": self.agent_name,
            "version": self.VERSION,
        }

    def create_response_plans(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Create response plans for multiple alerts."""

        return [
            self.create_response_plan(alert)
            for alert in alerts
        ]


# Shared instance for use by API routes and other agents.
response_agent = ResponseAgent()
