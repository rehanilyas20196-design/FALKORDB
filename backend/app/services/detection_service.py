"""
GraphGuard AI - Detection Service

Runs the configured detection rules against the security events that are
currently held by the in-memory event store (backend/app/api/event.py).

This service is intentionally stateless: it evaluates the current event
set on demand and returns the alerts produced by the rules. It does not
persist alerts and it never mutates the stored events.

Used by the detections router (backend/app/api/detections.py).
"""

import logging
from typing import Any

from backend.app.api.event import _events

from backend.app.rules.base import BaseDetectionRule
from backend.app.rules.brute_force import BruteForceRule
from backend.app.rules.lateral_movement import LateralMovementRule
from backend.app.rules.suspicious_login import SuspiciousLoginRule

logger = logging.getLogger("graphguard.detections")


class DetectionService:
    """Evaluate detection rules against the in-memory security events."""

    # Rule instances are shared across calls. They are configuration
    # only and hold no per-request state.
    _rules: tuple[BaseDetectionRule, ...] = (
        BruteForceRule(),
        LateralMovementRule(),
        SuspiciousLoginRule(),
    )

    @staticmethod
    def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
        """
        Map stored event fields onto the field names the rules expect.

        The event store records the account under "user"; the detection
        rules read "username". This adapter bridges the two without
        mutating the stored event.
        """
        normalized = dict(event)

        if normalized.get("username") is None and normalized.get("user"):
            normalized["username"] = normalized.get("user")

        return normalized

    @classmethod
    def get_rules(cls) -> list[dict[str, Any]]:
        """Return metadata for every configured detection rule."""
        return [rule.get_metadata() for rule in cls._rules]

    @classmethod
    def run_detection_rules(cls) -> dict[str, Any]:
        """
        Run every configured rule against the current event set.

        Returns a summary plus the alerts that were raised. Rules that
        fail are logged and skipped so one bad rule cannot hide the rest.
        """
        events = [
            cls._normalize_event(event)
            for event in list(_events.values())
            if isinstance(event, dict)
        ]

        alerts: list[dict[str, Any]] = []
        failed_rules: list[str] = []

        for rule in cls._rules:
            if not rule.enabled:
                continue

            try:
                if hasattr(rule, "detect_batch"):
                    alerts.extend(rule.detect_batch(events))
                else:
                    for event in events:
                        alerts.extend(rule.detect(event))
            except Exception:
                logger.exception(
                    "Detection rule failed: %s", rule.RULE_ID
                )
                failed_rules.append(rule.RULE_ID)

        # Newest alerts first so the UI shows the latest activity.
        alerts.sort(key=lambda alert: alert.get("detected_at", ""), reverse=True)

        logger.info(
            "Detection run complete: events=%d alerts=%d failed_rules=%d",
            len(events),
            len(alerts),
            len(failed_rules),
        )

        return {
            "alerts": alerts,
            "alert_count": len(alerts),
            "events_evaluated": len(events),
            "rules_evaluated": len(cls._rules),
            "failed_rules": failed_rules,
            "rules": cls.get_rules(),
        }
