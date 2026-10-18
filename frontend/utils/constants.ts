import type { EventSeverity } from "../types/event";

export const API_PREFIX = "/api/v1";

export const APP_NAME = "GraphGuard AI";
export const APP_TAGLINE = "Security Operations Console";

export const SEVERITY_ORDER: EventSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

export const SEVERITY_LABELS: Record<EventSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const DEFAULT_EVENT_LIMIT = 200;

export const EVENT_LIMIT_OPTIONS = [50, 100, 200, 500] as const;

export const DISCLAIMER =
  "GraphGuard AI is a development build. Backend event storage is in-memory and is cleared when the backend restarts.";
