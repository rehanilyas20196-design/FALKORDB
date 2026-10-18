import type { EventSeverity } from "../types/event";

export interface SeverityMeta {
  label: string;
  badgeVariant: "critical" | "high" | "medium" | "low";
  color: string;
}

export const SEVERITY_META: Record<EventSeverity, SeverityMeta> = {
  critical: { label: "Critical", badgeVariant: "critical", color: "#ef4444" },
  high: { label: "High", badgeVariant: "high", color: "#f97316" },
  medium: { label: "Medium", badgeVariant: "medium", color: "#f59e0b" },
  low: { label: "Low", badgeVariant: "low", color: "#22c55e" },
};

export function isEventSeverity(value: unknown): value is EventSeverity {
  return (
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  );
}

export function severityMeta(value: string): SeverityMeta {
  if (isEventSeverity(value)) {
    return SEVERITY_META[value];
  }

  return { label: value || "Unknown", badgeVariant: "low", color: "#64748b" };
}
