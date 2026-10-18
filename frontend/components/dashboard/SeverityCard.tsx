import type { CSSProperties } from "react";
import { SEVERITY_META } from "../../utils/severity";
import type { EventSeverity } from "../../types/event";

interface SeverityCardProps {
  severity: EventSeverity;
  count: number;
}

export function SeverityCard({ severity, count }: SeverityCardProps) {
  const meta = SEVERITY_META[severity];

  return (
    <div
      className="severity-card"
      style={{ "--severity-color": meta.color } as CSSProperties}
    >
      <div className="severity-count">{count}</div>
      <div className="severity-label">{meta.label}</div>
    </div>
  );
}
