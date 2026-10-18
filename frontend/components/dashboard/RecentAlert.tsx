import { Badge } from "../common/Badge";
import { EmptyState } from "../common/EmptyState";
import { ShieldCheck } from "lucide-react";
import { SEVERITY_META } from "../../utils/severity";
import { formatRelativeTime } from "../../utils/formatDate";
import type { SecurityEvent } from "../../types/event";

interface RecentAlertProps {
  events: SecurityEvent[];
}

export function RecentAlert({ events }: RecentAlertProps) {
  if (events.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck size={24} />}
        title="No high-priority events"
        description="No critical or high severity events have been ingested yet."
      />
    );
  }

  return (
    <div className="alert-list">
      {events.map((event) => {
        const meta = SEVERITY_META[event.severity];

        return (
          <div className="alert-row" key={event.event_id}>
            <div className="alert-main">
              <div className="alert-title">{event.event_type}</div>
              <div className="alert-meta">
                {event.source}
                {event.source_ip ? ` · ${event.source_ip}` : ""} ·{" "}
                {formatRelativeTime(event.timestamp)}
              </div>
            </div>
            <Badge variant={meta.badgeVariant}>{meta.label}</Badge>
          </div>
        );
      })}
    </div>
  );
}
