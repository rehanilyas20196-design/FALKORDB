import type { CSSProperties } from "react";
import { Badge } from "../common/Badge";
import { SEVERITY_META } from "../../utils/severity";
import { formatRelativeTime } from "../../utils/formatDate";
import type { SecurityEvent } from "../../types/event";

interface EventTimeLineProps {
  events: SecurityEvent[];
}

export function EventTimeLine({ events }: EventTimeLineProps) {
  return (
    <div className="alert-list">
      {events.map((event) => {
        const meta = SEVERITY_META[event.severity];

        return (
          <div className="alert-row" key={event.event_id}>
            <span
              className="status-dot"
              style={{ background: meta.color } as CSSProperties}
              aria-hidden="true"
            />
            <div className="alert-main">
              <div className="alert-title">{event.event_type}</div>
              <div className="alert-meta">
                {event.source} · {formatRelativeTime(event.timestamp)}
              </div>
            </div>
            <Badge variant={meta.badgeVariant}>{meta.label}</Badge>
          </div>
        );
      })}
    </div>
  );
}
