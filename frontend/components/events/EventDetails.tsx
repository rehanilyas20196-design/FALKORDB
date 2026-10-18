import type { ReactNode } from "react";
import { Badge } from "../common/Badge";
import { SEVERITY_META } from "../../utils/severity";
import { formatDateTime, formatRelativeTime } from "../../utils/formatDate";
import type { SecurityEvent } from "../../types/event";

interface EventDetailsProps {
  event: SecurityEvent;
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="detail-row">
      <div className="detail-key">{label}</div>
      <div className="detail-value">{value}</div>
    </div>
  );
}

export function EventDetails({ event }: EventDetailsProps) {
  const meta = SEVERITY_META[event.severity];
  const metadata = event.metadata ?? {};
  const hasMetadata = Object.keys(metadata).length > 0;

  return (
    <div className="stack">
      <div className="row">
        <Badge variant={meta.badgeVariant}>{meta.label}</Badge>
        <strong>{event.event_type}</strong>
      </div>

      <div className="detail-list">
        <Row label="Event ID" value={<span className="mono">{event.event_id}</span>} />
        <Row label="Source" value={event.source} />
        <Row label="User" value={event.user ?? "—"} />
        <Row label="Source IP" value={event.source_ip ?? "—"} />
        <Row label="Destination IP" value={event.destination_ip ?? "—"} />
        <Row
          label="Timestamp"
          value={
            <>
              {formatDateTime(event.timestamp)}{" "}
              <span className="faint">({formatRelativeTime(event.timestamp)})</span>
            </>
          }
        />
        <Row
          label="Description"
          value={event.description ? event.description : "—"}
        />
      </div>

      {hasMetadata ? (
        <div>
          <div className="detail-key" style={{ marginBottom: 8 }}>
            Metadata
          </div>
          <pre className="code-block">{JSON.stringify(metadata, null, 2)}</pre>
        </div>
      ) : null}
    </div>
  );
}
