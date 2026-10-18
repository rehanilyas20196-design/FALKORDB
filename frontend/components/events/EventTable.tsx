import { Eye, Trash2 } from "lucide-react";
import { Badge } from "../common/Badge";
import { SEVERITY_META } from "../../utils/severity";
import { formatDateTime } from "../../utils/formatDate";
import type { SecurityEvent } from "../../types/event";

interface EventTableProps {
  events: SecurityEvent[];
  deletingId: string | null;
  onSelect: (event: SecurityEvent) => void;
  onDelete: (event: SecurityEvent) => void;
}

export function EventTable({
  events,
  deletingId,
  onSelect,
  onDelete,
}: EventTableProps) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Event type</th>
            <th>Source</th>
            <th>User</th>
            <th>Source IP</th>
            <th>Time</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const meta = SEVERITY_META[event.severity];

            return (
              <tr key={event.event_id}>
                <td>
                  <Badge variant={meta.badgeVariant}>{meta.label}</Badge>
                </td>
                <td className="cell-title">{event.event_type}</td>
                <td className="cell-muted">{event.source}</td>
                <td className="cell-muted">{event.user ?? "—"}</td>
                <td className="cell-mono">{event.source_ip ?? "—"}</td>
                <td className="cell-muted">{formatDateTime(event.timestamp)}</td>
                <td>
                  <div className="row-actions">
                    <button
                      type="button"
                      className="icon-button"
                      aria-label={`View event ${event.event_type}`}
                      onClick={() => onSelect(event)}
                    >
                      <Eye size={16} aria-hidden="true" />
                    </button>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label={`Delete event ${event.event_type}`}
                      disabled={deletingId === event.event_id}
                      onClick={() => onDelete(event)}
                    >
                      {deletingId === event.event_id ? (
                        <span className="spinner sm" aria-hidden="true" />
                      ) : (
                        <Trash2 size={16} aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
