import { RotateCcw, Search } from "lucide-react";
import { Button } from "../common/Button";
import { SelectField, TextField } from "../common/Field";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../utils/constants";
import type { EventSeverity } from "../../types/event";

interface EventFilterProps {
  severity: EventSeverity | "";
  eventType: string;
  loading: boolean;
  resultCount: number;
  onSeverityChange: (value: EventSeverity | "") => void;
  onEventTypeChange: (value: string) => void;
  onReset: () => void;
}

export function EventFilter({
  severity,
  eventType,
  loading,
  resultCount,
  onSeverityChange,
  onEventTypeChange,
  onReset,
}: EventFilterProps) {
  const severityOptions = [
    { value: "", label: "All severities" },
    ...SEVERITY_ORDER.map((value) => ({
      value,
      label: SEVERITY_LABELS[value],
    })),
  ];

  return (
    <div className="filter-bar">
      <SelectField
        label="Severity"
        name="severity"
        value={severity}
        options={severityOptions}
        onChange={(event) =>
          onSeverityChange(event.target.value as EventSeverity | "")
        }
      />

      <TextField
        label="Event type"
        name="event_type"
        placeholder="e.g. login_failure"
        value={eventType}
        onChange={(event) => onEventTypeChange(event.target.value)}
      />

      <div className="filter-spacer" />

      <span className="faint">
        <Search
          size={13}
          aria-hidden="true"
          style={{ verticalAlign: "-2px", marginRight: 6 }}
        />
        {loading ? "Loading…" : `${resultCount} result${resultCount === 1 ? "" : "s"}`}
      </span>

      <Button
        variant="ghost"
        size="sm"
        icon={<RotateCcw size={15} aria-hidden="true" />}
        onClick={onReset}
      >
        Reset
      </Button>
    </div>
  );
}
