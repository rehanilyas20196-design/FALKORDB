import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../common/Button";
import { SelectField, TextAreaField, TextField } from "../common/Field";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "../../utils/constants";
import type { CreateEventInput, EventSeverity } from "../../types/event";

interface CreateEventFormProps {
  submitting: boolean;
  onSubmit: (input: CreateEventInput) => void;
  onCancel: () => void;
}

interface FormState {
  event_type: string;
  source: string;
  severity: EventSeverity;
  description: string;
  user: string;
  source_ip: string;
  destination_ip: string;
  timestamp: string;
  metadata: string;
}

const INITIAL: FormState = {
  event_type: "",
  source: "",
  severity: "medium",
  description: "",
  user: "",
  source_ip: "",
  destination_ip: "",
  timestamp: "",
  metadata: "",
};

function nullable(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function CreateEventForm({
  submitting,
  onSubmit,
  onCancel,
}: CreateEventFormProps) {
  const [form, setForm] = useState<FormState>(INITIAL);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const update = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const validate = (): CreateEventInput | null => {
    const nextErrors: Record<string, string> = {};

    if (form.event_type.trim().length < 1) {
      nextErrors.event_type = "Event type is required.";
    }

    if (form.source.trim().length < 1) {
      nextErrors.source = "Source is required.";
    }

    let metadata: Record<string, unknown> = {};

    if (form.metadata.trim().length > 0) {
      try {
        const parsed: unknown = JSON.parse(form.metadata);
        if (
          parsed === null ||
          typeof parsed !== "object" ||
          Array.isArray(parsed)
        ) {
          nextErrors.metadata = "Metadata must be a JSON object.";
        } else {
          metadata = parsed as Record<string, unknown>;
        }
      } catch {
        nextErrors.metadata = "Metadata must be valid JSON.";
      }
    }

    setErrors(nextErrors);

    if (Object.keys(nextErrors).length > 0) {
      return null;
    }

    return {
      event_type: form.event_type.trim(),
      source: form.source.trim(),
      severity: form.severity,
      description: form.description.trim(),
      user: nullable(form.user),
      source_ip: nullable(form.source_ip),
      destination_ip: nullable(form.destination_ip),
      timestamp: form.timestamp
        ? new Date(form.timestamp).toISOString()
        : null,
      metadata,
    };
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const input = validate();
    if (input) {
      onSubmit(input);
    }
  };

  return (
    <form onSubmit={handleSubmit} noValidate>
      <div className="form-grid">
        <TextField
          label="Event type"
          name="event_type"
          required
          placeholder="login_failure"
          value={form.event_type}
          error={errors.event_type}
          maxLength={150}
          onChange={(event) => update("event_type", event.target.value)}
        />

        <TextField
          label="Source"
          name="source"
          required
          placeholder="host-01 / auth-service"
          value={form.source}
          error={errors.source}
          maxLength={200}
          onChange={(event) => update("source", event.target.value)}
        />

        <SelectField
          label="Severity"
          name="severity"
          value={form.severity}
          options={SEVERITY_ORDER.map((value) => ({
            value,
            label: SEVERITY_LABELS[value],
          }))}
          onChange={(event) =>
            update("severity", event.target.value as EventSeverity)
          }
        />

        <TextField
          label="Timestamp"
          name="timestamp"
          type="datetime-local"
          hint="Optional. Defaults to the server time."
          value={form.timestamp}
          onChange={(event) => update("timestamp", event.target.value)}
        />

        <TextField
          label="User"
          name="user"
          placeholder="Optional"
          value={form.user}
          onChange={(event) => update("user", event.target.value)}
        />

        <TextField
          label="Source IP"
          name="source_ip"
          placeholder="Optional"
          value={form.source_ip}
          onChange={(event) => update("source_ip", event.target.value)}
        />

        <TextField
          label="Destination IP"
          name="destination_ip"
          placeholder="Optional"
          value={form.destination_ip}
          onChange={(event) => update("destination_ip", event.target.value)}
        />

        <div className="span-2">
          <TextAreaField
            label="Description"
            name="description"
            rows={3}
            placeholder="What happened?"
            value={form.description}
            onChange={(event) => update("description", event.target.value)}
          />
        </div>

        <div className="span-2">
          <TextAreaField
            label="Metadata (JSON)"
            name="metadata"
            placeholder='{ "rule": "T1110", "attempts": 12 }'
            value={form.metadata}
            error={errors.metadata}
            onChange={(event) => update("metadata", event.target.value)}
          />
        </div>
      </div>

      <div className="modal-footer" style={{ paddingLeft: 0, paddingRight: 0 }}>
        <Button variant="ghost" onClick={onCancel} disabled={submitting}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={submitting}>
          Create event
        </Button>
      </div>
    </form>
  );
}
