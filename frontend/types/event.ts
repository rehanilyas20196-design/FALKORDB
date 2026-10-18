export type EventSeverity = "low" | "medium" | "high" | "critical";

export const EVENT_SEVERITIES: EventSeverity[] = [
  "low",
  "medium",
  "high",
  "critical",
];

export interface SecurityEvent {
  event_id: string;
  event_type: string;
  source: string;
  severity: EventSeverity;
  description: string;
  user: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface CreateEventInput {
  event_type: string;
  source: string;
  severity: EventSeverity;
  description?: string;
  user?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  timestamp?: string | null;
  metadata?: Record<string, unknown>;
}

export interface EventQuery {
  severity?: EventSeverity | "";
  event_type?: string;
  limit?: number;
}

export interface DeleteEventResult {
  status: string;
  message: string;
  event_id: string;
}

export interface EventsHealth {
  status: string;
  service: string;
  [key: string]: unknown;
}
