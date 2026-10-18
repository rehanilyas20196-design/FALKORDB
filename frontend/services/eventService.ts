import { apiRequest, buildQueryString } from "./api";
import type {
  CreateEventInput,
  DeleteEventResult,
  EventQuery,
  EventsHealth,
  SecurityEvent,
} from "../types/event";

const BASE = "/events";

export const eventService = {
  list(query: EventQuery = {}, signal?: AbortSignal): Promise<SecurityEvent[]> {
    const qs = buildQueryString({
      severity: query.severity,
      event_type: query.event_type,
      limit: query.limit,
    });

    return apiRequest<SecurityEvent[]>(`${BASE}/${qs}`, { signal });
  },

  get(eventId: string, signal?: AbortSignal): Promise<SecurityEvent> {
    return apiRequest<SecurityEvent>(
      `${BASE}/${encodeURIComponent(eventId)}`,
      { signal },
    );
  },

  create(input: CreateEventInput, signal?: AbortSignal): Promise<SecurityEvent> {
    return apiRequest<SecurityEvent>(`${BASE}/`, {
      method: "POST",
      body: input,
      signal,
    });
  },

  remove(eventId: string, signal?: AbortSignal): Promise<DeleteEventResult> {
    return apiRequest<DeleteEventResult>(
      `${BASE}/${encodeURIComponent(eventId)}`,
      { method: "DELETE", signal },
    );
  },

  health(signal?: AbortSignal): Promise<EventsHealth> {
    return apiRequest<EventsHealth>(`${BASE}/health/status`, { signal });
  },
};
