import { useCallback, useEffect, useState } from "react";
import { eventService } from "../services/eventService";
import { getErrorMessage, isAbortError } from "../utils/errors";
import type {
  CreateEventInput,
  EventQuery,
  SecurityEvent,
} from "../types/event";

export interface UseEventsResult {
  events: SecurityEvent[];
  loading: boolean;
  error: string | null;
  refresh: () => void;
  createEvent: (input: CreateEventInput) => Promise<SecurityEvent>;
  deleteEvent: (eventId: string) => Promise<void>;
}

export function useEvents(query: EventQuery = {}): UseEventsResult {
  const { severity, event_type: eventType, limit } = query;

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => {
    setRefreshToken((token) => token + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setLoading(true);
    setError(null);

    eventService
      .list({ severity, event_type: eventType, limit }, controller.signal)
      .then((data) => {
        if (!active) {
          return;
        }
        setEvents(data);
      })
      .catch((err) => {
        if (!active || isAbortError(err)) {
          return;
        }
        setError(getErrorMessage(err));
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [severity, eventType, limit, refreshToken]);

  const createEvent = useCallback(
    async (input: CreateEventInput) => {
      const created = await eventService.create(input);
      refresh();
      return created;
    },
    [refresh],
  );

  const deleteEvent = useCallback(
    async (eventId: string) => {
      await eventService.remove(eventId);
      setEvents((current) =>
        current.filter((event) => event.event_id !== eventId),
      );
    },
    [],
  );

  return { events, loading, error, refresh, createEvent, deleteEvent };
}
