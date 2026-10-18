import { useCallback, useEffect, useMemo, useState } from "react";
import { eventService } from "../services/eventService";
import { systemService } from "../services/systemService";
import { assistantService } from "../services/assistantService";
import { getErrorMessage, isAbortError } from "../utils/errors";
import type { EventSeverity, SecurityEvent } from "../types/event";
import type { HealthResponse } from "../types/api";
import type { AssistantHealth } from "../types/assistant";

export interface DashboardStats {
  total: number;
  bySeverity: Record<EventSeverity, number>;
  uniqueSources: number;
  last24h: number;
  highPriority: number;
}

export interface UseDashboardResult {
  events: SecurityEvent[];
  recentEvents: SecurityEvent[];
  alertEvents: SecurityEvent[];
  stats: DashboardStats;
  loading: boolean;
  error: string | null;
  refresh: () => void;
  systemHealth: HealthResponse | null;
  systemHealthError: string | null;
  assistantHealth: AssistantHealth | null;
  assistantHealthError: string | null;
}

const EMPTY_SEVERITY_COUNTS: Record<EventSeverity, number> = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
};

function deriveStats(events: SecurityEvent[]): DashboardStats {
  const bySeverity: Record<EventSeverity, number> = {
    ...EMPTY_SEVERITY_COUNTS,
  };

  const sources = new Set<string>();
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  let last24h = 0;

  for (const event of events) {
    if (bySeverity[event.severity] !== undefined) {
      bySeverity[event.severity] += 1;
    }

    if (event.source) {
      sources.add(event.source);
    }

    const occurred = new Date(event.timestamp).getTime();
    if (!Number.isNaN(occurred) && occurred >= oneDayAgo) {
      last24h += 1;
    }
  }

  return {
    total: events.length,
    bySeverity,
    uniqueSources: sources.size,
    last24h,
    highPriority: bySeverity.critical + bySeverity.high,
  };
}

export function useDashboard(): UseDashboardResult {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  const [systemHealth, setSystemHealth] = useState<HealthResponse | null>(null);
  const [systemHealthError, setSystemHealthError] = useState<string | null>(
    null,
  );
  const [assistantHealth, setAssistantHealth] =
    useState<AssistantHealth | null>(null);
  const [assistantHealthError, setAssistantHealthError] = useState<
    string | null
  >(null);

  const refresh = useCallback(() => {
    setRefreshToken((token) => token + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setLoading(true);
    setError(null);

    eventService
      .list({ limit: 500 }, controller.signal)
      .then((data) => {
        if (active) {
          setEvents(data);
        }
      })
      .catch((err) => {
        if (active && !isAbortError(err)) {
          setError(getErrorMessage(err));
        }
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
  }, [refreshToken]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setSystemHealthError(null);

    systemService
      .health(controller.signal)
      .then((data) => {
        if (active) {
          setSystemHealth(data);
        }
      })
      .catch((err) => {
        if (active && !isAbortError(err)) {
          setSystemHealth(null);
          setSystemHealthError(getErrorMessage(err));
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [refreshToken]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setAssistantHealthError(null);

    assistantService
      .health(controller.signal)
      .then((data) => {
        if (active) {
          setAssistantHealth(data);
        }
      })
      .catch((err) => {
        if (active && !isAbortError(err)) {
          setAssistantHealth(null);
          setAssistantHealthError(getErrorMessage(err));
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [refreshToken]);

  const stats = useMemo(() => deriveStats(events), [events]);

  const recentEvents = useMemo(
    () =>
      [...events]
        .sort(
          (a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
        )
        .slice(0, 6),
    [events],
  );

  const alertEvents = useMemo(
    () =>
      events
        .filter(
          (event) =>
            event.severity === "critical" || event.severity === "high",
        )
        .sort(
          (a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
        )
        .slice(0, 5),
    [events],
  );

  return {
    events,
    recentEvents,
    alertEvents,
    stats,
    loading,
    error,
    refresh,
    systemHealth,
    systemHealthError,
    assistantHealth,
    assistantHealthError,
  };
}
