import { useEffect, useState } from "react";
import { systemService } from "../services/systemService";
import { isAbortError } from "../utils/errors";
import type { HealthResponse } from "../types/api";

export type SystemStatus = "loading" | "online" | "offline";

export interface UseSystemHealthResult {
  status: SystemStatus;
  health: HealthResponse | null;
}

export function useSystemHealth(pollMs = 30000): UseSystemHealthResult {
  const [status, setStatus] = useState<SystemStatus>("loading");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    const check = async () => {
      try {
        const result = await systemService.health(controller.signal);
        if (active) {
          setHealth(result);
          setStatus("online");
        }
      } catch (error) {
        if (active && !isAbortError(error)) {
          setHealth(null);
          setStatus("offline");
        }
      }
    };

    void check();
    const interval = window.setInterval(() => void check(), pollMs);

    return () => {
      active = false;
      controller.abort();
      window.clearInterval(interval);
    };
  }, [pollMs]);

  return { status, health };
}
