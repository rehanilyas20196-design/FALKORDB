import { apiRequest } from "./api";
import type {
  ApiInfo,
  HealthResponse,
  ReadinessResponse,
} from "../types/api";

export const systemService = {
  health(signal?: AbortSignal): Promise<HealthResponse> {
    return apiRequest<HealthResponse>("/health", {
      signal,
      useApiPrefix: false,
    });
  },

  readiness(signal?: AbortSignal): Promise<ReadinessResponse> {
    return apiRequest<ReadinessResponse>("/ready", {
      signal,
      useApiPrefix: false,
    });
  },

  info(signal?: AbortSignal): Promise<ApiInfo> {
    return apiRequest<ApiInfo>("/info", { signal });
  },
};
