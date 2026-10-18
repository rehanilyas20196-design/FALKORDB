import { apiRequest } from "./api";
import type {
  AssistantHealth,
  AssistantRequest,
  AssistantResponse,
} from "../types/assistant";

const BASE = "/assistant";

export const assistantService = {
  health(signal?: AbortSignal): Promise<AssistantHealth> {
    return apiRequest<AssistantHealth>(`${BASE}/health`, { signal });
  },

  chat(
    request: AssistantRequest,
    signal?: AbortSignal,
  ): Promise<AssistantResponse> {
    return apiRequest<AssistantResponse>(`${BASE}/chat`, {
      method: "POST",
      body: {
        message: request.message,
        history: request.history ?? [],
        context: request.context ?? null,
      },
      signal,
    });
  },
};
