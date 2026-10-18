export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface AssistantRequest {
  message: string;
  history?: ChatMessage[];
  context?: string | null;
}

export interface AssistantResponse {
  success: boolean;
  answer: string;
  model: string;
  source: "gemini" | "fallback" | string;
}

export interface AssistantHealth {
  success: boolean;
  assistant: string;
  gemini_configured: boolean;
  model: string;
  status: string;
}
