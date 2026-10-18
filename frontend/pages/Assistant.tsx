import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card, CardBody, CardHeader } from "../components/common/Card";
import { Badge } from "../components/common/Badge";
import { Button } from "../components/common/Button";
import { ErrorMessage } from "../components/common/ErrorMessage";
import { useToast } from "../components/common/Toast";
import { ChatWindow } from "../components/assistant/ChatWindow";
import { ChatInput } from "../components/assistant/ChatInput";
import { assistantService } from "../services/assistantService";
import { getErrorMessage, isAbortError } from "../utils/errors";
import type { AssistantHealth, ChatMessage } from "../types/assistant";

const SUGGESTIONS = [
  "Explain the difference between an alert and an incident.",
  "What are common indicators of a brute-force attack?",
  "How should I triage a high severity authentication failure?",
  "Summarise a safe incident response checklist.",
];

const WELCOME: ChatMessage = {
  role: "assistant",
  content:
    "Hello. I am the GraphGuard AI assistant. Ask me about security alerts, logs, attack patterns, or incident response procedures.",
};

export function Assistant() {
  const toast = useToast();

  const [messages, setMessages] = useState<ChatMessage[]>([WELCOME]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);

  const [health, setHealth] = useState<AssistantHealth | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthToken, setHealthToken] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setHealthLoading(true);
    setHealthError(null);

    assistantService
      .health(controller.signal)
      .then((result) => {
        if (active) {
          setHealth(result);
        }
      })
      .catch((error) => {
        if (active && !isAbortError(error)) {
          setHealth(null);
          setHealthError(getErrorMessage(error));
        }
      })
      .finally(() => {
        if (active) {
          setHealthLoading(false);
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [healthToken]);

  const loadHealth = () => setHealthToken((token) => token + 1);

  const handleSend = async () => {
    const text = input.trim();
    if (text.length === 0 || sending) {
      return;
    }

    const history = messages.slice(-20);
    const userMessage: ChatMessage = { role: "user", content: text };
    setMessages((current) => [...current, userMessage]);
    setInput("");
    setSending(true);
    setSendError(null);

    try {
      const response = await assistantService.chat({
        message: text,
        history,
      });

      setMessages((current) => [
        ...current,
        { role: "assistant", content: response.answer },
      ]);

      if (response.source === "fallback") {
        toast.push(
          "info",
          "Gemini is not configured on the backend; a fallback response was returned.",
          "Fallback mode",
        );
      }
    } catch (error) {
      const message = getErrorMessage(error);
      setSendError(message);
      toast.push("error", message, "Assistant request failed");
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <PageHeader
        title="AI Assistant"
        subtitle="Cyber-security assistant powered by the backend assistant API. Credentials stay server-side."
        actions={
          <Button
            variant="secondary"
            icon={<RefreshCw size={16} aria-hidden="true" />}
            onClick={loadHealth}
            loading={healthLoading}
          >
            Refresh status
          </Button>
        }
      />

      <Card style={{ marginBottom: 20 }}>
        <CardHeader
          title="Assistant service"
          action={
            health ? (
              <Badge variant={health.gemini_configured ? "low" : "medium"}>
                {health.status}
              </Badge>
            ) : healthError ? (
              <Badge variant="critical">unreachable</Badge>
            ) : (
              <Badge variant="neutral">checking</Badge>
            )
          }
        />
        <CardBody>
          {healthError ? (
            <ErrorMessage
              title="Assistant service unreachable"
              message={healthError}
              onRetry={loadHealth}
            />
          ) : health ? (
            <div className="row">
              <span className="muted">
                Model: <span className="mono">{health.model}</span>
              </span>
              <span className="faint">·</span>
              <span className="muted">
                {health.gemini_configured
                  ? "Gemini is configured."
                  : "Gemini is not configured; responses fall back."}
              </span>
            </div>
          ) : (
            <div className="row">
              <span className="spinner sm" aria-hidden="true" />
              <span className="muted">Checking assistant configuration…</span>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Conversation"
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setMessages([WELCOME]);
                setSendError(null);
              }}
            >
              Clear
            </Button>
          }
        />
        <div className="chat-shell">
          <ChatWindow messages={messages} pending={sending} />

          {sendError ? (
            <div style={{ padding: "0 16px 12px" }}>
              <ErrorMessage title="Message failed" message={sendError} />
            </div>
          ) : null}

          <div className="chat-suggestions">
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                className="suggestion-chip"
                disabled={sending}
                onClick={() => setInput(suggestion)}
              >
                {suggestion}
              </button>
            ))}
          </div>

          <ChatInput
            value={input}
            sending={sending}
            onChange={setInput}
            onSend={handleSend}
          />
        </div>
      </Card>
    </>
  );
}
