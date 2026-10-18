import type { FormEvent, KeyboardEvent } from "react";
import { SendHorizontal } from "lucide-react";
import { Button } from "../common/Button";

interface ChatInputProps {
  value: string;
  sending: boolean;
  disabled?: boolean;
  onChange: (value: string) => void;
  onSend: () => void;
}

export function ChatInput({
  value,
  sending,
  disabled = false,
  onChange,
  onSend,
}: ChatInputProps) {
  const canSend = value.trim().length > 0 && !sending && !disabled;

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (canSend) {
      onSend();
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      if (canSend) {
        onSend();
      }
    }
  };

  return (
    <form className="chat-composer" onSubmit={handleSubmit}>
      <label className="sr-only" htmlFor="assistant-message">
        Message
      </label>
      <textarea
        id="assistant-message"
        className="textarea"
        value={value}
        placeholder="Ask about alerts, logs, or incident response… (Enter to send, Shift+Enter for newline)"
        maxLength={4000}
        disabled={disabled || sending}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={handleKeyDown}
      />
      <Button
        type="submit"
        variant="primary"
        loading={sending}
        disabled={!canSend}
        icon={<SendHorizontal size={16} aria-hidden="true" />}
      >
        Send
      </Button>
    </form>
  );
}
