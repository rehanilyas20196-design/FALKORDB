import { useEffect, useRef } from "react";
import { Bot } from "lucide-react";
import { ChatMessageView } from "./ChatMessage";
import type { ChatMessage } from "../../types/assistant";

interface ChatWindowProps {
  messages: ChatMessage[];
  pending: boolean;
}

export function ChatWindow({ messages, pending }: ChatWindowProps) {
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, pending]);

  return (
    <div className="chat-scroll" role="log" aria-live="polite">
      {messages.map((message, index) => (
        <ChatMessageView key={index} message={message} />
      ))}

      {pending ? (
        <div className="chat-message assistant">
          <div className="chat-avatar" aria-hidden="true">
            <Bot size={16} />
          </div>
          <div className="chat-bubble">
            <span className="spinner sm" aria-hidden="true" />
          </div>
        </div>
      ) : null}

      <div ref={endRef} />
    </div>
  );
}
