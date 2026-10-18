import { Bot, User } from "lucide-react";
import type { ChatMessage } from "../../types/assistant";

interface ChatMessageViewProps {
  message: ChatMessage;
  meta?: string;
}

export function ChatMessageView({ message, meta }: ChatMessageViewProps) {
  const isUser = message.role === "user";

  return (
    <div className={`chat-message ${isUser ? "user" : "assistant"}`}>
      <div className="chat-avatar" aria-hidden="true">
        {isUser ? <User size={16} /> : <Bot size={16} />}
      </div>
      <div>
        <div className="chat-bubble">{message.content}</div>
        {meta ? <div className="chat-meta">{meta}</div> : null}
      </div>
    </div>
  );
}
