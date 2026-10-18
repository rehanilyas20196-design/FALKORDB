import type { ReactNode } from "react";
import { Inbox } from "lucide-react";

interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: EmptyStateProps) {
  return (
    <div className="state-block">
      <div className="empty-state-icon" aria-hidden="true">
        {icon ?? <Inbox size={24} />}
      </div>
      <div className="empty-state-title">{title}</div>
      {description ? <p className="empty-state-text">{description}</p> : null}
      {action}
    </div>
  );
}
