import { AlertTriangle } from "lucide-react";
import { Button } from "./Button";

interface ErrorMessageProps {
  message: string;
  title?: string;
  onRetry?: () => void;
}

export function ErrorMessage({
  message,
  title = "Something went wrong",
  onRetry,
}: ErrorMessageProps) {
  return (
    <div className="error-message" role="alert">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <div className="error-title">{title}</div>
        <div>{message}</div>
        {onRetry ? (
          <div className="error-actions">
            <Button size="sm" variant="secondary" onClick={onRetry}>
              Try again
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
