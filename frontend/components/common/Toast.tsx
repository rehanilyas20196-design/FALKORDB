import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
  title?: string;
}

interface ToastContextValue {
  push: (kind: ToastKind, message: string, title?: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

let nextId = 0;

function ToastIcon({ kind }: { kind: ToastKind }) {
  if (kind === "success") {
    return <CheckCircle2 size={18} aria-hidden="true" />;
  }

  if (kind === "error") {
    return <AlertTriangle size={18} aria-hidden="true" />;
  }

  return <Info size={18} aria-hidden="true" />;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const remove = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string, title?: string) => {
      nextId += 1;
      const id = nextId;
      setItems((current) => [...current, { id, kind, message, title }]);
      window.setTimeout(() => remove(id), 5000);
    },
    [remove],
  );

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-viewport" aria-live="polite" aria-atomic="false">
        {items.map((item) => (
          <div key={item.id} className={`toast ${item.kind}`} role="status">
            <span className="toast-icon">
              <ToastIcon kind={item.kind} />
            </span>
            <div className="toast-body">
              {item.title ? (
                <div className="toast-title">{item.title}</div>
              ) : null}
              <div className="toast-text">{item.message}</div>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);

  if (context === null) {
    throw new Error("useToast must be used within a ToastProvider.");
  }

  return context;
}
