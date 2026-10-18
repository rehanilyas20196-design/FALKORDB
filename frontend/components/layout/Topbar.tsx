import { Menu } from "lucide-react";
import { useSystemHealth } from "../../hooks/useSystemHealth";

interface TopbarProps {
  onMenuClick: () => void;
}

const STATUS_DOT: Record<string, string> = {
  online: "status-dot online",
  offline: "status-dot offline",
  loading: "status-dot pending",
};

const STATUS_LABEL: Record<string, string> = {
  online: "API online",
  offline: "API offline",
  loading: "Checking API",
};

export function Topbar({ onMenuClick }: TopbarProps) {
  const { status } = useSystemHealth();

  return (
    <header className="topbar">
      <button
        type="button"
        className="icon-button topbar-menu"
        onClick={onMenuClick}
        aria-label="Open navigation"
      >
        <Menu size={20} aria-hidden="true" />
      </button>

      <div className="topbar-title">Security Operations Console</div>

      <div className="topbar-actions">
        <span className="status-pill" role="status">
          <span className={STATUS_DOT[status] ?? "status-dot"} aria-hidden="true" />
          {STATUS_LABEL[status] ?? "Unknown"}
        </span>
      </div>
    </header>
  );
}
