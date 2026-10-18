import { NavLink } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  Bot,
  FileClock,
  FolderSearch,
  LayoutDashboard,
  Network,
} from "lucide-react";
import type { ReactNode } from "react";

interface NavEntry {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
  badge?: string;
}

interface NavGroup {
  section: string;
  items: NavEntry[];
}

const GROUPS: NavGroup[] = [
  {
    section: "Operations",
    items: [
      {
        to: "/",
        label: "Dashboard",
        icon: <LayoutDashboard size={18} />,
        end: true,
      },
      { to: "/events", label: "Events", icon: <Activity size={18} /> },
      { to: "/alerts", label: "Alerts", icon: <AlertOctagon size={18} />, badge: "N/A" },
    ],
  },
  {
    section: "Analysis",
    items: [
      {
        to: "/investigations",
        label: "Investigations",
        icon: <FolderSearch size={18} />,
        badge: "N/A",
      },
      {
        to: "/attack-paths",
        label: "Attack Paths",
        icon: <Network size={18} />,
        badge: "N/A",
      },
    ],
  },
  {
    section: "Assistance",
    items: [
      { to: "/assistant", label: "AI Assistant", icon: <Bot size={18} /> },
      {
        to: "/audit-logs",
        label: "Audit Logs",
        icon: <FileClock size={18} />,
        badge: "N/A",
      },
    ],
  },
];

interface SlidebarProps {
  open: boolean;
  onNavigate: () => void;
}

export function Slidebar({ open, onNavigate }: SlidebarProps) {
  return (
    <nav className={open ? "sidebar open" : "sidebar"} aria-label="Primary">
      <div className="sidebar-header">
        <div className="brand">
          <img className="brand-mark" src="/logo.svg" alt="" aria-hidden="true" />
          <div className="brand-text">
            <span className="brand-name">GraphGuard AI</span>
            <span className="brand-sub">Security Console</span>
          </div>
        </div>
      </div>

      <div className="nav">
        {GROUPS.map((group) => (
          <div key={group.section}>
            <div className="nav-section">{group.section}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                className={({ isActive }) =>
                  isActive ? "nav-item active" : "nav-item"
                }
              >
                {item.icon}
                <span className="truncate">{item.label}</span>
                {item.badge ? <span className="nav-badge">{item.badge}</span> : null}
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      <div className="sidebar-footer">
        <span>GraphGuard AI · Console v1.0</span>
        <span className="faint">In-memory event store</span>
      </div>
    </nav>
  );
}
