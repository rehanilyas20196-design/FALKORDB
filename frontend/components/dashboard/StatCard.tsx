import type { ReactNode } from "react";

type StatTone = "default" | "danger" | "warning" | "success" | "accent";

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: string;
  icon: ReactNode;
  tone?: StatTone;
}

const TONE_CLASS: Record<StatTone, string> = {
  default: "stat-icon",
  danger: "stat-icon danger",
  warning: "stat-icon warning",
  success: "stat-icon success",
  accent: "stat-icon accent",
};

export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = "default",
}: StatCardProps) {
  return (
    <div className="stat-card">
      <div className={TONE_CLASS[tone]} aria-hidden="true">
        {icon}
      </div>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        {hint ? <div className="stat-hint">{hint}</div> : null}
      </div>
    </div>
  );
}
