import type { ReactNode } from "react";

type BadgeVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "neutral"
  | "info";

interface BadgeProps {
  variant?: BadgeVariant;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function Badge({
  variant = "neutral",
  icon,
  children,
  className,
}: BadgeProps) {
  const classes = ["badge", `badge-${variant}`, className ?? ""]
    .filter(Boolean)
    .join(" ");

  return (
    <span className={classes}>
      {icon}
      {children}
    </span>
  );
}
