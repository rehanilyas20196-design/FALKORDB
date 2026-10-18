import type { CSSProperties, ReactNode } from "react";

interface CardProps {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}

export function Card({ children, className, style }: CardProps) {
  return (
    <section
      className={["card", className ?? ""].filter(Boolean).join(" ")}
      style={style}
    >
      {children}
    </section>
  );
}

interface CardHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
}

export function CardHeader({ title, subtitle, action }: CardHeaderProps) {
  return (
    <div className="card-header">
      <div>
        <div className="card-title">{title}</div>
        {subtitle ? <div className="card-subtitle">{subtitle}</div> : null}
      </div>
      {action}
    </div>
  );
}

interface CardBodyProps {
  children: ReactNode;
  flush?: boolean;
}

export function CardBody({ children, flush = false }: CardBodyProps) {
  return (
    <div className={flush ? "card-body flush" : "card-body"}>{children}</div>
  );
}
