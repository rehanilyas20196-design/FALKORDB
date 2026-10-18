interface LoadingSpinnerProps {
  size?: "sm" | "md";
  label?: string;
}

export function LoadingSpinner({
  size = "md",
  label = "Loading",
}: LoadingSpinnerProps) {
  return (
    <span
      className={size === "sm" ? "spinner sm" : "spinner"}
      role="status"
      aria-label={label}
    />
  );
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="state-block">
      <LoadingSpinner />
      <span className="muted">{label}</span>
    </div>
  );
}
