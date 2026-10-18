export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

export function formatRelativeTime(value: string | null | undefined): string {
  if (!value) {
    return "unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  const diffMs = Date.now() - date.getTime();
  const diffSeconds = Math.round(diffMs / 1000);

  const ranges: { limit: number; divisor: number; unit: Intl.RelativeTimeFormatUnit }[] = [
    { limit: 60, divisor: 1, unit: "second" },
    { limit: 3600, divisor: 60, unit: "minute" },
    { limit: 86400, divisor: 3600, unit: "hour" },
    { limit: 604800, divisor: 86400, unit: "day" },
    { limit: 2629800, divisor: 604800, unit: "week" },
    { limit: 31557600, divisor: 2629800, unit: "month" },
  ];

  const formatter = new Intl.RelativeTimeFormat(undefined, {
    numeric: "auto",
  });

  const absSeconds = Math.abs(diffSeconds);

  for (const range of ranges) {
    if (absSeconds < range.limit) {
      return formatter.format(
        -Math.round(diffSeconds / range.divisor),
        range.unit,
      );
    }
  }

  return formatter.format(-Math.round(diffSeconds / 31557600), "year");
}
