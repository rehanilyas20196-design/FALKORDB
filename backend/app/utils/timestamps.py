
"""
GraphGuard AI - Timestamp Utilities

Provides consistent UTC timestamp handling for security events,
alerts, investigations, audit logs, and API responses.
"""

from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return the current UTC timestamp as an ISO 8601 string."""
    return utc_now().isoformat()


def timestamp_to_iso(value: datetime) -> str:
    """Convert a datetime to a normalized UTC ISO 8601 string."""
    if not isinstance(value, datetime):
        raise TypeError("value must be a datetime object.")

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat()


def parse_timestamp(value: Any) -> datetime:
    """
    Parse a datetime, ISO 8601 string, or Unix timestamp.

    Naive datetimes and ISO strings without timezone information
    are interpreted as UTC.
    """
    if isinstance(value, datetime):
        parsed = value

    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            )
        except (ValueError, OverflowError, OSError) as exc:
            raise ValueError("Invalid Unix timestamp.") from exc

    elif isinstance(value, str):
        text = value.strip()

        if not text:
            raise ValueError("Timestamp cannot be empty.")

        try:
            parsed = datetime.fromisoformat(
                text.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                "Timestamp must be a valid ISO 8601 string."
            ) from exc

    else:
        raise TypeError(
            "Timestamp must be a datetime, ISO 8601 string, "
            "or numeric Unix timestamp."
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def normalize_timestamp(value: Any = None) -> str:
    """Return a normalized UTC ISO 8601 timestamp."""
    if value is None:
        return utc_now_iso()

    return timestamp_to_iso(parse_timestamp(value))


def unix_timestamp(value: Any = None) -> float:
    """Convert a timestamp to Unix time in seconds."""
    parsed = utc_now() if value is None else parse_timestamp(value)
    return parsed.timestamp()


def timestamp_age_seconds(
    value: Any,
    now: Any = None,
) -> float:
    """
    Calculate the age of a timestamp in seconds.

    A negative result indicates that the timestamp is in the future
    relative to the reference time.
    """
    event_time = parse_timestamp(value)
    reference_time = utc_now() if now is None else parse_timestamp(now)

    return (reference_time - event_time).total_seconds()


def is_timestamp_within(
    value: Any,
    seconds: float,
    now: Any = None,
) -> bool:
    """
    Check whether a timestamp is within the previous time window.

    Future timestamps return False.
    """
    if seconds < 0:
        raise ValueError("seconds must be non-negative.")

    age = timestamp_age_seconds(value, now=now)

    return 0 <= age <= seconds


def timestamps_are_equal(
    first: Any,
    second: Any,
) -> bool:
    """Compare two timestamps after converting both to UTC."""
    return parse_timestamp(first) == parse_timestamp(second)


def timestamp_difference_seconds(
    first: Any,
    second: Any,
) -> float:
    """Return the difference in seconds: first timestamp minus second."""
    first_time = parse_timestamp(first)
    second_time = parse_timestamp(second)

    return (first_time - second_time).total_seconds()


def format_timestamp(
    value: Any = None,
    include_microseconds: bool = False,
) -> str:
    """
    Format a timestamp as a readable UTC string.

    Example:
        2026-10-18 10:30:45 UTC
    """
    parsed = utc_now() if value is None else parse_timestamp(value)

    if include_microseconds:
        return parsed.strftime("%Y-%m-%d %H:%M:%S.%f UTC")

    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")


def is_valid_timestamp(value: Any) -> bool:
    """Return True if a value can be parsed as a supported timestamp."""
    try:
        parse_timestamp(value)
        return True
    except (TypeError, ValueError):
        return False
