
"""
GraphGuard AI - Validation Utilities

Reusable validation helpers for security events, alerts, investigations,
API inputs, and configuration data.

Uses Python's standard library only.
"""

import json
import math
import re
from ipaddress import ip_address
from typing import Any
from uuid import UUID


# ---------------------------------------------------------
# Validation constants
# ---------------------------------------------------------

ALLOWED_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_ALERT_STATUSES = {
    "open",
    "investigating",
    "resolved",
    "dismissed",
}

ALLOWED_CASE_STATUSES = {
    "open",
    "in_progress",
    "pending",
    "resolved",
    "closed",
}

ALLOWED_CATEGORIES = {
    "authentication",
    "network",
    "endpoint",
    "privilege",
    "file",
    "application",
    "cloud",
    "other",
}

IDENTIFIER_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}$"
)

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


# ---------------------------------------------------------
# General value validation
# ---------------------------------------------------------

def is_empty(value: Any) -> bool:
    """Return True for None or a string containing only whitespace."""
    return value is None or (
        isinstance(value, str) and not value.strip()
    )


def validate_required(
    value: Any,
    field_name: str = "value",
) -> Any:
    """Ensure a required value is present."""
    if is_empty(value):
        raise ValueError(f"{field_name} is required.")

    return value


def validate_string(
    value: Any,
    field_name: str = "value",
    min_length: int = 0,
    max_length: int = 1000,
    allow_empty: bool = False,
    strip: bool = True,
) -> str:
    """Validate a string and enforce length limits."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")

    result = value.strip() if strip else value

    if not allow_empty and not result:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(result) < min_length:
        raise ValueError(
            f"{field_name} must contain at least "
            f"{min_length} characters."
        )

    if len(result) > max_length:
        raise ValueError(
            f"{field_name} cannot exceed {max_length} characters."
        )

    return result


def validate_integer(
    value: Any,
    field_name: str = "value",
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Validate an integer, rejecting booleans and decimal values."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer.")

    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field_name} must be an integer.")

    if isinstance(value, str):
        text = value.strip()

        if not re.fullmatch(r"[+-]?\d+", text):
            raise ValueError(f"{field_name} must be an integer.")

        try:
            result = int(text)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be an integer."
            ) from exc

    elif isinstance(value, (int, float)):
        result = int(value)

    else:
        raise ValueError(f"{field_name} must be an integer.")

    if minimum is not None and result < minimum:
        raise ValueError(
            f"{field_name} must be at least {minimum}."
        )

    if maximum is not None and result > maximum:
        raise ValueError(
            f"{field_name} cannot exceed {maximum}."
        )

    return result


def validate_number(
    value: Any,
    field_name: str = "value",
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    """Validate a finite numeric value and optional bounds."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a number.")

    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            f"{field_name} must be a number."
        ) from exc

    if not math.isfinite(result):
        raise ValueError(f"{field_name} must be finite.")

    if minimum is not None and result < minimum:
        raise ValueError(
            f"{field_name} must be at least {minimum}."
        )

    if maximum is not None and result > maximum:
        raise ValueError(
            f"{field_name} cannot exceed {maximum}."
        )

    return result


def validate_boolean(
    value: Any,
    field_name: str = "value",
) -> bool:
    """Require a real boolean value."""
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean.")

    return value


# ---------------------------------------------------------
# Security-specific validation
# ---------------------------------------------------------

def validate_severity(value: Any) -> str:
    """Validate and normalize a security severity."""
    severity = validate_string(
        value,
        field_name="severity",
        max_length=20,
    ).lower()

    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            "severity must be one of: "
            + ", ".join(sorted(ALLOWED_SEVERITIES))
        )

    return severity


def validate_alert_status(value: Any) -> str:
    """Validate an alert lifecycle status."""
    status = validate_string(
        value,
        field_name="status",
        max_length=30,
    ).lower()

    if status not in ALLOWED_ALERT_STATUSES:
        raise ValueError(
            "Invalid alert status. Allowed values: "
            + ", ".join(sorted(ALLOWED_ALERT_STATUSES))
        )

    return status


def validate_case_status(value: Any) -> str:
    """Validate a case lifecycle status."""
    status = validate_string(
        value,
        field_name="status",
        max_length=30,
    ).lower()

    if status not in ALLOWED_CASE_STATUSES:
        raise ValueError(
            "Invalid case status. Allowed values: "
            + ", ".join(sorted(ALLOWED_CASE_STATUSES))
        )

    return status


def validate_category(value: Any) -> str:
    """Validate a security event category."""
    category = validate_string(
        value,
        field_name="category",
        max_length=50,
    ).lower()

    if category not in ALLOWED_CATEGORIES:
        raise ValueError(
            "Invalid category. Allowed values: "
            + ", ".join(sorted(ALLOWED_CATEGORIES))
        )

    return category


def validate_risk_score(value: Any) -> int:
    """Validate a risk score between 0 and 100."""
    return validate_integer(
        value,
        field_name="risk_score",
        minimum=0,
        maximum=100,
    )


def validate_port(value: Any) -> int:
    """Validate a TCP or UDP port number."""
    return validate_integer(
        value,
        field_name="port",
        minimum=1,
        maximum=65535,
    )


def validate_protocol(value: Any) -> str:
    """Validate and normalize a network protocol name."""
    protocol = validate_string(
        value,
        field_name="protocol",
        max_length=20,
    ).lower()

    allowed = {
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "http",
        "https",
        "dns",
        "ssh",
        "ftp",
        "smtp",
        "other",
    }

    if protocol not in allowed:
        raise ValueError("Unsupported protocol.")

    return protocol


# ---------------------------------------------------------
# Network and identity validation
# ---------------------------------------------------------

def validate_ip_address(value: Any) -> str:
    """Validate an IPv4 or IPv6 address and return its canonical form."""
    if not isinstance(value, str):
        raise ValueError("IP address must be a string.")

    value = value.strip()

    if not value:
        raise ValueError("IP address cannot be empty.")

    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise ValueError("Invalid IPv4 or IPv6 address.") from exc


def validate_optional_ip(value: Any) -> str | None:
    """Validate an optional IP address."""
    if value is None or (
        isinstance(value, str) and not value.strip()
    ):
        return None

    return validate_ip_address(value)


def validate_email(value: Any) -> str:
    """Perform basic email address format validation."""
    email = validate_string(
        value,
        field_name="email",
        max_length=254,
    )

    if not EMAIL_PATTERN.fullmatch(email):
        raise ValueError("Invalid email address format.")

    return email


def validate_identifier(
    value: Any,
    field_name: str = "identifier",
) -> str:
    """Validate an application identifier."""
    identifier = validate_string(
        value,
        field_name=field_name,
        max_length=150,
    )

    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise ValueError(
            f"{field_name} contains unsupported characters."
        )

    return identifier


def validate_uuid(value: Any) -> str:
    """Validate a UUID and return its canonical string form."""
    if not isinstance(value, (str, UUID)):
        raise ValueError("UUID must be a string or UUID object.")

    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("Invalid UUID.") from exc


# ---------------------------------------------------------
# Pagination validation
# ---------------------------------------------------------

def validate_pagination(
    page: Any = 1,
    page_size: Any = 50,
    max_page_size: int = 200,
) -> dict[str, int]:
    """Validate pagination values and calculate the database offset."""
    page_value = validate_integer(
        page,
        field_name="page",
        minimum=1,
    )

    max_size = validate_integer(
        max_page_size,
        field_name="max_page_size",
        minimum=1,
    )

    size_value = validate_integer(
        page_size,
        field_name="page_size",
        minimum=1,
        maximum=max_size,
    )

    return {
        "page": page_value,
        "page_size": size_value,
        "offset": (page_value - 1) * size_value,
        "limit": size_value,
    }


# ---------------------------------------------------------
# Dictionary and JSON validation
# ---------------------------------------------------------

def validate_dict(
    value: Any,
    field_name: str = "value",
) -> dict[str, Any]:
    """Require a dictionary with string keys."""
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object.")

    if not all(isinstance(key, str) for key in value):
        raise ValueError(
            f"{field_name} must have string keys."
        )

    return value


def validate_json_serializable(
    value: Any,
    field_name: str = "value",
) -> Any:
    """Ensure a value can be safely encoded as JSON."""
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            f"{field_name} must contain JSON-serializable values."
        ) from exc

    return value


def validate_metadata(
    value: Any,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Validate metadata as a JSON-compatible object with a size limit."""
    metadata = validate_dict(value, field_name="metadata")
    validate_json_serializable(metadata, field_name="metadata")

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive.")

    encoded = json.dumps(
        metadata,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")

    if len(encoded) > max_bytes:
        raise ValueError(
            f"metadata cannot exceed {max_bytes} encoded bytes."
        )

    return metadata


# ---------------------------------------------------------
# Event validation
# ---------------------------------------------------------

def validate_security_event(
    event: Any,
) -> dict[str, Any]:
    """
    Validate essential security event fields.

    Returns a shallow copy with normalized core fields.
    Additional fields are preserved.
    """
    data = validate_dict(event, field_name="event")

    event_type = validate_string(
        data.get("event_type", data.get("type")),
        field_name="event_type",
        max_length=150,
    )

    result = dict(data)
    result["event_type"] = event_type
    result["severity"] = validate_severity(
        data.get("severity", "medium")
    )
    result["category"] = validate_category(
        data.get("category", "other")
    )

    if data.get("event_id") is not None:
        result["event_id"] = validate_identifier(
            data["event_id"],
            field_name="event_id",
        )

    for field in ("source_ip", "destination_ip"):
        if field in data:
            result[field] = validate_optional_ip(data[field])

    if data.get("port") is not None:
        result["port"] = validate_port(data["port"])

    if data.get("risk_score") is not None:
        result["risk_score"] = validate_risk_score(
            data["risk_score"]
        )

    if data.get("metadata") is not None:
        result["metadata"] = validate_metadata(data["metadata"])

    return result


# ---------------------------------------------------------
# Convenience checks
# ---------------------------------------------------------

def is_valid_ip(value: Any) -> bool:
    """Return True if value is a valid IP address."""
    try:
        validate_ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_email(value: Any) -> bool:
    """Return True if value has a valid basic email format."""
    try:
        validate_email(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_identifier(value: Any) -> bool:
    """Return True if value is a valid application identifier."""
    try:
        validate_identifier(value)
        return True
    except (ValueError, TypeError):
        return False
