
"""
GraphGuard AI — Demo Event Generator

Generates synthetic security events for local development and testing.

Output:
    backend/data/sample_events.json

Run from the project root:
    python scripts/generate_demo_events.py

Optional:
    python scripts/generate_demo_events.py --count 100
    python scripts/generate_demo_events.py --output backend/data/demo_events.json
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "backend" / "data" / "sample_events.json"

USERS = [
    "admin",
    "analyst",
    "developer",
    "service_account",
    "finance_user",
    "guest",
]

HOSTS = [
    "workstation-01",
    "workstation-02",
    "dev-server-01",
    "web-server-01",
    "database-server-01",
    "jump-host-01",
]

INTERNAL_IPS = [
    "10.0.0.10",
    "10.0.0.15",
    "10.0.0.20",
    "192.168.1.10",
    "192.168.1.25",
]

EXTERNAL_IPS = [
    "198.51.100.23",
    "203.0.113.42",
    "203.0.113.77",
    "198.51.100.88",
]

EVENT_TYPES = [
    "login_success",
    "login_failure",
    "privilege_escalation",
    "file_access",
    "process_execution",
    "network_connection",
    "authentication_failure",
    "account_creation",
]

SEVERITIES = ["low", "medium", "high", "critical"]

# Reserved documentation IP addresses are used so that these events
# cannot accidentally identify real external infrastructure.
SUSPICIOUS_SCENARIOS = [
    {
        "event_type": "login_failure",
        "severity": "high",
        "description": "Repeated failed authentication attempts",
        "source": "authentication",
        "user": "admin",
    },
    {
        "event_type": "privilege_escalation",
        "severity": "critical",
        "description": "Unexpected privilege escalation",
        "source": "endpoint",
        "user": "service_account",
    },
    {
        "event_type": "network_connection",
        "severity": "high",
        "description": "Connection to a flagged external test address",
        "source": "network",
        "user": "developer",
    },
    {
        "event_type": "account_creation",
        "severity": "high",
        "description": "Unexpected account creation",
        "source": "identity",
        "user": "admin",
    },
]


def utc_timestamp(offset_minutes: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp."""
    timestamp = datetime.now(timezone.utc) - timedelta(
        minutes=offset_minutes
    )
    return timestamp.isoformat().replace("+00:00", "Z")


def make_event(
    index: int,
    *,
    suspicious: bool = False,
    scenario: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create one synthetic security event."""
    scenario = scenario or {}

    user = scenario.get("user", random.choice(USERS))
    host = random.choice(HOSTS)
    event_type = scenario.get("event_type", random.choice(EVENT_TYPES))
    severity = scenario.get("severity", random.choices(
        SEVERITIES,
        weights=[45, 30, 20, 5],
        k=1,
    )[0])

    source_ip = random.choice(
        EXTERNAL_IPS if suspicious and event_type == "network_connection"
        else INTERNAL_IPS
    )

    event_id = str(uuid.uuid4())

    event = {
        "id": event_id,
        "event_type": event_type,
        "timestamp": utc_timestamp(random.randint(0, 1440)),
        "severity": severity,
        "source": scenario.get("source", "endpoint"),
        "description": scenario.get(
            "description",
            f"Synthetic {event_type.replace('_', ' ')} event",
        ),
        "user": user,
        "username": user,
        "hostname": host,
        "source_ip": source_ip,
        "destination_ip": (
            random.choice(EXTERNAL_IPS)
            if event_type == "network_connection"
            else random.choice(INTERNAL_IPS)
        ),
        "suspicious": suspicious,
        "tags": ["demo", "synthetic"] + (
            ["suspicious"] if suspicious else []
        ),
        "metadata": {
            "generator": "GraphGuard AI",
            "synthetic": True,
            "scenario": (
                "suspicious_test" if suspicious else "normal_activity"
            ),
            "sequence": index,
        },
    }

    if event_type == "process_execution":
        event["process_name"] = random.choice([
            "python.exe",
            "node.exe",
            "powershell.exe",
            "nginx",
            "sshd",
        ])

    if event_type == "file_access":
        event["file_path"] = random.choice([
            "/var/log/auth.log",
            "/app/config/settings.json",
            "/srv/application/data.db",
            "C:\\Logs\\application.log",
        ])

    if event_type == "network_connection":
        event["protocol"] = random.choice(["TCP", "UDP", "HTTPS"])
        event["destination_port"] = random.choice([443, 80, 8080, 5432])

    return event


def generate_events(
    count: int,
    suspicious_ratio: float = 0.15,
    seed: int | None = 42,
) -> list[dict[str, Any]]:
    """Generate reproducible synthetic events."""
    if count < 1:
        raise ValueError("count must be at least 1")

    if not 0 <= suspicious_ratio <= 1:
        raise ValueError("suspicious_ratio must be between 0 and 1")

    random.seed(seed)

    suspicious_count = round(count * suspicious_ratio)
    events: list[dict[str, Any]] = []

    for index in range(count):
        suspicious = index < suspicious_count

        scenario = (
            SUSPICIOUS_SCENARIOS[
                index % len(SUSPICIOUS_SCENARIOS)
            ]
            if suspicious
            else None
        )

        events.append(
            make_event(
                index=index + 1,
                suspicious=suspicious,
                scenario=scenario,
            )
        )

    random.shuffle(events)
    return events


def write_events(
    events: list[dict[str, Any]],
    output_path: Path,
) -> None:
    """Write generated events as a JSON array."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic GraphGuard AI security events."
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of events to generate (default: 100).",
    )

    parser.add_argument(
        "--suspicious-ratio",
        type=float,
        default=0.15,
        help="Fraction of suspicious test events (default: 0.15).",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output JSON file path.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible generation.",
    )

    args = parser.parse_args()

    try:
        events = generate_events(
            count=args.count,
            suspicious_ratio=args.suspicious_ratio,
            seed=args.seed,
        )

        output_path = (
            args.output
            if args.output.is_absolute()
            else PROJECT_ROOT / args.output
        )

        write_events(events, output_path)

        suspicious_count = sum(
            event["suspicious"] for event in events
        )

        print("GraphGuard AI demo events generated successfully.")
        print(f"Total events:      {len(events)}")
        print(f"Suspicious events: {suspicious_count}")
        print(f"Normal events:     {len(events) - suspicious_count}")
        print(f"Output file:       {output_path.resolve()}")

    except (OSError, ValueError) as exc:
        raise SystemExit(f"Error generating events: {exc}") from exc


if __name__ == "__main__":
    main()
