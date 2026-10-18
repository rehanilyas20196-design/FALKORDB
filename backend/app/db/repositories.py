
"""
GraphGuard AI - FalkorDB repositories.

Repositories provide reusable database operations for events,
alerts, cases, and graph investigations.

Note:
The queries assume the node labels and properties defined in
backend/app/db/queries.py.
"""

from typing import Any

from backend.app.db.falkordb import db_manager
from backend.app.db import queries


class RepositoryError(Exception):
    """Raised when a repository operation fails."""


def _execute(
    query: str,
    parameters: dict[str, Any] | None = None,
) -> list[Any]:
    """Execute a Cypher query and return its result rows."""
    try:
        graph = db_manager.get_graph()
        result = graph.query(query, parameters or {})
        return result.result_set or []
    except Exception as exc:
        raise RepositoryError(
            f"FalkorDB query failed: {exc}"
        ) from exc


def _properties(value: Any) -> dict[str, Any]:
    """Convert a FalkorDB node or a dictionary to a plain dictionary."""
    if isinstance(value, dict):
        return dict(value)

    if value is None:
        return {}

    # FalkorDB nodes commonly expose their properties this way.
    props = getattr(value, "properties", None)
    if isinstance(props, dict):
        return dict(props)

    # Some client objects expose properties through a method.
    if callable(props):
        try:
            result = props()
            if isinstance(result, dict):
                return dict(result)
        except Exception:
            pass

    return {"value": str(value)}


def _first_column(rows: list[Any]) -> list[Any]:
    """Return the first value from each result row."""
    values = []

    for row in rows:
        if isinstance(row, (list, tuple)):
            if row:
                values.append(row[0])
        else:
            values.append(row)

    return values


def _records(rows: list[Any], columns: list[str]) -> list[dict[str, Any]]:
    """Convert result rows into dictionaries using known column names."""
    records = []

    for row in rows:
        if isinstance(row, dict):
            records.append(row)
            continue

        if isinstance(row, (list, tuple)):
            records.append({
                columns[index]: value
                for index, value in enumerate(row)
                if index < len(columns)
            })
        else:
            records.append({"value": row})

    return records


def _positive_limit(limit: int, maximum: int = 500) -> int:
    """Validate and cap a requested result limit."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")

    return min(limit, maximum)


# ==================================================
# EVENT REPOSITORY
# ==================================================

class EventRepository:
    """Database operations for security events."""

    @staticmethod
    def create(event: dict[str, Any]) -> dict[str, Any]:
        required = ("event_id", "event_type", "source", "severity")
        missing = [key for key in required if key not in event]

        if missing:
            raise ValueError(
                "Missing event fields: " + ", ".join(missing)
            )

        parameters = {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "source": event["source"],
            "severity": event["severity"],
            "description": event.get("description", ""),
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "timestamp": event.get("timestamp"),
        }

        rows = _execute(queries.CREATE_EVENT, parameters)

        if not rows:
            raise RepositoryError("Event creation returned no result")

        return _properties(rows[0][0])

    @staticmethod
    def get_by_id(event_id: str) -> dict[str, Any] | None:
        rows = _execute(
            queries.GET_EVENT_BY_ID,
            {"event_id": event_id},
        )
        values = _first_column(rows)

        return _properties(values[0]) if values else None

    @staticmethod
    def list_all(limit: int = 100) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_EVENTS,
            {"limit": _positive_limit(limit)},
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def list_by_severity(
        severity: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_EVENTS_BY_SEVERITY,
            {
                "severity": severity,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def list_by_type(
        event_type: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_EVENTS_BY_TYPE,
            {
                "event_type": event_type,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def count() -> int:
        rows = _execute(queries.COUNT_EVENTS)
        records = _records(rows, ["total_events"])

        return int(records[0]["total_events"]) if records else 0

    @staticmethod
    def list_by_user(
        username: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.GET_EVENTS_BY_USER,
            {
                "username": username,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def list_by_source_ip(
        source_ip: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.GET_EVENTS_BY_SOURCE_IP,
            {
                "source_ip": source_ip,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def list_by_destination_ip(
        destination_ip: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.GET_EVENTS_BY_DESTINATION_IP,
            {
                "destination_ip": destination_ip,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]


# ==================================================
# ALERT REPOSITORY
# ==================================================

class AlertRepository:
    """Database operations for security alerts."""

    @staticmethod
    def create(alert: dict[str, Any]) -> dict[str, Any]:
        required = ("alert_id", "title", "severity")
        missing = [key for key in required if key not in alert]

        if missing:
            raise ValueError(
                "Missing alert fields: " + ", ".join(missing)
            )

        parameters = {
            "alert_id": alert["alert_id"],
            "title": alert["title"],
            "description": alert.get("description", ""),
            "severity": alert["severity"],
            "status": alert.get("status", "open"),
            "risk_score": alert.get("risk_score", 0),
            "created_at": alert.get("created_at"),
        }

        rows = _execute(queries.CREATE_ALERT, parameters)

        if not rows:
            raise RepositoryError("Alert creation returned no result")

        return _properties(rows[0][0])

    @staticmethod
    def get_by_id(alert_id: str) -> dict[str, Any] | None:
        rows = _execute(
            queries.GET_ALERT_BY_ID,
            {"alert_id": alert_id},
        )
        values = _first_column(rows)

        return _properties(values[0]) if values else None

    @staticmethod
    def list_all(limit: int = 100) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_ALERTS,
            {"limit": _positive_limit(limit)},
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def list_open(limit: int = 100) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_OPEN_ALERTS,
            {"limit": _positive_limit(limit)},
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def update_status(
        alert_id: str,
        status: str,
        updated_at: str,
    ) -> dict[str, Any] | None:
        allowed_statuses = {
            "open",
            "investigating",
            "resolved",
            "closed",
        }

        if status not in allowed_statuses:
            raise ValueError(
                f"Invalid status. Allowed values: "
                f"{', '.join(sorted(allowed_statuses))}"
            )

        rows = _execute(
            queries.UPDATE_ALERT_STATUS,
            {
                "alert_id": alert_id,
                "status": status,
                "updated_at": updated_at,
            },
        )
        values = _first_column(rows)

        return _properties(values[0]) if values else None

    @staticmethod
    def link_to_event(
        alert_id: str,
        event_id: str,
    ) -> bool:
        rows = _execute(
            queries.LINK_ALERT_TO_EVENT,
            {
                "alert_id": alert_id,
                "event_id": event_id,
            },
        )
        return bool(rows)


# ==================================================
# CASE REPOSITORY
# ==================================================

class CaseRepository:
    """Database operations for investigation cases."""

    @staticmethod
    def create(case: dict[str, Any]) -> dict[str, Any]:
        required = ("case_id", "title")
        missing = [key for key in required if key not in case]

        if missing:
            raise ValueError(
                "Missing case fields: " + ", ".join(missing)
            )

        rows = _execute(
            queries.CREATE_CASE,
            {
                "case_id": case["case_id"],
                "title": case["title"],
                "description": case.get("description", ""),
                "status": case.get("status", "open"),
                "priority": case.get("priority", "medium"),
                "created_at": case.get("created_at"),
            },
        )

        if not rows:
            raise RepositoryError("Case creation returned no result")

        return _properties(rows[0][0])

    @staticmethod
    def get_by_id(case_id: str) -> dict[str, Any] | None:
        rows = _execute(
            queries.GET_CASE_BY_ID,
            {"case_id": case_id},
        )
        values = _first_column(rows)

        return _properties(values[0]) if values else None

    @staticmethod
    def list_all(limit: int = 100) -> list[dict[str, Any]]:
        rows = _execute(
            queries.LIST_CASES,
            {"limit": _positive_limit(limit)},
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def link_to_alert(
        case_id: str,
        alert_id: str,
    ) -> bool:
        rows = _execute(
            queries.LINK_CASE_TO_ALERT,
            {
                "case_id": case_id,
                "alert_id": alert_id,
            },
        )
        return bool(rows)


# ==================================================
# GRAPH REPOSITORY
# ==================================================

class GraphRepository:
    """Read operations for graph exploration and investigation."""

    @staticmethod
    def count_nodes() -> int:
        rows = _execute(queries.COUNT_NODES)
        records = _records(rows, ["total_nodes"])

        return int(records[0]["total_nodes"]) if records else 0

    @staticmethod
    def count_relationships() -> int:
        rows = _execute(queries.COUNT_RELATIONSHIPS)
        records = _records(rows, ["total_relationships"])

        return (
            int(records[0]["total_relationships"])
            if records
            else 0
        )

    @staticmethod
    def get_nodes(limit: int = 100) -> list[Any]:
        rows = _execute(
            queries.GET_GRAPH_NODES,
            {"limit": _positive_limit(limit)},
        )
        return _first_column(rows)

    @staticmethod
    def get_relationships(limit: int = 100) -> list[dict[str, Any]]:
        rows = _execute(
            queries.GET_GRAPH_RELATIONSHIPS,
            {"limit": _positive_limit(limit)},
        )
        return _records(rows, ["source", "relationship", "target"])

    @staticmethod
    def get_neighbors(
        node_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.GET_NODE_NEIGHBORS,
            {
                "node_id": node_id,
                "limit": _positive_limit(limit),
            },
        )
        return _records(rows, ["node", "relationship", "neighbor"])

    @staticmethod
    def get_node(node_id: str) -> Any | None:
        rows = _execute(
            queries.GET_NODE_BY_ID,
            {"node_id": node_id},
        )
        values = _first_column(rows)

        return values[0] if values else None

    @staticmethod
    def find_attack_paths(
        source_id: int,
        target_id: int,
        limit: int = 20,
    ) -> list[Any]:
        if isinstance(source_id, bool) or not isinstance(source_id, int):
            raise ValueError("source_id must be an integer")

        if isinstance(target_id, bool) or not isinstance(target_id, int):
            raise ValueError("target_id must be an integer")

        rows = _execute(
            queries.FIND_ATTACK_PATHS,
            {
                "source_id": source_id,
                "target_id": target_id,
                "limit": _positive_limit(limit, maximum=100),
            },
        )
        return _first_column(rows)


# ==================================================
# DETECTION REPOSITORY
# ==================================================

class DetectionRepository:
    """Database queries used by detection and investigation services."""

    @staticmethod
    def find_failed_logins(
        start_time: Any,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.DETECT_FAILED_LOGINS,
            {
                "start_time": start_time,
                "limit": _positive_limit(limit),
            },
        )
        return [_properties(value) for value in _first_column(rows)]

    @staticmethod
    def find_repeated_failed_logins(
        start_time: Any,
        threshold: int = 5,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise ValueError("threshold must be a positive integer")

        rows = _execute(
            queries.DETECT_REPEATED_FAILED_LOGINS_BY_USER,
            {
                "start_time": start_time,
                "threshold": threshold,
                "limit": _positive_limit(limit),
            },
        )
        return _records(
            rows,
            ["username", "source_ip", "failed_attempts"],
        )

    @staticmethod
    def find_privilege_escalation(
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = _execute(
            queries.DETECT_PRIVILEGE_ESCALATION,
            {"limit": _positive_limit(limit)},
        )
        return [_properties(value) for value in _first_column(rows)]


# ==================================================
# CONVENIENT REPOSITORY INSTANCES
# ==================================================

event_repository = EventRepository()
alert_repository = AlertRepository()
case_repository = CaseRepository()
graph_repository = GraphRepository()
detection_repository = DetectionRepository()
