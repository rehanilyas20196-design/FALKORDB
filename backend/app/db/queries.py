
"""
Centralized Cypher queries for GraphGuard AI.

These queries assume the graph uses nodes such as Event, Alert,
User, Host, and IP. Adjust labels and property names to match
the actual schema in database/init.cypher.
"""

from typing import Any


# --------------------------------------------------
# GRAPH OVERVIEW
# --------------------------------------------------

COUNT_NODES = """
MATCH (n)
RETURN count(n) AS total_nodes
"""

COUNT_RELATIONSHIPS = """
MATCH ()-[r]->()
RETURN count(r) AS total_relationships
"""

GET_GRAPH_NODES = """
MATCH (n)
RETURN n
LIMIT $limit
"""

GET_GRAPH_RELATIONSHIPS = """
MATCH (source)-[r]->(target)
RETURN source, r, target
LIMIT $limit
"""


# --------------------------------------------------
# NODE LOOKUPS
# --------------------------------------------------

GET_NODE_BY_ID = """
MATCH (n)
WHERE toString(id(n)) = $node_id
RETURN n
LIMIT 1
"""

GET_NODE_NEIGHBORS = """
MATCH (n)-[r]-(neighbor)
WHERE toString(id(n)) = $node_id
RETURN n, r, neighbor
LIMIT $limit
"""

GET_NODE_OUTGOING_RELATIONSHIPS = """
MATCH (n)-[r]->(neighbor)
WHERE toString(id(n)) = $node_id
RETURN n, r, neighbor
LIMIT $limit
"""

GET_NODE_INCOMING_RELATIONSHIPS = """
MATCH (neighbor)-[r]->(n)
WHERE toString(id(n)) = $node_id
RETURN neighbor, r, n
LIMIT $limit
"""


# --------------------------------------------------
# EVENT QUERIES
# --------------------------------------------------

CREATE_EVENT = """
CREATE (e:Event {
    event_id: $event_id,
    event_type: $event_type,
    source: $source,
    severity: $severity,
    description: $description,
    username: $username,
    source_ip: $source_ip,
    destination_ip: $destination_ip,
    timestamp: $timestamp
})
RETURN e
"""

GET_EVENT_BY_ID = """
MATCH (e:Event {event_id: $event_id})
RETURN e
LIMIT 1
"""

LIST_EVENTS = """
MATCH (e:Event)
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

LIST_EVENTS_BY_SEVERITY = """
MATCH (e:Event {severity: $severity})
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

LIST_EVENTS_BY_TYPE = """
MATCH (e:Event {event_type: $event_type})
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

COUNT_EVENTS = """
MATCH (e:Event)
RETURN count(e) AS total_events
"""


# --------------------------------------------------
# ALERT QUERIES
# --------------------------------------------------

CREATE_ALERT = """
CREATE (a:Alert {
    alert_id: $alert_id,
    title: $title,
    description: $description,
    severity: $severity,
    status: $status,
    risk_score: $risk_score,
    created_at: $created_at
})
RETURN a
"""

GET_ALERT_BY_ID = """
MATCH (a:Alert {alert_id: $alert_id})
RETURN a
LIMIT 1
"""

LIST_ALERTS = """
MATCH (a:Alert)
RETURN a
ORDER BY a.created_at DESC
LIMIT $limit
"""

LIST_OPEN_ALERTS = """
MATCH (a:Alert)
WHERE a.status = 'open'
RETURN a
ORDER BY a.created_at DESC
LIMIT $limit
"""

UPDATE_ALERT_STATUS = """
MATCH (a:Alert {alert_id: $alert_id})
SET a.status = $status,
    a.updated_at = $updated_at
RETURN a
"""

LINK_ALERT_TO_EVENT = """
MATCH (a:Alert {alert_id: $alert_id})
MATCH (e:Event {event_id: $event_id})
MERGE (a)-[:TRIGGERED_BY]->(e)
RETURN a, e
"""


# --------------------------------------------------
# USER AND HOST INVESTIGATION
# --------------------------------------------------

GET_EVENTS_BY_USER = """
MATCH (e:Event)
WHERE e.username = $username
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

GET_EVENTS_BY_SOURCE_IP = """
MATCH (e:Event)
WHERE e.source_ip = $source_ip
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

GET_EVENTS_BY_DESTINATION_IP = """
MATCH (e:Event)
WHERE e.destination_ip = $destination_ip
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

GET_EVENTS_IN_TIME_RANGE = """
MATCH (e:Event)
WHERE e.timestamp >= $start_time
  AND e.timestamp <= $end_time
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""


# --------------------------------------------------
# BRUTE-FORCE DETECTION
# --------------------------------------------------

DETECT_FAILED_LOGINS = """
MATCH (e:Event)
WHERE toLower(e.event_type) CONTAINS 'login'
  AND (
      toLower(e.event_type) CONTAINS 'fail'
      OR toLower(e.description) CONTAINS 'failed'
  )
  AND e.timestamp >= $start_time
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

DETECT_REPEATED_FAILED_LOGINS_BY_USER = """
MATCH (e:Event)
WHERE toLower(e.event_type) CONTAINS 'login'
  AND (
      toLower(e.event_type) CONTAINS 'fail'
      OR toLower(e.description) CONTAINS 'failed'
  )
  AND e.timestamp >= $start_time
WITH e.username AS username,
     e.source_ip AS source_ip,
     count(e) AS failed_attempts
WHERE failed_attempts >= $threshold
RETURN username, source_ip, failed_attempts
ORDER BY failed_attempts DESC
LIMIT $limit
"""


# --------------------------------------------------
# PRIVILEGE ESCALATION
# --------------------------------------------------

DETECT_PRIVILEGE_ESCALATION = """
MATCH (e:Event)
WHERE toLower(e.event_type) CONTAINS 'privilege'
   OR toLower(e.event_type) CONTAINS 'escalation'
   OR toLower(e.description) CONTAINS 'privilege escalation'
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""


# --------------------------------------------------
# SUSPICIOUS NETWORK ACTIVITY
# --------------------------------------------------

GET_EVENTS_FOR_IP = """
MATCH (e:Event)
WHERE e.source_ip = $ip OR e.destination_ip = $ip
RETURN e
ORDER BY e.timestamp DESC
LIMIT $limit
"""

GET_NETWORK_CONNECTIONS = """
MATCH (source)-[r]->(target)
WHERE source:Host OR source:IP
RETURN source, r, target
LIMIT $limit
"""


# --------------------------------------------------
# ATTACK-PATH EXPLORATION
# --------------------------------------------------

FIND_ATTACK_PATHS = """
MATCH p = (source)-[*1..5]->(target)
WHERE id(source) = $source_id
  AND id(target) = $target_id
RETURN p
LIMIT $limit
"""

FIND_PATHS_FROM_IP_TO_HOST = """
MATCH p = (source:IP)-[*1..5]->(target:Host)
WHERE source.address = $ip_address
RETURN p
LIMIT $limit
"""


# --------------------------------------------------
# CASE QUERIES
# --------------------------------------------------

CREATE_CASE = """
CREATE (c:Case {
    case_id: $case_id,
    title: $title,
    description: $description,
    status: $status,
    priority: $priority,
    created_at: $created_at
})
RETURN c
"""

GET_CASE_BY_ID = """
MATCH (c:Case {case_id: $case_id})
RETURN c
LIMIT 1
"""

LIST_CASES = """
MATCH (c:Case)
RETURN c
ORDER BY c.created_at DESC
LIMIT $limit
"""

LINK_CASE_TO_ALERT = """
MATCH (c:Case {case_id: $case_id})
MATCH (a:Alert {alert_id: $alert_id})
MERGE (c)-[:CONTAINS_ALERT]->(a)
RETURN c, a
"""


# --------------------------------------------------
# QUERY REGISTRY
# --------------------------------------------------

QUERY_REGISTRY: dict[str, str] = {
    "count_nodes": COUNT_NODES,
    "count_relationships": COUNT_RELATIONSHIPS,
    "get_graph_nodes": GET_GRAPH_NODES,
    "get_graph_relationships": GET_GRAPH_RELATIONSHIPS,
    "get_node_by_id": GET_NODE_BY_ID,
    "get_node_neighbors": GET_NODE_NEIGHBORS,
    "get_event_by_id": GET_EVENT_BY_ID,
    "list_events": LIST_EVENTS,
    "get_alert_by_id": GET_ALERT_BY_ID,
    "list_alerts": LIST_ALERTS,
    "list_open_alerts": LIST_OPEN_ALERTS,
    "detect_failed_logins": DETECT_FAILED_LOGINS,
    "detect_privilege_escalation": DETECT_PRIVILEGE_ESCALATION,
    "find_attack_paths": FIND_ATTACK_PATHS,
}


def get_query(name: str) -> str:
    """Retrieve a registered query by its name."""
    try:
        return QUERY_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown query '{name}'. "
            f"Available queries: {', '.join(sorted(QUERY_REGISTRY))}"
        ) from exc


def get_query_names() -> list[str]:
    """Return the names of registered queries."""
    return sorted(QUERY_REGISTRY)


def validate_query_parameters(
    parameters: dict[str, Any],
    required: tuple[str, ...],
) -> None:
    """Check that all required parameter names are present."""
    missing = [
        name for name in required
        if name not in parameters
    ]

    if missing:
        raise ValueError(
            "Missing query parameters: " + ", ".join(missing)
        )
