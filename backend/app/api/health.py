
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from backend.app.db.falkordb import db_manager

logger = logging.getLogger("graphguard.graph")

router = APIRouter(
    prefix="/graph",
    tags=["Graph"],
)


# --------------------------------------------------
# RESPONSE SCHEMAS
# --------------------------------------------------

class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    total_nodes: int
    total_relationships: int


# --------------------------------------------------
# DATABASE HELPER
# --------------------------------------------------

def get_graph():
    """Get the active FalkorDB graph connection."""
    try:
        return db_manager.get_graph()
    except Exception as exc:
        logger.exception("Could not access FalkorDB.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph database is unavailable.",
        ) from exc


def record_to_dict(record: Any) -> dict[str, Any]:
    """Convert a FalkorDB query record into a JSON-friendly dictionary."""
    if hasattr(record, "data"):
        data = record.data()
        return {
            str(key): serialize_value(value)
            for key, value in data.items()
        }

    if isinstance(record, dict):
        return {
            str(key): serialize_value(value)
            for key, value in record.items()
        }

    return {"value": serialize_value(record)}


def serialize_value(value: Any) -> Any:
    """Convert common graph values into JSON-friendly values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): serialize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [serialize_value(item) for item in value]

    # FalkorDB nodes commonly expose properties and an internal ID.
    if hasattr(value, "properties"):
        properties = value.properties
        if callable(properties):
            properties = properties()

        return {
            "id": getattr(value, "id", None),
            "labels": list(getattr(value, "labels", []) or []),
            "properties": serialize_value(properties or {}),
        }

    # Relationships commonly expose source, destination and type.
    if hasattr(value, "relation"):
        return {
            "id": getattr(value, "id", None),
            "type": getattr(value, "relation", None),
            "source": getattr(value, "src_node", None),
            "target": getattr(value, "dest_node", None),
            "properties": serialize_value(
                getattr(value, "properties", {}) or {}
            ),
        }

    return str(value)


def execute_query(query: str, params: dict[str, Any] | None = None):
    """Execute a read query and return its records."""
    graph = get_graph()

    try:
        result = graph.query(query, params or {})
        return [
            record_to_dict(record)
            for record in result.result_set
        ]
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Graph query failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not retrieve graph data.",
        ) from exc


# --------------------------------------------------
# GRAPH HEALTH
# --------------------------------------------------

@router.get("/health")
async def graph_health():
    graph = get_graph()

    try:
        graph.query("RETURN 1")
        return {
            "status": "healthy",
            "service": "GraphGuard Graph API",
        }
    except Exception as exc:
        logger.exception("Graph health check failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph database health check failed.",
        ) from exc


# --------------------------------------------------
# GET GRAPH OVERVIEW
# --------------------------------------------------

@router.get("/overview")
async def graph_overview():
    records = execute_query(
        """
        MATCH (n)
        RETURN count(n) AS total_nodes
        """
    )
    total_nodes = records[0]["total_nodes"] if records else 0

    records = execute_query(
        """
        MATCH ()-[r]->()
        RETURN count(r) AS total_relationships
        """
    )
    total_relationships = (
        records[0]["total_relationships"] if records else 0
    )

    return {
        "total_nodes": total_nodes,
        "total_relationships": total_relationships,
        "graph": "graphguard",
    }


# --------------------------------------------------
# GET FULL GRAPH
# --------------------------------------------------

@router.get("/", response_model=GraphResponse)
async def get_full_graph(
    limit: int = Query(default=200, ge=1, le=1000),
):
    node_records = execute_query(
        """
        MATCH (n)
        RETURN n
        LIMIT $limit
        """,
        {"limit": limit},
    )

    relationship_records = execute_query(
        """
        MATCH (a)-[r]->(b)
        RETURN a, r, b
        LIMIT $limit
        """,
        {"limit": limit},
    )

    nodes = []
    for record in node_records:
        nodes.append(
            serialize_value(record.get("n"))
        )

    relationships = []
    for record in relationship_records:
        relationships.append({
            "source": serialize_value(record.get("a")),
            "relationship": serialize_value(record.get("r")),
            "target": serialize_value(record.get("b")),
        })

    return GraphResponse(
        nodes=nodes,
        relationships=relationships,
        total_nodes=len(nodes),
        total_relationships=len(relationships),
    )


# --------------------------------------------------
# FIND NODES BY LABEL
# --------------------------------------------------

@router.get("/nodes")
async def get_nodes(
    label: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
):
    # Labels cannot safely be supplied as query parameters.
    # Use a fixed, validated label before interpolating it.
    allowed_labels = {
        "Event",
        "Alert",
        "User",
        "Host",
        "IP",
        "Process",
        "Case",
    }

    if label is not None:
        if label not in allowed_labels:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Unsupported label. Allowed labels: "
                    + ", ".join(sorted(allowed_labels))
                ),
            )

        query = (
            f"MATCH (n:`{label}`) "
            "RETURN n LIMIT $limit"
        )
    else:
        query = "MATCH (n) RETURN n LIMIT $limit"

    records = execute_query(query, {"limit": limit})

    return {
        "count": len(records),
        "nodes": [
            serialize_value(record.get("n"))
            for record in records
        ],
    }


# --------------------------------------------------
# GET NODE NEIGHBORS
# --------------------------------------------------

@router.get("/neighbors/{node_id}")
async def get_node_neighbors(
    node_id: str,
    limit: int = Query(default=100, ge=1, le=500),
):
    records = execute_query(
        """
        MATCH (n)-[r]-(neighbor)
        WHERE toString(id(n)) = $node_id
        RETURN n, r, neighbor
        LIMIT $limit
        """,
        {
            "node_id": node_id,
            "limit": limit,
        },
    )

    return {
        "node_id": node_id,
        "count": len(records),
        "neighbors": [
            {
                "node": serialize_value(record.get("n")),
                "relationship": serialize_value(record.get("r")),
                "neighbor": serialize_value(record.get("neighbor")),
            }
            for record in records
        ],
    }


# --------------------------------------------------
# SEARCH NODES BY PROPERTY
# --------------------------------------------------

@router.get("/search")
async def search_nodes(
    property_name: str = Query(
        ...,
        min_length=1,
        max_length=100,
    ),
    value: str = Query(
        ...,
        min_length=1,
        max_length=500,
    ),
    limit: int = Query(default=50, ge=1, le=200),
):
    allowed_properties = {
        "id",
        "name",
        "username",
        "hostname",
        "ip",
        "source_ip",
        "event_type",
        "severity",
        "status",
    }

    if property_name not in allowed_properties:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported search property.",
        )

    records = execute_query(
        f"""
        MATCH (n)
        WHERE toString(n.`{property_name}`) = $value
        RETURN n
        LIMIT $limit
        """,
        {
            "value": value,
            "limit": limit,
        },
    )

    return {
        "count": len(records),
        "nodes": [
            serialize_value(record.get("n"))
            for record in records
        ],
    }
