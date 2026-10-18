
import logging
from collections import deque
from typing import Any

from backend.app.db.falkordb import db_manager

logger = logging.getLogger("graphguard.attack_path")


class AttackPathService:
    """
    Finds and evaluates potential attack paths in the GraphGuard graph.

    This service performs read-only graph queries. It does not execute
    containment actions or modify security infrastructure.
    """

    def __init__(
        self,
        max_depth: int = 5,
        default_limit: int = 20,
    ) -> None:
        self.max_depth = max(1, min(int(max_depth), 8))
        self.default_limit = max(1, min(int(default_limit), 100))

    # ---------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------

    @staticmethod
    def _properties(value: Any) -> dict[str, Any]:
        """Convert a FalkorDB node or dictionary to a plain dictionary."""
        if isinstance(value, dict):
            return value

        if value is None:
            return {}

        props = getattr(value, "properties", None)

        if callable(props):
            try:
                props = props()
            except Exception:
                props = None

        if isinstance(props, dict):
            return props

        try:
            return dict(value)
        except (TypeError, ValueError):
            return {}

    @classmethod
    def _node_to_dict(cls, node: Any) -> dict[str, Any]:
        """Serialize a graph node without depending on a specific node class."""
        if node is None:
            return {}

        properties = cls._properties(node)

        labels = getattr(node, "labels", None)
        if callable(labels):
            try:
                labels = labels()
            except Exception:
                labels = None

        if labels is not None:
            try:
                properties["labels"] = list(labels)
            except TypeError:
                pass

        node_id = getattr(node, "id", None)
        if node_id is not None:
            properties.setdefault("graph_id", node_id)

        return properties

    @classmethod
    def _relationship_to_dict(cls, relationship: Any) -> dict[str, Any]:
        """Serialize a graph relationship."""
        if relationship is None:
            return {}

        properties = cls._properties(relationship)

        relation_type = getattr(relationship, "relation", None)
        if callable(relation_type):
            try:
                relation_type = relation_type()
            except Exception:
                relation_type = None

        if relation_type is None:
            relation_type = getattr(relationship, "type", None)

        if relation_type is not None:
            properties.setdefault("type", str(relation_type))

        relation_id = getattr(relationship, "id", None)
        if relation_id is not None:
            properties.setdefault("graph_id", relation_id)

        return properties

    @staticmethod
    def _records(result: Any) -> list[Any]:
        """Extract rows from a FalkorDB query result."""
        if result is None:
            return []

        if isinstance(result, list):
            return result

        result_records = getattr(result, "result_set", None)
        if result_records is not None:
            return list(result_records)

        try:
            return list(result)
        except TypeError:
            return []

    @staticmethod
    def _safe_limit(limit: int | None, default: int) -> int:
        """Keep user-provided result limits within safe bounds."""
        if limit is None:
            return default

        try:
            return max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    # ---------------------------------------------------------
    # Risk scoring
    # ---------------------------------------------------------

    def calculate_risk_score(
        self,
        path: dict[str, Any],
    ) -> int:
        """
        Estimate path risk from path length, sensitive nodes,
        privilege indicators, and suspicious relationships.

        This is a heuristic score, not a calibrated probability.
        """
        nodes = path.get("nodes", [])
        relationships = path.get("relationships", [])

        score = 10

        # Longer paths can represent more opportunities for movement.
        score += min(len(relationships) * 5, 20)

        sensitive_keywords = (
            "admin",
            "administrator",
            "domain controller",
            "domain_controller",
            "database",
            "production",
            "critical",
            "privileged",
            "root",
        )

        for node in nodes:
            text = " ".join(
                str(value)
                for value in node.values()
                if isinstance(value, (str, int, float))
            ).lower()

            if any(keyword in text for keyword in sensitive_keywords):
                score += 10

            privilege = str(
                node.get("privilege", node.get("role", ""))
            ).lower()

            if privilege in {"admin", "administrator", "root", "system"}:
                score += 15

        suspicious_keywords = (
            "admin",
            "execute",
            "remote",
            "credential",
            "lateral",
            "exploit",
            "privilege",
        )

        for relationship in relationships:
            relation_text = " ".join(
                str(value)
                for value in relationship.values()
                if isinstance(value, (str, int, float))
            ).lower()

            if any(word in relation_text for word in suspicious_keywords):
                score += 8

        return max(0, min(score, 100))

    # ---------------------------------------------------------
    # Path normalization
    # ---------------------------------------------------------

    def _normalize_path(self, path_value: Any) -> dict[str, Any]:
        """
        Convert a returned FalkorDB path into a serializable structure.

        FalkorDB versions can expose path components differently.
        """
        nodes: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        path_nodes = getattr(path_value, "nodes", None)
        if callable(path_nodes):
            try:
                path_nodes = path_nodes()
            except Exception:
                path_nodes = None

        path_relationships = getattr(path_value, "relationships", None)
        if callable(path_relationships):
            try:
                path_relationships = path_relationships()
            except Exception:
                path_relationships = None

        if path_nodes is not None:
            try:
                nodes = [
                    self._node_to_dict(node)
                    for node in path_nodes
                ]
            except TypeError:
                nodes = []

        if path_relationships is not None:
            try:
                relationships = [
                    self._relationship_to_dict(rel)
                    for rel in path_relationships
                ]
            except TypeError:
                relationships = []

        # Some FalkorDB client versions return paths as iterable objects.
        if not nodes and not relationships:
            try:
                components = list(path_value)
            except (TypeError, ValueError):
                components = []

            for index, component in enumerate(components):
                if index % 2 == 0:
                    nodes.append(self._node_to_dict(component))
                else:
                    relationships.append(
                        self._relationship_to_dict(component)
                    )

        return {
            "nodes": nodes,
            "relationships": relationships,
        }

    # ---------------------------------------------------------
    # Find attack paths
    # ---------------------------------------------------------

    def find_attack_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Find directed paths between two graph nodes.

        Expected node property:
            node_id

        If your database uses another identifier property, update
        the Cypher WHERE clause to match database/init.cypher.
        """
        if not source_id or not target_id:
            return {
                "success": False,
                "message": "Both source_id and target_id are required.",
                "source_id": source_id,
                "target_id": target_id,
                "total": 0,
                "paths": [],
            }

        if source_id == target_id:
            return {
                "success": True,
                "message": "Source and target are the same node.",
                "source_id": source_id,
                "target_id": target_id,
                "total": 0,
                "paths": [],
            }

        depth = self.max_depth
        if max_depth is not None:
            try:
                depth = max(1, min(int(max_depth), self.max_depth))
            except (TypeError, ValueError):
                depth = self.max_depth

        result_limit = self._safe_limit(limit, self.default_limit)

        query = f"""
        MATCH p = (source)-[*1..{depth}]->(target)
        WHERE source.node_id = $source_id
          AND target.node_id = $target_id
        RETURN p
        LIMIT $limit
        """

        try:
            graph = db_manager.get_graph()
            result = graph.query(
                query,
                {
                    "source_id": str(source_id),
                    "target_id": str(target_id),
                    "limit": result_limit,
                },
            )

            paths: list[dict[str, Any]] = []

            for row in self._records(result):
                if not row:
                    continue

                path_data = self._normalize_path(row[0])

                if not path_data["nodes"]:
                    continue

                risk_score = self.calculate_risk_score(path_data)

                paths.append({
                    "path_id": f"path-{len(paths) + 1}",
                    "source_id": str(source_id),
                    "target_id": str(target_id),
                    "nodes": path_data["nodes"],
                    "relationships": path_data["relationships"],
                    "node_count": len(path_data["nodes"]),
                    "relationship_count": len(
                        path_data["relationships"]
                    ),
                    "risk_score": risk_score,
                    "risk_level": self._risk_level(risk_score),
                })

            paths.sort(
                key=lambda item: item["risk_score"],
                reverse=True,
            )

            return {
                "success": True,
                "message": f"Found {len(paths)} possible attack path(s).",
                "source_id": str(source_id),
                "target_id": str(target_id),
                "max_depth": depth,
                "total": len(paths),
                "paths": paths,
            }

        except Exception as exc:
            logger.exception(
                "Failed to find attack paths from %s to %s",
                source_id,
                target_id,
            )
            return {
                "success": False,
                "message": "Could not query attack paths from FalkorDB.",
                "error": str(exc),
                "source_id": str(source_id),
                "target_id": str(target_id),
                "total": 0,
                "paths": [],
            }

    # ---------------------------------------------------------
    # Analyze one supplied path
    # ---------------------------------------------------------

    def analyze_attack_path(
        self,
        path: dict[str, Any],
    ) -> dict[str, Any]:
        """Score a path and produce a defensive explanation."""
        if not isinstance(path, dict):
            return {
                "success": False,
                "message": "The path must be a dictionary.",
            }

        nodes = path.get("nodes", [])
        relationships = path.get("relationships", [])

        if not isinstance(nodes, list) or not isinstance(
            relationships, list
        ):
            return {
                "success": False,
                "message": "Path nodes and relationships must be lists.",
            }

        normalized = {
            "nodes": [
                node for node in nodes if isinstance(node, dict)
            ],
            "relationships": [
                rel for rel in relationships if isinstance(rel, dict)
            ],
        }

        risk_score = self.calculate_risk_score(normalized)
        recommendations = [
            "Verify that each relationship represents an authorized connection.",
            "Review access permissions on sensitive destination systems.",
            "Investigate unusual authentication and remote-access activity.",
            "Enable monitoring for privilege changes and lateral movement.",
        ]

        if risk_score >= 80:
            summary = (
                "Critical-priority path based on the configured "
                "heuristic. Validate the path and investigate promptly."
            )
        elif risk_score >= 60:
            summary = (
                "High-priority path. Review its connections and "
                "the privileges available along the route."
            )
        elif risk_score >= 35:
            summary = (
                "Moderate-risk path. Review access controls and "
                "monitor related activity."
            )
        else:
            summary = (
                "Lower heuristic risk. Continue monitoring and "
                "validate the graph data."
            )

        return {
            "success": True,
            "summary": summary,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "node_count": len(normalized["nodes"]),
            "relationship_count": len(normalized["relationships"]),
            "recommendations": recommendations,
            "requires_human_review": True,
        }

    # ---------------------------------------------------------
    # Rank paths
    # ---------------------------------------------------------

    def prioritize_attack_paths(
        self,
        paths: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return valid paths ranked by descending risk score."""
        if not isinstance(paths, list):
            return []

        valid_paths = [
            path for path in paths
            if isinstance(path, dict)
        ]

        def get_score(path: dict[str, Any]) -> int:
            try:
                return int(path.get("risk_score", 0))
            except (TypeError, ValueError):
                return 0

        return sorted(
            valid_paths,
            key=get_score,
            reverse=True,
        )

    # ---------------------------------------------------------
    # Graph reachability helper
    # ---------------------------------------------------------

    def get_reachable_nodes(
        self,
        source_id: str,
        max_depth: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List nodes reachable from a starting node."""
        if not source_id:
            return {
                "success": False,
                "message": "source_id is required.",
                "nodes": [],
                "total": 0,
            }

        depth = self.max_depth
        if max_depth is not None:
            try:
                depth = max(1, min(int(max_depth), self.max_depth))
            except (TypeError, ValueError):
                depth = self.max_depth

        result_limit = self._safe_limit(limit, self.default_limit)

        query = f"""
        MATCH (source)-[*1..{depth}]->(target)
        WHERE source.node_id = $source_id
        RETURN DISTINCT target
        LIMIT $limit
        """

        try:
            result = db_manager.get_graph().query(
                query,
                {
                    "source_id": str(source_id),
                    "limit": result_limit,
                },
            )

            nodes: list[dict[str, Any]] = []

            for row in self._records(result):
                if row:
                    node = self._node_to_dict(row[0])
                    if node:
                        nodes.append(node)

            return {
                "success": True,
                "source_id": str(source_id),
                "max_depth": depth,
                "total": len(nodes),
                "nodes": nodes,
            }

        except Exception as exc:
            logger.exception(
                "Failed to find reachable nodes from %s",
                source_id,
            )
            return {
                "success": False,
                "message": "Could not query reachable nodes.",
                "error": str(exc),
                "source_id": str(source_id),
                "nodes": [],
                "total": 0,
            }


# Shared service instance
attack_path_service = AttackPathService()

# Compatibility alias for modules that use a shorter name.
AttackPathAnalyzer = AttackPathService
attack_path_analyzer = attack_path_service
