
from falkordb import FalkorDB
from backend.app.config import settings


class DatabaseManager:
    def __init__(self):
        self.client = None
        self.graph = None

    def connect(self):
        """Connect to FalkorDB and select the GraphGuard graph."""
        if self.graph is not None:
            return self.graph

        self.client = FalkorDB(
            host=settings.FALKORDB_HOST,
            port=settings.FALKORDB_PORT,
            password=settings.FALKORDB_PASSWORD or None,
        )

        self.graph = self.client.select_graph(
            settings.FALKORDB_GRAPH
        )

        # Verify that the database can execute a query.
        self.graph.query("RETURN 1")
        return self.graph

    def get_graph(self):
        """Return the active graph connection."""
        if self.graph is None:
            return self.connect()
        return self.graph

    def close(self):
        """Close the database client during shutdown."""
        if self.client is not None:
            self.client.close()

        self.client = None
        self.graph = None


db_manager = DatabaseManager()
