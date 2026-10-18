
"""Tests for the GraphGuard AI graph API."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def graph_routes():
    """Get registered graph-related routes."""
    return [
        route
        for route in app.routes
        if "graph" in getattr(route, "path", "").lower()
    ]


def test_application_starts():
    """The FastAPI application should initialize."""
    assert app is not None


def test_health_endpoint(client):
    """The application health endpoint should respond."""
    response = client.get("/health")

    assert response.status_code == 200


def test_graph_routes_registered(graph_routes):
    """At least one graph-related route should be registered."""
    assert graph_routes, (
        "No graph routes found. Check the graph router "
        "and its registration in backend/app/main.py."
    )


def test_openapi_schema_available(client):
    """OpenAPI documentation should be available."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()

    assert "openapi" in schema
    assert "paths" in schema


def test_graph_routes_appear_in_openapi(client):
    """Graph endpoints should be documented in OpenAPI."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json().get("paths", {})

    graph_paths = [
        path for path in paths
        if "graph" in path.lower()
    ]

    assert graph_paths, "No graph-related OpenAPI paths found."


def test_graph_get_endpoints_do_not_return_server_error(
    client,
    graph_routes,
):
    """Static graph GET routes should not return HTTP 500."""
    assert graph_routes, "No graph routes are registered."

    for route in graph_routes:
        path = route.path

        # Skip routes that require path parameters.
        if "{" in path or "}" in path:
            continue

        if "GET" not in getattr(route, "methods", set()):
            continue

        response = client.get(path)

        assert response.status_code != 500, (
            f"GET {path} returned HTTP 500: {response.text}"
        )


def test_graph_route_methods_are_registered(graph_routes):
    """Graph routes should declare HTTP methods."""
    assert graph_routes, "No graph routes are registered."

    for route in graph_routes:
        methods = getattr(route, "methods", set())

        assert methods, (
            f"Graph route {route.path} has no HTTP methods."
        )


def test_graph_api_does_not_expose_internal_tracebacks(client):
    """An unknown graph endpoint should not expose a traceback."""
    response = client.get(
        "/api/v1/graph/__test_nonexistent_endpoint__"
    )

    assert response.status_code == 404
    assert "Traceback (most recent call last)" not in response.text


def test_openapi_paths_are_a_dictionary(client):
    """OpenAPI paths should be returned as a dictionary."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json().get("paths")

    assert isinstance(paths, dict)
