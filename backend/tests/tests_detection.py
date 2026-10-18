
"""Tests for the GraphGuard AI detection API."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def get_detection_routes():
    """Return registered detection-related routes."""
    return [
        route
        for route in app.routes
        if "detection" in getattr(route, "path", "").lower()
    ]


def test_application_initializes():
    """The application should initialize successfully."""
    assert app is not None


def test_openapi_endpoint(client):
    """OpenAPI documentation should be available."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()

    assert "openapi" in schema
    assert "paths" in schema


def test_detection_routes_registered():
    """At least one detection route should be registered."""
    routes = get_detection_routes()

    assert routes, (
        "No detection routes found. Check the detection router "
        "and its registration in backend/app/main.py."
    )


def test_detection_routes_documented(client):
    """Detection routes should appear in the OpenAPI schema."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json().get("paths", {})

    detection_paths = [
        path for path in paths
        if "detection" in path.lower()
    ]

    assert detection_paths, (
        "No detection endpoints found in OpenAPI documentation."
    )


def test_detection_routes_declare_http_methods():
    """Each detection route should declare its HTTP methods."""
    routes = get_detection_routes()

    assert routes, "No detection routes are registered."

    for route in routes:
        methods = getattr(route, "methods", set())

        assert methods, (
            f"Detection route {route.path} has no HTTP methods."
        )


def test_static_detection_get_endpoints_do_not_return_500(
    client,
):
    """Static detection GET endpoints should not crash the API."""
    routes = get_detection_routes()

    assert routes, "No detection routes are registered."

    for route in routes:
        path = route.path

        # Routes with parameters require specific test identifiers.
        if "{" in path or "}" in path:
            continue

        if "GET" not in getattr(route, "methods", set()):
            continue

        response = client.get(path)

        assert response.status_code != 500, (
            f"GET {path} returned HTTP 500: {response.text}"
        )


def test_unknown_detection_endpoint_returns_404(client):
    """An unknown detection endpoint should return HTTP 404."""
    response = client.get(
        "/api/v1/detection/__test_unknown_endpoint__"
    )

    assert response.status_code == 404


def test_health_endpoint(client):
    """The application health endpoint should respond."""
    response = client.get("/health")

    assert response.status_code == 200


def test_detection_api_does_not_expose_tracebacks(client):
    """Unknown detection requests should not expose tracebacks."""
    response = client.get(
        "/api/v1/detection/__test_unknown_endpoint__"
    )

    assert response.status_code == 404

    assert "Traceback (most recent call last)" not in response.text
