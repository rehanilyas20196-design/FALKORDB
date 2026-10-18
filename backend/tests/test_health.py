
"""Tests for the GraphGuard AI health and system endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_application_initializes():
    """The FastAPI application should initialize successfully."""
    assert app is not None


def test_health_endpoint(client):
    """The health endpoint should return HTTP 200."""
    response = client.get("/health")

    assert response.status_code == 200


def test_health_response_is_json(client):
    """The health endpoint should return a JSON response."""
    response = client.get("/health")

    assert response.status_code == 200
    assert "application/json" in response.headers.get(
        "content-type", ""
    )

    assert isinstance(response.json(), dict)


def test_health_response_contains_status(client):
    """The health response should provide a status field."""
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert "status" in data
    assert isinstance(data["status"], str)
    assert data["status"]


def test_readiness_endpoint(client):
    """The readiness endpoint should return HTTP 200."""
    response = client.get("/ready")

    assert response.status_code == 200


def test_readiness_response_is_json(client):
    """The readiness endpoint should return JSON."""
    response = client.get("/ready")

    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_api_info_endpoint(client):
    """The API information endpoint should respond successfully."""
    response = client.get("/api/v1/info")

    assert response.status_code == 200


def test_api_info_response_is_json(client):
    """The API information endpoint should return JSON."""
    response = client.get("/api/v1/info")

    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_openapi_endpoint(client):
    """OpenAPI documentation should be available."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    data = response.json()

    assert "openapi" in data
    assert "info" in data
    assert "paths" in data


def test_docs_endpoint(client):
    """Swagger UI should be available when enabled."""
    response = client.get("/docs")

    assert response.status_code == 200
    assert "text/html" in response.headers.get(
        "content-type", ""
    )


def test_unknown_endpoint_returns_404(client):
    """Unknown API paths should return HTTP 404."""
    response = client.get(
        "/api/v1/__test_unknown_health_endpoint__"
    )

    assert response.status_code == 404


def test_health_endpoint_does_not_return_server_error(client):
    """Repeated health requests should not produce HTTP 500."""
    for _ in range(3):
        response = client.get("/health")

        assert response.status_code == 200
