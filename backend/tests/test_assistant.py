
"""
Tests for the FolderDB AI Agent Assistant API.

Location:
    backend/tests/test_assistant.py

Run from:
    D:\\AI agent

Command:
    python -m pytest .\\backend\\tests\\test_assistant.py -v
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_assistant_routes_registered():
    """Verify that the assistant endpoints are registered."""
    paths = app.openapi()["paths"]

    assert "/api/v1/assistant/health" in paths
    assert "/api/v1/assistant/chat" in paths

    assert "get" in paths["/api/v1/assistant/health"]
    assert "post" in paths["/api/v1/assistant/chat"]


def test_assistant_health(client):
    """Verify that the assistant health endpoint responds successfully."""
    response = client.get("/api/v1/assistant/health")

    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, dict)


def test_assistant_chat_endpoint_exists(client):
    """Verify that the chat endpoint is reachable.

    An empty JSON object is used to check that the route exists.
    A 422 response is acceptable if required fields are missing.
    """
    response = client.post(
        "/api/v1/assistant/chat",
        json={},
    )

    assert response.status_code != 404


def test_assistant_chat_rejects_invalid_json(client):
    """Verify that malformed JSON is rejected."""
    response = client.post(
        "/api/v1/assistant/chat",
        content="{invalid json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
