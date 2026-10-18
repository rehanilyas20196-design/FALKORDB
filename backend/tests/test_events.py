
"""Tests for the GraphGuard AI Security Events API."""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def event_payload():
    """Provide a valid event payload."""
    return {
        "event_type": "suspicious_login",
        "source": "test-server",
        "severity": "high",
        "description": "Multiple failed login attempts detected",
        "user": "test-user",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "metadata": {
            "failed_attempts": 5,
            "test": True,
        },
    }


def test_event_routes_registered(client):
    """The events endpoints should be registered in OpenAPI."""
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json().get("paths", {})

    assert "/api/v1/events" in paths or "/api/v1/events/" in paths


def test_create_event(client, event_payload):
    """Creating a valid event should return HTTP 201."""
    response = client.post("/api/v1/events/", json=event_payload)

    assert response.status_code == 201

    data = response.json()

    assert data["event_id"]
    assert data["event_type"] == event_payload["event_type"]
    assert data["source"] == event_payload["source"]
    assert data["severity"] == "high"
    assert data["description"] == event_payload["description"]
    assert data["user"] == event_payload["user"]
    assert data["source_ip"] == event_payload["source_ip"]
    assert data["destination_ip"] == event_payload["destination_ip"]


def test_list_events(client, event_payload):
    """The list endpoint should return created events."""
    create_response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert create_response.status_code == 201

    response = client.get("/api/v1/events/")

    assert response.status_code == 200
    assert isinstance(response.json(), list)

    event_ids = [event["event_id"] for event in response.json()]
    assert create_response.json()["event_id"] in event_ids


def test_create_event_with_empty_payload(client):
    """An empty payload should be rejected by request validation."""
    response = client.post("/api/v1/events/", json={})

    assert response.status_code == 422


def test_create_event_with_invalid_json(client):
    """A malformed JSON body should be rejected."""
    response = client.post(
        "/api/v1/events/",
        content='{"event_type": ',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422


def test_get_created_event(client, event_payload):
    """A created event should be retrievable by its ID."""
    create_response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert create_response.status_code == 201

    event_id = create_response.json()["event_id"]

    response = client.get(f"/api/v1/events/{event_id}")

    assert response.status_code == 200
    assert response.json()["event_id"] == event_id
    assert response.json()["event_type"] == event_payload["event_type"]


def test_get_event_not_found(client):
    """Requesting an unknown event should return HTTP 404."""
    response = client.get(
        "/api/v1/events/EVT-DOES-NOT-EXIST"
    )

    assert response.status_code == 404


def test_delete_created_event(client, event_payload):
    """A created event should be deletable."""
    create_response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert create_response.status_code == 201

    event_id = create_response.json()["event_id"]

    delete_response = client.delete(
        f"/api/v1/events/{event_id}"
    )

    assert delete_response.status_code == 200

    result = delete_response.json()
    assert result["status"] == "success"

    get_response = client.get(
        f"/api/v1/events/{event_id}"
    )

    assert get_response.status_code == 404


def test_delete_event_not_found(client):
    """Deleting an unknown event should return HTTP 404."""
    response = client.delete(
        "/api/v1/events/EVT-DOES-NOT-EXIST"
    )

    assert response.status_code == 404


def test_create_event_normalizes_severity(client, event_payload):
    """Severity should be normalized to lowercase."""
    event_payload["severity"] = " HIGH "

    response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert response.status_code == 201
    assert response.json()["severity"] == "high"


@pytest.mark.parametrize(
    "severity",
    ["unknown", "urgent", "extreme"],
)
def test_create_event_rejects_invalid_severity(
    client,
    event_payload,
    severity,
):
    """Unsupported severity values should be rejected."""
    event_payload["severity"] = severity

    response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert response.status_code == 422


def test_list_events_filters_by_severity(client, event_payload):
    """The list endpoint should filter by severity."""
    event_payload["severity"] = "critical"

    create_response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert create_response.status_code == 201

    response = client.get(
        "/api/v1/events/",
        params={"severity": "critical"},
    )

    assert response.status_code == 200
    assert all(
        event["severity"] == "critical"
        for event in response.json()
    )


def test_list_events_filters_by_event_type(client, event_payload):
    """The list endpoint should filter by event type."""
    create_response = client.post(
        "/api/v1/events/",
        json=event_payload,
    )

    assert create_response.status_code == 201

    response = client.get(
        "/api/v1/events/",
        params={"event_type": event_payload["event_type"]},
    )

    assert response.status_code == 200
    assert all(
        event["event_type"].lower()
        == event_payload["event_type"].lower()
        for event in response.json()
    )


def test_list_events_rejects_invalid_severity_filter(client):
    """An invalid severity filter should return HTTP 422."""
    response = client.get(
        "/api/v1/events/",
        params={"severity": "not-a-severity"},
    )

    assert response.status_code == 422


def test_list_events_respects_limit(client, event_payload):
    """The list endpoint should respect its limit parameter."""
    for _ in range(3):
        response = client.post(
            "/api/v1/events/",
            json=event_payload,
        )
        assert response.status_code == 201

    response = client.get(
        "/api/v1/events/",
        params={"limit": 2},
    )

    assert response.status_code == 200
    assert len(response.json()) <= 2
