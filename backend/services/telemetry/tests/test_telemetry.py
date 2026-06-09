import pytest
from httpx import AsyncClient

from app.services.ingestion import normalize_event


@pytest.mark.asyncio
async def test_telemetry_health(client: AsyncClient):
    # Call health check
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "telemetry"}



def test_normalize_process_event():
    raw_event = {
        "event_type": "process_create",
        "occurred_at": "2026-06-08T12:00:00Z",
        "payload": {
          "process_name": "cmd.exe",
          "pid": 5824,
          "parent_pid": 1024,
          "command_line": "cmd.exe /c whoami",
          "executable": "C:\\Windows\\System32\\cmd.exe",
          "user": "SYSTEM",
          "sha256": "abcdef123456"
        }
    }

    normalized = normalize_event(raw_event, "test-endpoint-id")

    assert normalized["agent"]["id"] == "test-endpoint-id"
    assert normalized["event"]["category"] == ["process"]
    assert normalized["event"]["type"] == "process_create"
    assert normalized["process"]["name"] == "cmd.exe"
    assert normalized["process"]["pid"] == 5824
    assert normalized["process"]["hash"]["sha256"] == "abcdef123456"
