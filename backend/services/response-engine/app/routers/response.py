"""
Automated response router.
Actions are dispatched to the target endpoint's agent via command channel.
"""
from enum import StrEnum
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import publish

router = APIRouter()
settings = get_settings()


class ResponseAction(StrEnum):
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    REMOVE_PERSISTENCE = "remove_persistence"


class ResponseRequest(BaseModel):
    endpoint_id: str
    action: ResponseAction
    parameters: dict[str, Any] = {}
    incident_id: str | None = None
    reason: str = ""


class ResponseResult(BaseModel):
    success: bool
    action: ResponseAction
    endpoint_id: str
    message: str


@router.post(
    "/execute",
    response_model=ResponseResult,
    summary="Execute an automated response action on an endpoint",
)
async def execute_response(body: ResponseRequest) -> ResponseResult:
    """
    Dispatch a response action to the target endpoint.
    
    The response engine publishes the command to Kafka → the agent's
    response consumer picks it up and executes it locally.
    """
    action_handlers = {
        ResponseAction.KILL_PROCESS: _kill_process,
        ResponseAction.QUARANTINE_FILE: _quarantine_file,
        ResponseAction.BLOCK_IP: _block_ip,
        ResponseAction.ISOLATE_HOST: _isolate_host,
        ResponseAction.DISABLE_USER: _disable_user,
        ResponseAction.REMOVE_PERSISTENCE: _remove_persistence,
    }

    handler = action_handlers.get(body.action)
    if not handler:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown action: {body.action}",
        )

    result = await handler(body.endpoint_id, body.parameters)
    return ResponseResult(
        success=result["success"],
        action=body.action,
        endpoint_id=body.endpoint_id,
        message=result["message"],
    )


async def _kill_process(endpoint_id: str, params: dict) -> dict:
    pid = params.get("pid")
    if not pid:
        return {"success": False, "message": "Missing pid parameter"}

    await publish(
        settings.kafka_topic_response,
        {
            "action": "kill_process",
            "endpoint_id": endpoint_id,
            "parameters": {"pid": pid},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Kill process PID {pid} dispatched to {endpoint_id}"}


async def _quarantine_file(endpoint_id: str, params: dict) -> dict:
    path = params.get("path")
    if not path:
        return {"success": False, "message": "Missing path parameter"}

    await publish(
        settings.kafka_topic_response,
        {
            "action": "quarantine_file",
            "endpoint_id": endpoint_id,
            "parameters": {"path": path},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Quarantine {path} dispatched to {endpoint_id}"}


async def _block_ip(endpoint_id: str, params: dict) -> dict:
    ip = params.get("ip")
    if not ip:
        return {"success": False, "message": "Missing ip parameter"}

    await publish(
        settings.kafka_topic_response,
        {
            "action": "block_ip",
            "endpoint_id": endpoint_id,
            "parameters": {"ip": ip},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Block IP {ip} dispatched to {endpoint_id}"}


async def _isolate_host(endpoint_id: str, params: dict) -> dict:
    await publish(
        settings.kafka_topic_response,
        {
            "action": "isolate_host",
            "endpoint_id": endpoint_id,
            "parameters": {},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Host isolation dispatched to {endpoint_id}"}


async def _disable_user(endpoint_id: str, params: dict) -> dict:
    username = params.get("username")
    if not username:
        return {"success": False, "message": "Missing username parameter"}

    await publish(
        settings.kafka_topic_response,
        {
            "action": "disable_user",
            "endpoint_id": endpoint_id,
            "parameters": {"username": username},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Disable user {username} dispatched to {endpoint_id}"}


async def _remove_persistence(endpoint_id: str, params: dict) -> dict:
    key = params.get("registry_key")
    if not key:
        return {"success": False, "message": "Missing registry_key parameter"}

    await publish(
        settings.kafka_topic_response,
        {
            "action": "remove_persistence",
            "endpoint_id": endpoint_id,
            "parameters": {"registry_key": key},
        },
        key=endpoint_id,
    )
    return {"success": True, "message": f"Remove persistence {key} dispatched to {endpoint_id}"}

