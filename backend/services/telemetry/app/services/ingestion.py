"""
Event normalization and agent token validation.
Normalizes raw agent payloads to ECS (Elastic Common Schema) format.
"""
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

from sentinelx_shared.models.endpoint import Endpoint
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# In production: look up token in Redis cache (fast) → DB (fallback)
_token_cache: dict[str, dict] = {}


async def validate_agent_token(db: AsyncSession, token: str) -> dict | None:
    """
    Validate an agent token and return endpoint info.
    Checks cache first, then falls back to DB.
    """
    if token in _token_cache:
        return _token_cache[token]

    result = await db.execute(select(Endpoint).where(Endpoint.agent_token == token))
    endpoint = result.scalar_one_or_none()
    if endpoint:
        endpoint_info = {"id": endpoint.id, "hostname": endpoint.hostname}
        _token_cache[token] = endpoint_info
        return endpoint_info
    return None



def normalize_event(raw: dict[str, Any], endpoint_id: str) -> dict[str, Any]:
    """
    Normalize a raw agent event to ECS-compatible format.
    ECS: https://www.elastic.co/guide/en/ecs/current/index.html
    """
    event_type = raw.get("event_type", "unknown")
    payload = raw.get("payload", {})
    occurred_at = raw.get("occurred_at", datetime.now(UTC).isoformat())

    normalized: dict[str, Any] = {
        # ECS base fields
        "@timestamp": occurred_at,
        "event": {
            "kind": "event",
            "category": _map_category(event_type),
            "type": event_type,
            "created": datetime.now(UTC).isoformat(),
        },
        "agent": {
            "id": endpoint_id,
            "type": "sentinelx",
        },
        "sentinelx": {
            "endpoint_id": endpoint_id,
            "raw": payload,
        },
    }

    # ── Process events ──────────────────────────────────────
    if event_type in ("process_create", "process_terminate"):
        normalized["process"] = {
            "name": payload.get("process_name"),
            "pid": payload.get("pid"),
            "parent": {"pid": payload.get("parent_pid")},
            "command_line": payload.get("command_line"),
            "executable": payload.get("executable"),
            "user": {"name": payload.get("user")},
            "hash": {
                "sha256": payload.get("sha256"),
                "md5": payload.get("md5"),
            },
        }

    # ── File events ─────────────────────────────────────────
    elif event_type in ("file_create", "file_delete", "file_modify", "file_rename"):
        normalized["file"] = {
            "path": payload.get("path"),
            "name": payload.get("name"),
            "extension": payload.get("extension"),
            "size": payload.get("size"),
            "hash": {"sha256": payload.get("sha256")},
        }

    # ── Network events ──────────────────────────────────────
    elif event_type in ("network_connection", "network_dns"):
        normalized["source"] = {"ip": payload.get("src_ip"), "port": payload.get("src_port")}
        normalized["destination"] = {
            "ip": payload.get("dst_ip"),
            "port": payload.get("dst_port"),
            "domain": payload.get("domain"),
        }
        normalized["network"] = {
            "protocol": payload.get("protocol"),
            "direction": payload.get("direction", "outbound"),
        }

    # ── Registry events ──────────────────────────────────────
    elif event_type in ("registry_set", "registry_delete"):
        normalized["registry"] = {
            "hive": payload.get("hive"),
            "key": payload.get("key"),
            "value": {"name": payload.get("value_name"), "data": payload.get("value_data")},
        }

    return normalized


def _map_category(event_type: str) -> list[str]:
    mapping = {
        "process_create": ["process"],
        "process_terminate": ["process"],
        "file_create": ["file"],
        "file_delete": ["file"],
        "file_modify": ["file"],
        "file_rename": ["file"],
        "network_connection": ["network"],
        "network_dns": ["network", "dns"],
        "registry_set": ["registry"],
        "registry_delete": ["registry"],
        "user_login": ["authentication"],
        "user_logout": ["authentication"],
    }
    return mapping.get(event_type, ["host"])
