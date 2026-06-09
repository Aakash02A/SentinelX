"""
Telemetry ingestion router.
Agents POST batches of telemetry events here.
"""
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sentinelx_shared.config import get_settings
from sentinelx_shared.db import DBSession
from sentinelx_shared.kafka_client import publish

from app.services.ingestion import normalize_event, validate_agent_token

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()


class HeartbeatPayload(BaseModel):
    agent_token: str
    hostname: str
    agent_version: str
    cpu_percent: float = Field(ge=0, le=100)
    ram_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)


class RawEvent(BaseModel):
    event_type: str
    occurred_at: datetime
    payload: dict


class TelemetryBatch(BaseModel):
    agent_token: str
    events: list[RawEvent] = Field(max_length=500)


@router.post(
    "/heartbeat",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Agent heartbeat — updates last_seen and system health",
)
async def heartbeat(body: HeartbeatPayload, db: DBSession) -> dict[str, str]:
    endpoint = await validate_agent_token(db, body.agent_token)
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    await publish(
        settings.kafka_topic_telemetry,
        {
            "type": "heartbeat",
            "endpoint_id": endpoint["id"],
            "hostname": body.hostname,
            "timestamp": datetime.now(UTC).isoformat(),
            "metrics": {
                "cpu_percent": body.cpu_percent,
                "ram_percent": body.ram_percent,
                "disk_percent": body.disk_percent,
            },
        },
        key=endpoint["id"],
    )
    return {"status": "accepted"}


@router.post(
    "/batch",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a batch of telemetry events from an agent",
)
async def ingest_batch(body: TelemetryBatch, db: DBSession) -> dict[str, int]:
    endpoint = await validate_agent_token(db, body.agent_token)
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    published = 0
    for raw_event in body.events:
        try:
            normalized = normalize_event(raw_event.model_dump(), endpoint["id"])
            await publish(
                settings.kafka_topic_events,
                normalized,
                key=endpoint["id"],
            )
            published += 1
        except Exception as exc:
            logger.warning("Failed to normalize event: %s", exc)

    logger.info("Ingested %d/%d events from endpoint %s", published, len(body.events), endpoint["id"])
    return {"accepted": published, "rejected": len(body.events) - published}

