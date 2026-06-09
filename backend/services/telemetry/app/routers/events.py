"""
Events router — ingests individual events and logs from agents.
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


class LogPayload(BaseModel):
    agent_token: str
    log_level: str = Field(default="INFO")
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SingleEventPayload(BaseModel):
    agent_token: str
    event_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a single event",
)
async def ingest_event(body: SingleEventPayload, db: DBSession) -> dict[str, str]:
    endpoint = await validate_agent_token(db, body.agent_token)
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token",
        )

    try:
        normalized = normalize_event(
            {
                "event_type": body.event_type,
                "occurred_at": body.occurred_at.isoformat(),
                "payload": body.payload,
            },
            endpoint["id"],
        )
        await publish(
            settings.kafka_topic_events,
            normalized,
            key=endpoint["id"],
        )
        return {"status": "accepted"}
    except Exception as exc:
        logger.error("Failed to normalize/publish event: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest event",
        )


@router.post(
    "/logs",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest agent logs",
)
async def ingest_logs(body: LogPayload, db: DBSession) -> dict[str, str]:
    endpoint = await validate_agent_token(db, body.agent_token)
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token",
        )

    # Publish log message to Kafka telemetry / logs topic
    await publish(
        settings.kafka_topic_telemetry,
        {
            "type": "log",
            "endpoint_id": endpoint["id"],
            "log_level": body.log_level,
            "message": body.message,
            "timestamp": body.timestamp.isoformat(),
        },
        key=endpoint["id"],
    )
    return {"status": "accepted"}
