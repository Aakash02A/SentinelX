"""
Alert Engine Service — consumes detection results from Kafka,
correlates events, scores threats, and creates Alerts + Incidents.
"""
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import consume_forever, make_consumer

from app.routers import alerts, incidents
from app.services.correlation import CorrelationEngine
from app.services.scoring import ThreatScoringEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()

_correlation = CorrelationEngine()
_scoring = ThreatScoringEngine()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Start background consumer task
    consumer = make_consumer(
        topics=[settings.kafka_topic_alerts],
        group_id="alert-engine",
    )
    task = asyncio.create_task(_consume_alerts(consumer))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def _consume_alerts(consumer) -> None:
    async for event in consume_forever(consumer, dlq_topic=settings.kafka_topic_dlq):
        try:
            await _correlation.process(event)
        except Exception as exc:
            logger.error("Alert processing error: %s", exc, exc_info=True)


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX Alert Engine",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
    app.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "alert-engine"}

    return app


app = create_app()
