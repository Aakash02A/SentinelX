"""
ML Engine Service — Kafka consumer that runs anomaly detection
and malware classification on incoming events.
"""
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import consume_forever, make_consumer, publish

from app.pipeline.inference import run_inference

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    consumer = make_consumer(
        topics=[settings.kafka_topic_events],
        group_id="ml-engine",
    )
    task = asyncio.create_task(_consume_events(consumer))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def _consume_events(consumer) -> None:
    async for event in consume_forever(consumer, dlq_topic=settings.kafka_topic_dlq):
        try:
            result = await run_inference(event)
            if result["anomaly_score"] > 0.5 or result["malware_probability"] > 0.5:
                await publish(
                    settings.kafka_topic_alerts,
                    {**event, "ml_result": result},
                    key=event.get("agent", {}).get("id"),
                )
        except Exception as exc:
            logger.error("ML inference error: %s", exc, exc_info=True)


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX ML Engine",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "ml-engine"}

    return app


app = create_app()
