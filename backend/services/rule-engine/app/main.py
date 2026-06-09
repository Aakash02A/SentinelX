"""
Rule Engine Service — FastAPI app.
Consumes ECS events from Kafka, runs detections, and outputs alerts.
"""
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import stop_producer

from app.consumers.event_consumer import consume_events, ioc_refresh_loop

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()

# Background tasks references to keep them from being garbage collected
_background_tasks = set()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Rule Engine starting up...")

    # Run Kafka event consumer in background task
    consumer_task = asyncio.create_task(consume_events())
    refresh_task = asyncio.create_task(ioc_refresh_loop())

    _background_tasks.add(consumer_task)
    _background_tasks.add(refresh_task)

    consumer_task.add_done_callback(_background_tasks.discard)
    refresh_task.add_done_callback(_background_tasks.discard)

    yield

    logger.info("Rule Engine shutting down...")
    for task in _background_tasks:
        task.cancel()
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    await stop_producer()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX Rule Engine Service",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "rule-engine"}

    return app


app = create_app()
