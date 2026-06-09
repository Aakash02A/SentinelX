"""
Telemetry Ingestion Service — FastAPI app.
Receives events from agents, normalizes to ECS, publishes to Kafka.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import stop_producer

from app.routers import events, telemetry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Telemetry service starting up...")
    yield
    logger.info("Telemetry service shutting down...")
    await stop_producer()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX Telemetry Ingestion Service",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],   # Agents connect from anywhere; auth via token
        allow_methods=["POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(telemetry.router, prefix="/telemetry", tags=["Telemetry"])
    app.include_router(events.router, prefix="/events", tags=["Events"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "telemetry"}

    return app


app = create_app()
