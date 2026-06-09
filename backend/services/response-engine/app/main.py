"""
Response Engine Service — executes automated response actions.
Receives action commands from Kafka and dispatches to agents.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentinelx_shared.config import get_settings

from app.routers import response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Response Engine service starting up...")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX Response Engine",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.include_router(response.router, prefix="/response", tags=["Response"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "response-engine"}

    return app


app = create_app()
