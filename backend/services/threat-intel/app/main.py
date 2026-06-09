"""
Threat Intelligence Service — FastAPI app.
Integrates VirusTotal, AbuseIPDB, AlienVault OTX, MISP, and NVD.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentinelx_shared.config import get_settings

from app.routers import feeds, intel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Threat Intelligence service starting up...")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX Threat Intelligence Service",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.include_router(intel.router, prefix="/threatintel", tags=["Threat Intel"])
    app.include_router(feeds.router, prefix="/feeds", tags=["IOC Feeds"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "threat-intel"}

    return app


app = create_app()
