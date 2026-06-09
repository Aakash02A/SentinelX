"""
AI Analyst Service — LangGraph-powered SOC analyst agent.
Provides incident summary, root cause analysis, MITRE mapping,
and natural language threat hunting.
"""
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sentinelx_shared.config import get_settings

from app.routers import analysis, hunting

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("AI Analyst service starting up...")
    yield
    logger.info("AI Analyst service shutting down...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelX AI SOC Analyst",
        description="LangGraph-powered AI security analyst for incident investigation",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        lifespan=lifespan,
    )

    app.include_router(analysis.router, prefix="/ai", tags=["AI Analysis"])
    app.include_router(hunting.router, prefix="/ai", tags=["Threat Hunting"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "ai-analyst"}

    return app


app = create_app()
