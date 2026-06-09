"""
Async HTTP client — ships telemetry batches to the backend with retry and offline buffering.
"""
import asyncio
import logging
from typing import Any, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from sentinelx_agent.config import AgentConfig

logger = logging.getLogger("sentinelx.transport")


class TelemetryClient:
    """
    Async telemetry client with:
    - In-memory event buffer
    - Configurable batch size and flush interval
    - Exponential backoff retry
    - Graceful offline handling
    """

    def __init__(self, config: "AgentConfig", agent_token: str) -> None:
        self._config = config
        self._agent_token = agent_token
        self._buffer: list[dict[str, Any]] = []
        self._client = httpx.AsyncClient(
            base_url=config.api_url,
            headers={
                "Authorization": f"Bearer {agent_token}",
                "Content-Type": "application/json",
                "User-Agent": f"SentinelX-Agent/{config.agent_version}",
            },
            timeout=config.api_timeout,
        )
        self._flush_task: asyncio.Task | None = None

    async def start_flush_loop(self) -> None:
        """Background task: flush buffer every N seconds."""
        while True:
            await asyncio.sleep(self._config.batch_flush_interval)
            await self.flush()

    async def enqueue(self, event: dict[str, Any]) -> None:
        """Add an event to the buffer. Flushes if batch_size reached."""
        self._buffer.append(event)
        if len(self._buffer) >= self._config.batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Send all buffered events to the backend."""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()

        success = await self._send_with_retry(
            "/telemetry/batch",
            payload={
                "agent_token": self._agent_token,
                "events": batch,
            },
        )

        if not success:
            # Re-queue on failure (up to buffer limit)
            overflow = max(0, len(self._buffer) + len(batch) - 10000)
            self._buffer.extend(batch[overflow:])
            logger.warning("Events re-queued. Buffer size: %d", len(self._buffer))

    async def heartbeat_loop(self) -> None:
        """Send periodic heartbeat with system metrics."""
        import psutil

        while True:
            try:
                await self._send_with_retry(
                    "/telemetry/heartbeat",
                    payload={
                        "agent_token": self._agent_token,
                        "hostname": self._config.hostname,
                        "agent_version": self._config.agent_version,
                        "cpu_percent": psutil.cpu_percent(interval=1),
                        "ram_percent": psutil.virtual_memory().percent,
                        "disk_percent": psutil.disk_usage("/").percent,
                    },
                )
                logger.debug("Heartbeat sent")
            except Exception as exc:
                logger.warning("Heartbeat failed: %s", exc)
            await asyncio.sleep(self._config.heartbeat_interval)

    async def _send_with_retry(
        self,
        path: str,
        payload: dict[str, Any],
        max_retries: int = 3,
    ) -> bool:
        """POST payload with exponential backoff. Returns True on success."""
        delay = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                response = await self._client.post(path, json=payload)
                response.raise_for_status()
                return True
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500:
                    logger.error("Client error %s for %s", exc.response.status_code, path)
                    return False  # Don't retry 4xx
                logger.warning("Server error (attempt %d/%d): %s", attempt, max_retries, exc)
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                logger.warning("Connection error (attempt %d/%d): %s", attempt, max_retries, exc)

            if attempt < max_retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)  # Cap at 30 seconds

        return False

    async def close(self) -> None:
        await self.flush()
        await self._client.aclose()
