"""
Agent registration and heartbeat.
Handles initial registration with the backend and token persistence.
"""
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from sentinelx_agent.config import AgentConfig

logger = logging.getLogger("sentinelx.registration")


class AgentRegistrar:
    def __init__(self, config: "AgentConfig") -> None:
        self._config = config

    async def register_or_restore(self) -> str:
        """Return existing token or register with the backend."""
        token_path = self._config.token_path

        if token_path.exists():
            token = token_path.read_text().strip()
            if token:
                logger.info("Restored existing agent token from %s", token_path)
                return token

        return await self._register()

    async def _register(self) -> str:
        """Register this agent with the telemetry service."""
        logger.info("Registering agent with %s...", self._config.api_url)

        payload = {
            "hostname": self._config.hostname,
            "os_type": self._config.os_type.lower(),
            "os_version": self._config.os_version[:100],
            "agent_version": self._config.agent_version,
        }

        async with httpx.AsyncClient(
            base_url=self._config.api_url,
            timeout=self._config.api_timeout,
        ) as client:
            for attempt in range(1, 6):
                try:
                    response = await client.post("/endpoints/register", json=payload)
                    response.raise_for_status()
                    data = response.json()
                    token = data["agent_token"]

                    # Persist token securely
                    token_path = self._config.token_path
                    token_path.parent.mkdir(parents=True, exist_ok=True)
                    token_path.write_text(token)
                    token_path.chmod(0o600)  # Owner read/write only

                    logger.info(
                        "✅ Agent registered successfully. Token saved to %s", token_path
                    )
                    return token

                except httpx.ConnectError:
                    logger.warning(
                        "Cannot connect to %s (attempt %d/5). Retrying in %ds...",
                        self._config.api_url, attempt, attempt * 2,
                    )
                    import asyncio
                    await asyncio.sleep(attempt * 2)
                except httpx.HTTPStatusError as exc:
                    logger.error("Registration failed: %s", exc.response.text)
                    raise

        raise RuntimeError(
            f"Failed to register agent after 5 attempts. "
            f"Is the backend reachable at {self._config.api_url}?"
        )
