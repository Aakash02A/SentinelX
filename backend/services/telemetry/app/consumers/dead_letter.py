"""
Dead letter queue (DLQ) consumer — listens for failed events and logs/persists them.
"""
import asyncio
import logging

from sentinelx_shared.config import get_settings
from sentinelx_shared.kafka_client import get_kafka_consumer

logger = logging.getLogger(__name__)
settings = get_settings()


async def consume_dlq() -> None:
    """Consume from DLQ topic and log/store failures."""
    consumer = get_kafka_consumer(settings.kafka_topic_dlq, group_id="telemetry-dlq-group")
    if not consumer:
        logger.warning("Kafka consumer not configured. DLQ consumer not started.")
        return

    logger.info("DLQ consumer started. Listening on topic: %s", settings.kafka_topic_dlq)
    try:
        async for msg in consumer:
            logger.error("DLQ Message Received: %s (Key: %s)", msg.value, msg.key)
            # In production, we might write these raw payloads to a dead-letter storage
            # (e.g. S3 or a specific DB table) for manual investigation and replay.
    except asyncio.CancelledError:
        logger.info("DLQ consumer task cancelled.")
    except Exception as exc:
        logger.critical("DLQ consumer encountered error: %s", exc, exc_info=True)
    finally:
        await consumer.stop()
