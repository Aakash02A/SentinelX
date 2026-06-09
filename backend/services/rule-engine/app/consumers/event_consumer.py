"""
Kafka event consumer — consumes events, evaluates Sigma rules and IOCs, and generates alerts.
"""
import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx_shared.config import get_settings
from sentinelx_shared.db import AsyncSessionLocal
from sentinelx_shared.kafka_client import get_kafka_consumer, publish
from sentinelx_shared.models.threat_intel import IOCType, ThreatIntel
from sqlalchemy import select

from app.engines.ioc_matcher import IOCMatcher
from app.engines.sigma import SigmaRuleEngine

logger = logging.getLogger(__name__)
settings = get_settings()

sigma_engine = SigmaRuleEngine()
ioc_matcher = IOCMatcher()

# Load rules from rules/ directory
rules_dir = Path(__file__).resolve().parent.parent.parent / "rules"
sigma_engine.load_directory(rules_dir)


async def refresh_iocs() -> None:
    """Refresh the IOC cache from the database."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ThreatIntel).where(ThreatIntel.is_active == True)
            )
            iocs = result.scalars().all()

            ips = [i.ioc_value for i in iocs if i.ioc_type == IOCType.IP]
            domains = [i.ioc_value for i in iocs if i.ioc_type == IOCType.DOMAIN]
            hashes = [
                i.ioc_value
                for i in iocs
                if i.ioc_type in (IOCType.FILE_HASH_SHA256, IOCType.FILE_HASH_MD5)
            ]
            urls = [i.ioc_value for i in iocs if i.ioc_type == IOCType.URL]

            ioc_matcher.load_iocs(ips=ips, domains=domains, hashes=hashes, urls=urls)
    except Exception as exc:
        logger.error("Failed to refresh IOCs from database: %s", exc)


async def consume_events() -> None:
    """Consume events from Kafka, evaluate rules, and emit alerts."""
    await refresh_iocs()

    # Create Kafka consumer
    consumer = get_kafka_consumer(
        settings.kafka_topic_events,
        group_id="rule-engine-group",
    )
    if not consumer:
        logger.warning("Kafka consumer not configured. Rule engine consumer not started.")
        return

    logger.info(
        "Rule Engine consumer started. Listening on: %s",
        settings.kafka_topic_events,
    )

    try:
        async for msg in consumer:
            try:
                # Parse event
                event = json.loads(msg.value.decode("utf-8"))
                await process_event(event)
            except Exception as exc:
                logger.error("Error processing event: %s", exc)
    except asyncio.CancelledError:
        logger.info("Rule Engine consumer task cancelled.")
    finally:
        await consumer.stop()


async def process_event(event: dict[str, Any]) -> None:
    """Evaluate a single event and generate alerts if matches are found."""
    endpoint_id = event.get("agent", {}).get("id", "unknown")

    # 1. Evaluate Sigma rules
    sigma_matches = sigma_engine.evaluate(event)
    for match in sigma_matches:
        alert = {
            "type": "rule",
            "endpoint_id": endpoint_id,
            "rule_id": match["rule_id"],
            "title": match["rule_title"],
            "description": f"Sigma rule match: {match['rule_title']}",
            "severity": match["severity"],
            "mitre_technique": match["mitre_technique"],
            "tags": match["tags"],
            "timestamp": datetime.now(UTC).isoformat(),
            "trigger_event": event,
        }
        await publish_alert(alert)

    # 2. Evaluate IOC matches
    ioc_matches = ioc_matcher.check_event(event)
    for match in ioc_matches:
        alert = {
            "type": "ioc",
            "endpoint_id": endpoint_id,
            "title": f"Malicious IOC Detected: {match['value']}",
            "description": f"Event contains known malicious {match['type']} IOC in {match['field']}",
            "severity": match["severity"],
            "mitre_technique": None,
            "tags": ["ioc", match["type"]],
            "timestamp": datetime.now(UTC).isoformat(),
            "trigger_event": event,
        }
        await publish_alert(alert)


async def publish_alert(alert: dict[str, Any]) -> None:
    """Publish the generated alert to the alerts Kafka topic."""
    logger.info("ALERT GENERATED: [%s] on Endpoint: %s", alert["title"], alert["endpoint_id"])
    await publish(
        settings.kafka_topic_alerts,
        alert,
        key=alert["endpoint_id"],
    )


async def ioc_refresh_loop() -> None:
    """Periodically refresh IOCs from the database."""
    while True:
        await asyncio.sleep(300)  # Refresh every 5 minutes
        await refresh_iocs()
