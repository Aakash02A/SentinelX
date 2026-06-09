"""
Threat intelligence feeds router.
"""
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, status
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.threat_intel import IOCType, ThreatIntel

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/refresh",
    status_code=status.HTTP_200_OK,
    summary="Trigger threat intelligence feed refresh and sync",
)
async def refresh_feeds(db: DBSession) -> dict[str, str | int]:
    # Mock refresh logic — seeds the database with initial known malicious IOCs
    # so that rule engine / ML engine have some data to match against.

    sample_iocs = [
        # Malicious IP
        {
            "ioc_value": "185.190.140.23",
            "ioc_type": IOCType.IP,
            "reputation_score": 85.0,
            "confidence": 90.0,
            "source": "AbuseIPDB",
            "description": "Known C2 Beacon IP / Cobalt Strike",
            "tags": "c2,cobalt_strike",
        },
        # Ransomware File Hash
        {
            "ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty file, but used as sample
            "ioc_type": IOCType.FILE_HASH_SHA256,
            "reputation_score": 100.0,
            "confidence": 95.0,
            "source": "VirusTotal",
            "description": "WannaCry ransomware variant loader hash",
            "tags": "ransomware,wannacry",
        },
        # Malicious domain
        {
            "ioc_value": "update.microsoft-security-patches.net",
            "ioc_type": IOCType.DOMAIN,
            "reputation_score": 90.0,
            "confidence": 80.0,
            "source": "AlienVault OTX",
            "description": "Phishing domain masquerading as Microsoft Update",
            "tags": "phishing,masquerade",
        },
    ]

    inserted = 0
    for sample in sample_iocs:
        # Check if already exists
        from sqlalchemy import select
        result = await db.execute(
            select(ThreatIntel).where(ThreatIntel.ioc_value == sample["ioc_value"])
        )
        if not result.scalar_one_or_none():
            ioc = ThreatIntel(
                ioc_value=sample["ioc_value"],
                ioc_type=sample["ioc_type"],
                reputation_score=sample["reputation_score"],
                confidence=sample["confidence"],
                source=sample["source"],
                description=sample["description"],
                tags=sample["tags"],
                is_active=True,
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
            )
            db.add(ioc)
            inserted += 1

    await db.flush()
    logger.info("Threat intelligence feeds sync completed. Loaded %d new IOCs.", inserted)
    return {"message": "Sync completed", "new_iocs_loaded": inserted}
