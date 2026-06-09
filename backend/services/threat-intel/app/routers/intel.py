"""
Threat Intel router — lookups and metadata query.
"""
import logging

from fastapi import APIRouter
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.threat_intel import ThreatIntel
from sqlalchemy import func, select

logger = logging.getLogger(__name__)
router = APIRouter()

# In production, load VT key from Settings
# settings = get_settings()
# vt_client = VirusTotalClient(settings.vt_api_key) if settings.vt_api_key else None
vt_client = None


@router.get(
    "/summary",
    summary="Get summary statistics of loaded threat intelligence",
)
async def get_intel_summary(db: DBSession) -> dict[str, int]:
    result = await db.execute(
        select(ThreatIntel.ioc_type, func.count(ThreatIntel.id))
        .group_by(ThreatIntel.ioc_type)
    )
    counts = {row[0]: row[1] for row in result.all()}
    return counts


@router.get(
    "/lookup/{ioc_value}",
    summary="Look up reputation of a specific IOC",
)
async def lookup_ioc(ioc_value: str, db: DBSession) -> dict:
    result = await db.execute(
        select(ThreatIntel).where(ThreatIntel.ioc_value == ioc_value)
    )
    ioc = result.scalar_one_or_none()

    if ioc:
        return {
            "found": True,
            "source": "local_db",
            "ioc_value": ioc.ioc_value,
            "ioc_type": ioc.ioc_type,
            "reputation_score": ioc.reputation_score,
            "confidence": ioc.confidence,
            "description": ioc.description,
            "tags": ioc.tags,
        }

    # Fallback to VirusTotal lookup if configured
    if vt_client:
        # Check if it looks like a hash or IP
        if len(ioc_value) in (32, 40, 64):  # file hash
            res = await vt_client.lookup_hash(ioc_value)
            return {"source": "virustotal", **res}
        elif "." in ioc_value or ":" in ioc_value:  # IP/Domain
            res = await vt_client.lookup_ip(ioc_value)
            return {"source": "virustotal", **res}

    return {
        "found": False,
        "ioc_value": ioc_value,
        "reputation_score": 0.0,
        "message": "IOC not found in database and external lookup is not configured",
    }
