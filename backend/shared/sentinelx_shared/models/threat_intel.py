"""Threat Intelligence IOC model."""
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinelx_shared.db import Base


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "hash_md5"
    FILE_HASH_SHA1 = "hash_sha1"
    FILE_HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    ioc_type: Mapped[IOCType] = mapped_column(
        String(30), nullable=False, index=True
    )

    # Reputation scores (0-100, higher = more malicious)
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Source feed
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # virustotal, abuseipdb, etc.
    tags: Mapped[str | None] = mapped_column(Text)   # JSON array stored as text for MySQL compat
    description: Mapped[str | None] = mapped_column(Text)

    # CVE fields (populated if ioc_type == cve)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<ThreatIntel {self.ioc_type}={self.ioc_value} score={self.reputation_score}>"
