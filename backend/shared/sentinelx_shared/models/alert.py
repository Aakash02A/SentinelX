"""Alert ORM model."""
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelx_shared.db import Base


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertSource(StrEnum):
    RULE_ENGINE = "rule_engine"
    ML_ENGINE = "ml_engine"
    THREAT_INTEL = "threat_intel"
    CORRELATION = "correlation"
    MANUAL = "manual"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="SET NULL"), index=True
    )
    assigned_to: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL")
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), nullable=False, index=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.NEW, nullable=False, index=True
    )
    source: Mapped[AlertSource] = mapped_column(
        Enum(AlertSource), nullable=False
    )

    # MITRE ATT&CK mapping
    mitre_tactic: Mapped[str | None] = mapped_column(String(100))
    mitre_technique: Mapped[str | None] = mapped_column(String(50))   # e.g. T1059.001

    # Threat score at time of alert (0-100)
    threat_score: Mapped[float] = mapped_column(nullable=False, index=True)

    # AI-generated narrative
    ai_summary: Mapped[str | None] = mapped_column(Text)

    # Raw detection context
    raw_context: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Timestamps
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship(back_populates="alerts")
    incident: Mapped["Incident | None"] = relationship(back_populates="alert")

    def __repr__(self) -> str:
        return f"<Alert id={self.id} severity={self.severity} status={self.status}>"
