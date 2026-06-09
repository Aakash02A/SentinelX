"""Endpoint (registered device) ORM model."""
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelx_shared.db import Base


class EndpointStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ISOLATED = "isolated"
    QUARANTINED = "quarantined"


class OSType(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os_type: Mapped[OSType] = mapped_column(
        Enum(OSType), default=OSType.UNKNOWN, nullable=False
    )
    os_version: Mapped[str | None] = mapped_column(String(100))
    agent_version: Mapped[str | None] = mapped_column(String(50))
    agent_token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    status: Mapped[EndpointStatus] = mapped_column(
        Enum(EndpointStatus), default=EndpointStatus.ACTIVE, nullable=False, index=True
    )
    threat_score: Mapped[float] = mapped_column(default=0.0, nullable=False)

    # Timestamps
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    # Relationships
    owner: Mapped["User"] = relationship(back_populates="endpoints")
    events: Mapped[list["Event"]] = relationship(back_populates="endpoint", lazy="dynamic")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="endpoint", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Endpoint id={self.id} hostname={self.hostname} status={self.status}>"
