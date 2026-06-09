"""Security Event ORM model — stores normalized telemetry from agents."""
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelx_shared.db import Base


class EventType(StrEnum):
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    FILE_RENAME = "file_rename"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_DNS = "network_dns"
    REGISTRY_SET = "registry_set"
    REGISTRY_DELETE = "registry_delete"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_PRIVILEGE_ESCALATION = "user_privilege_escalation"
    SYSTEM_HEALTH = "system_health"
    ALERT_TRIGGERED = "alert_triggered"


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[EventType] = mapped_column(
        Enum(EventType), nullable=False, index=True
    )

    # Normalized ECS (Elastic Common Schema) payload
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Quick-access denormalized fields (indexed for fast queries)
    process_name: Mapped[str | None] = mapped_column(String(255), index=True)
    process_pid: Mapped[int | None] = mapped_column()
    file_path: Mapped[str | None] = mapped_column(Text)
    network_src_ip: Mapped[str | None] = mapped_column(String(45))
    network_dst_ip: Mapped[str | None] = mapped_column(String(45))
    network_dst_port: Mapped[int | None] = mapped_column()
    user_name: Mapped[str | None] = mapped_column(String(255), index=True)

    # Scoring
    rule_score: Mapped[float] = mapped_column(default=0.0, nullable=False)
    ml_score: Mapped[float] = mapped_column(default=0.0, nullable=False)
    threat_score: Mapped[float] = mapped_column(default=0.0, nullable=False, index=True)

    # Timestamps
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship(back_populates="events")

    def __repr__(self) -> str:
        return f"<Event id={self.id} type={self.event_type} score={self.threat_score}>"
