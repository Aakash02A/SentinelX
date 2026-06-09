"""
Alerts router — query and update security alerts.
"""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from sqlalchemy import select

router = APIRouter()


class AlertResponse(BaseModel):
    id: str
    endpoint_id: str
    event_id: str | None
    assigned_to: str | None
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: AlertSource
    mitre_technique: str | None
    threat_score: float
    raw_context: dict[str, Any]
    triggered_at: datetime
    updated_at: datetime
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


class UpdateAlertRequest(BaseModel):
    status: AlertStatus | None = None
    assigned_to: str | None = None


@router.get(
    "",
    response_model=list[AlertResponse],
    summary="List all alerts with optional status/severity filters",
)
async def list_alerts(
    db: DBSession,
    status: AlertStatus | None = None,
    severity: AlertSeverity | None = None,
    endpoint_id: str | None = None,
) -> list[Alert]:
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if endpoint_id:
        query = query.where(Alert.endpoint_id == endpoint_id)

    query = query.order_by(Alert.triggered_at.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert by ID",
)
async def get_alert(alert_id: str, db: DBSession) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert status or assignee",
)
async def update_alert(
    alert_id: str,
    body: UpdateAlertRequest,
    db: DBSession,
) -> Alert:
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if body.status is not None:
        alert.status = body.status
        if body.status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
            alert.resolved_at = datetime.utcnow()
    if body.assigned_to is not None:
        alert.assigned_to = body.assigned_to

    await db.flush()
    return alert
