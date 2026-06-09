"""
Incidents router — track and manage security incidents.
"""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.incident import Incident, IncidentSeverity, IncidentStatus
from sqlalchemy import select

router = APIRouter()


class IncidentResponse(BaseModel):
    id: str
    alert_id: str
    owner_id: str | None
    title: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    timeline: list[dict[str, Any]]
    notes: str | None
    ai_root_cause: str | None
    ai_recommended_actions: list[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None

    model_config = {"from_attributes": True}


class UpdateIncidentRequest(BaseModel):
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    owner_id: str | None = None
    notes: str | None = None
    summary: str | None = None


class AddTimelineEntryRequest(BaseModel):
    actor: str
    action: str
    details: str = ""


@router.get(
    "",
    response_model=list[IncidentResponse],
    summary="List all incidents with optional filters",
)
async def list_incidents(
    db: DBSession,
    status: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
) -> list[Incident]:
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)

    query = query.order_by(Incident.created_at.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get incident by ID",
)
async def get_incident(incident_id: str, db: DBSession) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Update incident attributes",
)
async def update_incident(
    incident_id: str,
    body: UpdateIncidentRequest,
    db: DBSession,
) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if body.status is not None:
        incident.status = body.status
        if body.status == IncidentStatus.RESOLVED:
            incident.resolved_at = datetime.utcnow()
            incident.add_timeline_entry("analyst", "resolved_incident", "Incident resolved.")
        elif body.status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.utcnow()
            incident.add_timeline_entry("analyst", "closed_incident", "Incident closed.")
    if body.severity is not None:
        incident.severity = body.severity
    if body.owner_id is not None:
        incident.owner_id = body.owner_id
    if body.notes is not None:
        incident.notes = body.notes
    if body.summary is not None:
        incident.summary = body.summary

    await db.flush()
    return incident


@router.post(
    "/{incident_id}/timeline",
    response_model=IncidentResponse,
    summary="Add an entry to the incident timeline",
)
async def add_timeline_entry(
    incident_id: str,
    body: AddTimelineEntryRequest,
    db: DBSession,
) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident.add_timeline_entry(
        actor=body.actor,
        action=body.action,
        details=body.details,
    )
    await db.flush()
    return incident
