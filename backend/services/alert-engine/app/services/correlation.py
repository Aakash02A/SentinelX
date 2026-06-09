"""
Correlation Engine — processes incoming alerts, computes composite threat scores,
and promotes severe alerts/patterns to Incidents.
"""
import logging
from datetime import UTC, datetime
from typing import Any

from sentinelx_shared.db import AsyncSessionLocal
from sentinelx_shared.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from sentinelx_shared.models.endpoint import Endpoint, EndpointStatus
from sentinelx_shared.models.incident import Incident, IncidentSeverity, IncidentStatus
from sqlalchemy import select

from app.services.scoring import ThreatScoringEngine

logger = logging.getLogger(__name__)


class CorrelationEngine:
    def __init__(self) -> None:
        self.scoring_engine = ThreatScoringEngine()

    async def process(self, raw_alert: dict[str, Any]) -> None:
        """
        Correlate and store alert. Update endpoint threat score.
        If threat score is critical, automatically create an Incident.
        """
        async with AsyncSessionLocal() as session:
            try:
                endpoint_id = raw_alert.get("endpoint_id")
                if not endpoint_id:
                    logger.warning("Alert missing endpoint_id. Skipping correlation.")
                    return

                # Find endpoint
                result = await session.execute(
                    select(Endpoint).where(Endpoint.id == endpoint_id)
                )
                endpoint = result.scalar_one_or_none()
                if not endpoint:
                    logger.warning("Endpoint ID %s not found in DB. Skipping correlation.", endpoint_id)
                    return

                # Determine source
                alert_type = raw_alert.get("type", "rule")
                source = AlertSource.RULE_ENGINE
                if alert_type == "ml":
                    source = AlertSource.ML_ENGINE
                elif alert_type == "ioc":
                    source = AlertSource.THREAT_INTEL

                # Compute compound threat score
                # For a single alert, we just score it individually
                ml_score = 0.0
                if alert_type == "ml":
                    ml_score = float(raw_alert.get("ml_result", {}).get("ml_score", 0.0))

                rule_matches = []
                if alert_type == "rule":
                    rule_matches = [raw_alert]

                threat_intel_matches = []
                if alert_type == "ioc":
                    threat_intel_matches = [raw_alert]

                score_info = self.scoring_engine.compute(
                    rule_matches=rule_matches,
                    ml_score=ml_score,
                    threat_intel_matches=threat_intel_matches,
                )

                final_threat_score = score_info["threat_score"]
                severity = score_info["severity"]

                # Create Alert object
                alert = Alert(
                    endpoint_id=endpoint_id,
                    title=raw_alert.get("title", "Correlation Alert"),
                    description=raw_alert.get("description", "Alert correlation"),
                    severity=AlertSeverity(severity),
                    status=AlertStatus.NEW,
                    source=source,
                    mitre_technique=raw_alert.get("mitre_technique"),
                    threat_score=final_threat_score,
                    raw_context=raw_alert.get("trigger_event", raw_alert),
                    triggered_at=datetime.now(UTC),
                )
                session.add(alert)
                await session.flush()  # populate alert.id

                # Update endpoint threat score
                endpoint.threat_score = max(endpoint.threat_score, final_threat_score)
                endpoint.last_seen = datetime.now(UTC)

                # Auto-isolate endpoint if threat score is critical (> 90)
                if endpoint.threat_score >= 90.0 and endpoint.status == EndpointStatus.ACTIVE:
                    endpoint.status = EndpointStatus.ISOLATED
                    logger.warning("AUTO-ISOLATION: Endpoint %s isolated due to threat score: %s", endpoint.hostname, endpoint.threat_score)

                # Promote to Incident if threat score is high / critical (>= 75)
                if final_threat_score >= 75.0:
                    incident = Incident(
                        alert_id=alert.id,
                        title=f"Incident: {alert.title}",
                        summary=f"Automated incident promoted due to high threat score ({final_threat_score}) on endpoint {endpoint.hostname}.",
                        severity=IncidentSeverity(severity),
                        status=IncidentStatus.OPEN,
                        mitre_techniques=[alert.mitre_technique] if alert.mitre_technique else [],
                        timeline=[
                            {
                                "timestamp": datetime.now(UTC).isoformat(),
                                "actor": "system",
                                "action": "promote_incident",
                                "details": f"Alert {alert.id} promoted to Incident",
                            }
                        ],
                    )
                    session.add(incident)
                    logger.info("Incident created: %s for alert %s", incident.title, alert.id)

                await session.commit()
                logger.info("Successfully correlated alert for endpoint: %s (New Score: %s)", endpoint.hostname, endpoint.threat_score)

            except Exception as exc:
                await session.rollback()
                logger.error("Failed to run correlation process: %s", exc, exc_info=True)
                raise
