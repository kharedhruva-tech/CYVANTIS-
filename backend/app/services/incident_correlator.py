import datetime
import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models import Investigation, Alert, HoneypotEvent
from app.services.detection_engine import DetectionFinding
from app.services.risk_scoring import risk_scoring_service
from app.services.threat_intelligence import threat_intel_service
from app.websocket import manager

logger = logging.getLogger(__name__)

class IncidentCorrelator:
    """
    Correlates security detections and raw events across source, session, IOC, time window, and attack pattern.
    Groups related alerts into persistent Incident investigations, prevents duplicate alert floods,
    preserves event provenance, and computes explainable risk scores.
    """
    CORRELATION_WINDOW_MINUTES = 30
    ALERT_DEDUP_WINDOW_MINUTES = 5

    def correlate_and_process(
        self,
        event_id: int,
        event_dict: Dict[str, Any],
        findings: List[DetectionFinding],
        db: Session,
        ml_prediction: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        if not findings or not db:
            return None

        now = datetime.datetime.utcnow()
        correlation_window = now - datetime.timedelta(minutes=self.CORRELATION_WINDOW_MINUTES)
        src_ip = event_dict.get("src_ip", "0.0.0.0")
        session_id = event_dict.get("session_id")

        # 1. Enrich threat reputation for risk scoring
        intel_result = threat_intel_service.enrich_ip(src_ip, db=db)
        intel_score = intel_result.get("threat_score", 20.0)

        # 2. Correlate with existing open Incident (Investigation)
        existing_incident = db.query(Investigation).filter(
            Investigation.status.in_(["open", "in_progress"]),
            Investigation.description.like(f"%{src_ip}%"),
            Investigation.updated_at >= correlation_window
        ).order_by(Investigation.updated_at.desc()).first()

        primary_finding = max(findings, key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity.lower(), 1))

        if existing_incident:
            incident = existing_incident
            # Update related events provenance list
            related_ids = []
            if incident.related_events:
                try:
                    related_ids = json.loads(incident.related_events)
                except Exception:
                    related_ids = []
            if event_id not in related_ids:
                related_ids.append(event_id)
            incident.related_events = json.dumps(related_ids)
            incident.updated_at = now

            event_count = len(related_ids)
        else:
            # Create new correlated Incident
            event_count = 1
            incident = Investigation(
                title=f"Incident: Adversarial Activity from {src_ip}",
                description=f"Correlated security incident targeting gateway. Vector: {primary_finding.title}. Source IP: {src_ip}.",
                severity=primary_finding.severity,
                status="open",
                asset_tier="Critical Gateway",
                created_at=now,
                updated_at=now,
                related_events=json.dumps([event_id])
            )
            db.add(incident)
            db.flush() # Populate incident.id

        # 3. Calculate Explainable Risk Score
        is_anom = bool(ml_prediction and ml_prediction.get("is_anomalous"))
        anom_val = float(ml_prediction.get("anomaly_score", 0.0)) if ml_prediction else 0.0

        risk_eval = risk_scoring_service.calculate_risk(
            severity=primary_finding.severity,
            threat_intel_score=intel_score,
            event_count=event_count,
            is_anomalous=is_anom,
            anomaly_score=anom_val,
            asset_tier=incident.asset_tier or "Critical Gateway",
            confidence=primary_finding.confidence
        )

        incident.risk_score = risk_eval["risk_score"]
        if primary_finding.severity == "critical" or risk_eval["priority"] == "CRITICAL":
            incident.severity = "critical"
        elif primary_finding.severity == "high" or risk_eval["priority"] == "HIGH":
            incident.severity = "high"

        # 4. Deduplicate and Persist Alerts
        dedup_window = now - datetime.timedelta(minutes=self.ALERT_DEDUP_WINDOW_MINUTES)
        existing_alert = db.query(Alert).filter(
            Alert.rule_name == primary_finding.rule_name,
            Alert.src_ip == src_ip,
            Alert.status == "active",
            Alert.timestamp >= dedup_window
        ).first()

        evidence_payload = {
            "triggering_event_id": event_id,
            "session_id": session_id,
            "all_findings": [f.to_dict() for f in findings],
            "risk_evaluation": risk_eval,
            "threat_intel": intel_result
        }

        if existing_alert:
            # Deduplicate by updating existing alert
            existing_alert.timestamp = now
            existing_alert.description = (
                f"{primary_finding.explanation} [Aggregated {event_count} events from {src_ip}]"
            )
            existing_alert.risk_score = risk_eval["risk_score"]
            existing_alert.risk_factors = json.dumps(risk_eval["factors"])
            existing_alert.evidence = json.dumps(evidence_payload)
            target_alert = existing_alert
        else:
            # Create new persistent Alert record
            target_alert = Alert(
                timestamp=now,
                title=primary_finding.title,
                description=primary_finding.explanation,
                severity=primary_finding.severity,
                rule_name=primary_finding.rule_name,
                src_ip=src_ip,
                status="active",
                risk_score=risk_eval["risk_score"],
                risk_factors=json.dumps(risk_eval["factors"]),
                incident_id=incident.id,
                mitre_tactics=primary_finding.mitre_tactics,
                mitre_techniques=primary_finding.mitre_techniques,
                recommended_actions=json.dumps(primary_finding.recommended_actions),
                evidence=json.dumps(evidence_payload),
                is_acknowledged=False
            )
            db.add(target_alert)

        try:
            db.commit()
            db.refresh(target_alert)
        except Exception as e:
            db.rollback()
            logger.error("Failed to commit alert/incident: %s", e)
            return None

        # 5. Broadcast real-time alert via WebSocket to authorized dashboard clients
        alert_broadcast_payload = {
            "id": target_alert.id,
            "timestamp": target_alert.timestamp.isoformat(),
            "title": target_alert.title,
            "description": target_alert.description,
            "severity": target_alert.severity,
            "rule_name": target_alert.rule_name,
            "src_ip": target_alert.src_ip,
            "status": target_alert.status,
            "risk_score": target_alert.risk_score,
            "incident_id": target_alert.incident_id,
            "mitre_tactics": target_alert.mitre_tactics,
            "mitre_techniques": target_alert.mitre_techniques,
            "recommended_actions": json.loads(target_alert.recommended_actions or "[]")
        }

        # Schedule async broadcast via event loop if running
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(manager.broadcast_alert(alert_broadcast_payload))
        except Exception as e:
            logger.debug("Could not schedule alert broadcast: %s", e)

        return target_alert

incident_correlator = IncidentCorrelator()
