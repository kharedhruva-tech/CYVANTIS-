import datetime
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models import HoneypotEvent
from app.geoip_service import enrich_ip
from app.websocket import manager
from app.ingestion.base import NormalizedEvent
from app.services.detection_engine import detection_engine
from app.services.incident_correlator import incident_correlator
from app.ml.predictor import predict_single_event

logger = logging.getLogger(__name__)

async def process_normalized_event(norm_ev: NormalizedEvent, db: Session) -> Dict[str, Any]:
    """
    End-to-End Event Processing Pipeline:
    1. Idempotency Check (SHA-256 Event Hash Deduplication)
    2. GeoIP & ASN Metadata Enrichment
    3. Machine Learning Inference & Anomaly Scoring
    4. Database Persistence (HoneypotEvent)
    5. Detection Engine (Deterministic Rules & Anomaly Match)
    6. Incident Correlation & Explainable Risk Scoring (5-Factor Formula)
    7. Real-Time WebSocket Telemetry Broadcast to SOC Dashboard Clients
    """
    # 1. Idempotency Check / Deduplication
    event_hash = norm_ev.event_hash or norm_ev.compute_hash()
    existing = db.query(HoneypotEvent).filter(HoneypotEvent.event_hash == event_hash).first()
    if existing:
        return {
            "success": True,
            "status": "duplicate",
            "event_id": existing.id,
            "event_hash": event_hash,
            "evaluated_severity": existing.severity,
            "findings_count": 0,
            "incident_id": None,
            "risk_score": None,
            "is_anomalous": False,
            "message": f"Duplicate event rejected. Event ID {existing.id} already exists with hash {event_hash[:12]}..."
        }

    # 2. GeoIP & ASN Enrichment
    geo = enrich_ip(norm_ev.src_ip)
    country = norm_ev.country if norm_ev.country != "Unknown" else geo.get("country", "Unknown")
    country_code = norm_ev.country_code if norm_ev.country_code != "XX" else geo.get("country_code", "XX")
    city = norm_ev.city if norm_ev.city != "Unknown" else geo.get("city", "Unknown")
    asn = norm_ev.asn if norm_ev.asn != "AS0000 Unknown" else geo.get("asn", "AS0000 Unknown")

    # 3. Machine Learning Inference & Anomaly Scoring
    event_payload = {
        "eventid": norm_ev.event_id,
        "command": norm_ev.command,
        "username": norm_ev.username,
        "password": norm_ev.password,
        "protocol": norm_ev.protocol,
        "dst_port": norm_ev.dst_port,
        "duration": norm_ev.duration
    }
    ml_res = predict_single_event(event_payload)

    # Reconcile severity: combine rule priority and ML prediction
    final_severity = norm_ev.severity
    if ml_res.get("predicted_severity") in ["critical", "high"] and norm_ev.severity in ["low", "medium"]:
        final_severity = ml_res.get("predicted_severity")

    # 4. Save HoneypotEvent record
    event_record = HoneypotEvent(
        eventid=norm_ev.event_id,
        timestamp=norm_ev.timestamp,
        src_ip=norm_ev.src_ip,
        dst_port=norm_ev.dst_port,
        protocol=norm_ev.protocol,
        username=norm_ev.username,
        password=norm_ev.password,
        command=norm_ev.command,
        file_hash=norm_ev.file_hash,
        session_id=norm_ev.session_id,
        duration=norm_ev.duration,
        country=country,
        country_code=country_code,
        city=city,
        asn=asn,
        severity=final_severity,
        is_simulated=norm_ev.is_simulated,
        data_source=norm_ev.data_source,
        event_hash=event_hash,
        raw_payload=norm_ev.raw_payload
    )
    db.add(event_record)
    db.commit()
    db.refresh(event_record)

    # 5. Detection Engine: Evaluate configured rules & anomalies
    findings = detection_engine.evaluate_event(norm_ev, db=db, ml_prediction=ml_res)

    # 6. Incident Correlation & Explainable Risk Prioritization
    target_alert = None
    if findings:
        target_alert = incident_correlator.correlate_and_process(
            event_id=event_record.id,
            event_dict=norm_ev.to_dict(),
            findings=findings,
            db=db,
            ml_prediction=ml_res
        )

    # 7. Real-Time WebSocket Event Broadcast to Authorized Dashboard Clients
    broadcast_data = {
        "id": event_record.id,
        "eventid": event_record.eventid,
        "timestamp": event_record.timestamp.isoformat(),
        "src_ip": event_record.src_ip,
        "dst_port": event_record.dst_port,
        "protocol": event_record.protocol,
        "username": event_record.username,
        "password": event_record.password,
        "command": event_record.command,
        "file_hash": event_record.file_hash,
        "session_id": event_record.session_id,
        "duration": event_record.duration,
        "country": event_record.country,
        "country_code": event_record.country_code,
        "city": event_record.city,
        "asn": event_record.asn,
        "severity": event_record.severity,
        "is_simulated": event_record.is_simulated,
        "data_source": event_record.data_source
    }
    try:
        await manager.broadcast_event(broadcast_data)
    except Exception as e:
        logger.debug("WebSocket broadcast error: %s", e)

    # Console Telemetry Log with explicit source labeling
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    mode_label = "[SIMULATED DEMO]" if norm_ev.is_simulated else f"[{norm_ev.data_source.upper()}]"
    cmd_info = f"cmd='{norm_ev.command[:35]}...'" if norm_ev.command and len(norm_ev.command) > 35 else (f"cmd='{norm_ev.command}'" if norm_ev.command else "")
    print(f"[+] [{now_str}] {mode_label} [{final_severity.upper()}] {norm_ev.protocol} {norm_ev.event_id} from {norm_ev.src_ip} ({country}) {cmd_info}", flush=True)

    return {
        "success": True,
        "status": "persisted",
        "event_id": event_record.id,
        "event_hash": event_hash,
        "evaluated_severity": final_severity,
        "findings_count": len(findings) if findings else 0,
        "incident_id": target_alert.incident_id if target_alert else None,
        "risk_score": target_alert.risk_score if target_alert else None,
        "is_anomalous": bool(ml_res.get("is_anomalous")),
        "message": "Event successfully ingested, persisted, evaluated, and correlated."
    }

