import pytest
from app.models import User, HoneypotEvent
from conftest import TestingSessionLocal
from app.security import get_password_hash

def test_account_lockout_policy(client):
    # Try invalid password 5 times on admin account to trigger lockout
    for _ in range(5):
        res = client.post("/api/v1/auth/login", data={"username": "admin", "password": "WrongPassword123!"})
        assert res.status_code in [401, 403]

    # 6th attempt should be locked out (403 Forbidden)
    locked_res = client.post("/api/v1/auth/login", data={"username": "admin", "password": "WrongPassword123!"})
    assert locked_res.status_code == 403
    assert "locked" in locked_res.json()["detail"].lower()

    # Reset admin account for other tests
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        if user:
            user.locked_until = None
            user.failed_login_attempts = 0
            db.commit()
    finally:
        db.close()

def test_password_redaction_for_non_admin(client):
    db = TestingSessionLocal()
    try:
        if not db.query(User).filter(User.username == "analyst_tester").first():
            db.add(User(
                username="analyst_tester",
                email="analyst_tester@cyvantis.soc",
                hashed_password=get_password_hash("TesterPass@2026!"),
                role="analyst",
                is_active=True
            ))
            db.commit()
    finally:
        db.close()

    from app.security import create_access_token
    # Generate token for non-admin analyst
    analyst_token = create_access_token(data={"sub": "analyst_tester", "role": "analyst"})
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Fetch events as non-admin
    events_res = client.get("/api/v1/events?page=1&page_size=10", headers=headers)
    assert events_res.status_code == 200
    items = events_res.json()["items"]
    for item in items:
        if item.get("password"):
            assert "redacted" in item["password"]

def test_websocket_unauthenticated_rejection(client):
    # Connecting to WebSocket without token should fail with policy violation (1008)
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws/events") as ws:
            pass
