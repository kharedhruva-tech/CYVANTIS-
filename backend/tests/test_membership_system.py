import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import User
from app.security import get_password_hash
from app.config import settings

client = TestClient(app)

def get_auth_token(username: str, password: str = None) -> str:
    if password is None:
        password = settings.ADMIN_DEFAULT_PASSWORD
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                username=username,
                email=f"{username}@cyvantis.soc",
                hashed_password=get_password_hash(password),
                role="viewer",
                is_active=True,
                must_change_password=False,
                is_totp_enabled=False
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            # Ensure user is not locked or forced into TOTP by other tests
            user.is_totp_enabled = False
            user.must_change_password = False
            user.hashed_password = get_password_hash(password)
            db.commit()
    finally:
        db.close()

    res = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password}
    )
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]

# -----------------------------------------------------------------------------
# 1. Test Membership Plans Retrieval
# -----------------------------------------------------------------------------
def test_get_membership_plans():
    res = client.get("/api/v1/memberships/plans")
    assert res.status_code == 200
    plans = res.json()
    assert len(plans) >= 4

    codes = [p["code"] for p in plans]
    assert "free" in codes
    assert "monthly" in codes
    assert "quarterly" in codes
    assert "yearly" in codes

    monthly = next(p for p in plans if p["code"] == "monthly")
    assert monthly["price_inr"] == 49.0
    assert monthly["duration_days"] == 30
    assert monthly["tier"] == "premium"

    yearly = next(p for p in plans if p["code"] == "yearly")
    assert yearly["price_inr"] == 399.0
    assert yearly["duration_days"] == 365
    assert yearly["daily_scan_limit"] == -1

# -----------------------------------------------------------------------------
# 2. Test User Subscriptions (Admin vs Regular User)
# -----------------------------------------------------------------------------
def test_subscription_resolution():
    # Admin has permanent enterprise clearance
    admin_token = get_auth_token("admin")
    res_admin = client.get(
        "/api/v1/memberships/my-subscription",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res_admin.status_code == 200
    admin_sub = res_admin.json()
    assert admin_sub["is_premium"] is True

    # Dedicated test user defaults to free tier initially
    user_token = get_auth_token("cyv_test_operative_free")
    res_user = client.get(
        "/api/v1/memberships/my-subscription",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_user.status_code == 200
    user_sub = res_user.json()
    assert user_sub["tier"] in ["free", "premium"]

# -----------------------------------------------------------------------------
# 3. Test UPI Configuration Endpoint
# -----------------------------------------------------------------------------
def test_get_upi_config():
    res = client.get("/api/v1/memberships/upi-config")
    assert res.status_code == 200
    data = res.json()
    assert "upi_id" in data
    assert "cyvantis.pay@upi" in data["upi_id"]

# -----------------------------------------------------------------------------
# 4. Test Order Creation, Screenshot Upload & Verification Workflow
# -----------------------------------------------------------------------------
def test_upi_order_submission_and_admin_approval():
    user_token = get_auth_token("cyv_test_operative_upi")
    admin_token = get_auth_token("admin")

    # 1. Get Monthly Plan ID
    plans_res = client.get("/api/v1/memberships/plans")
    monthly_plan = next(p for p in plans_res.json() if p["code"] == "monthly")

    # 2. Create Order
    create_res = client.post(
        "/api/v1/memberships/orders/create",
        json={"plan_id": monthly_plan["id"], "payment_method": "upi_qr"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert create_res.status_code == 200
    order = create_res.json()
    order_code = order["order_code"]
    order_id = order["id"]
    assert order["status"] == "pending"
    assert order["amount_inr"] == 49.0

    # 3. Submit UPI Screenshot and UTR
    fake_screenshot = io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRFAKE_RECEIPT_BYTES")
    utr_number = f"UTR{order_code[-8:]}"

    submit_res = client.post(
        f"/api/v1/memberships/orders/{order_code}/submit-upi",
        data={"upi_ref_no": utr_number},
        files={"screenshot": ("receipt.png", fake_screenshot, "image/png")},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert submit_res.status_code == 200
    submitted_order = submit_res.json()
    # CRITICAL: Status must still be PENDING (Never auto-approve from screenshot)
    assert submitted_order["status"] == "pending"
    assert submitted_order["upi_ref_no"] == utr_number

    # 4. Duplicate UTR check: another order cannot use the same UTR
    create_res2 = client.post(
        "/api/v1/memberships/orders/create",
        json={"plan_id": monthly_plan["id"], "payment_method": "upi_qr"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    order2_code = create_res2.json()["order_code"]
    fake_screenshot2 = io.BytesIO(b"fake_bytes")
    dup_res = client.post(
        f"/api/v1/memberships/orders/{order2_code}/submit-upi",
        data={"upi_ref_no": utr_number},
        files={"screenshot": ("receipt2.png", fake_screenshot2, "image/png")},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert dup_res.status_code == 400
    assert "already been submitted" in dup_res.text.lower()

    # 5. Non-Admin attempting to approve must fail (403 Forbidden)
    unauth_approve = client.post(
        f"/api/v1/memberships/admin/orders/{order_id}/verify",
        json={"action": "approve", "admin_notes": "Attempt by non-admin"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert unauth_approve.status_code == 403

    # 6. Admin Approves Order
    admin_approve = client.post(
        f"/api/v1/memberships/admin/orders/{order_id}/verify",
        json={"action": "approve", "admin_notes": "Verified by Chief Admin"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_approve.status_code == 200
    assert admin_approve.json()["status"] == "approved"

    # 7. Check User Subscription: User is now active Premium!
    check_sub = client.get(
        "/api/v1/memberships/my-subscription",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert check_sub.status_code == 200
    assert check_sub.json()["is_premium"] is True
    assert check_sub.json()["days_remaining"] is not None
    assert check_sub.json()["days_remaining"] >= 29

# -----------------------------------------------------------------------------
# 5. Test Premium Tool Gating (require_premium_access)
# -----------------------------------------------------------------------------
def test_premium_tool_gating():
    # User on Free tier attempting to access premium tools
    free_user_token = get_auth_token("cyv_test_operative_free_tools")
    admin_token = get_auth_token("admin")

    # Free user hits /api/v1/pentest/payload-lab -> 403 Forbidden
    blocked_res = client.post(
        "/api/v1/pentest/payload-lab",
        json={"payload_type": "bash_reverse_shell", "lhost": "10.0.0.5", "lport": 4444, "encoding": "plain"},
        headers={"Authorization": f"Bearer {free_user_token}"}
    )
    assert blocked_res.status_code == 403
    assert "premium" in blocked_res.text.lower()

    # Admin hits /api/v1/pentest/payload-lab -> 200 OK
    admin_res = client.post(
        "/api/v1/pentest/payload-lab",
        json={"payload_type": "bash_reverse_shell", "lhost": "10.0.0.5", "lport": 4444, "encoding": "plain"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_res.status_code == 200

# -----------------------------------------------------------------------------
# 6. Test Admin Overview & Manual Membership Activation
# -----------------------------------------------------------------------------
def test_admin_membership_management():
    admin_token = get_auth_token("admin")

    # Admin overview KPIs
    overview_res = client.get(
        "/api/v1/memberships/admin/overview",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert overview_res.status_code == 200
    ov = overview_res.json()
    assert "total_users" in ov
    assert "active_premium" in ov
    assert "total_revenue_inr" in ov

    # Admin manual activate
    manual_res = client.post(
        "/api/v1/memberships/admin/manual-activate",
        json={"user_id": 1, "plan_code": "yearly", "duration_days": 365, "notes": "Test manual grant"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert manual_res.status_code == 200
    assert "successfully activated" in manual_res.json()["message"].lower()

    # Admin audit logs
    audit_res = client.get(
        "/api/v1/memberships/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert audit_res.status_code == 200
    assert len(audit_res.json()) >= 1
