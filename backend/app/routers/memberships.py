import os
import hmac
import hashlib
import uuid
import datetime
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas
from app.config import settings
from app.security import get_current_user, require_roles, check_user_membership

router = APIRouter(prefix="/memberships", tags=["Memberships & Subscriptions"])

# Ensure receipt upload directory exists
os.makedirs(settings.RECEIPTS_DIR, exist_ok=True)

# ==============================================================================
# Public & User Membership Endpoints
# ==============================================================================

@router.get("/plans", response_model=List[schemas.MembershipPlanResponse])
def get_membership_plans(db: Session = Depends(get_db)):
    """Retrieve all active membership plans."""
    plans = (
        db.query(models.MembershipPlan)
        .filter(models.MembershipPlan.is_active == True)
        .order_by(models.MembershipPlan.sort_order.asc(), models.MembershipPlan.price_inr.asc())
        .all()
    )
    return plans

@router.get("/my-subscription", response_model=schemas.UserSubscriptionResponse)
def get_my_subscription(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve the current user's active membership and pending payment orders."""
    info = check_user_membership(current_user, db)

    # Check for recent pending payment order
    pending_order = (
        db.query(models.PaymentOrder)
        .filter(
            models.PaymentOrder.user_id == current_user.id,
            models.PaymentOrder.status == "pending"
        )
        .order_by(models.PaymentOrder.created_at.desc())
        .first()
    )

    pending_order_resp = None
    if pending_order:
        plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == pending_order.plan_id).first()
        pending_order_resp = schemas.PaymentOrderResponse(
            id=pending_order.id,
            order_code=pending_order.order_code,
            user_id=pending_order.user_id,
            username=current_user.username,
            user_email=current_user.email,
            plan_id=pending_order.plan_id,
            plan_name=plan.name if plan else None,
            amount_inr=pending_order.amount_inr,
            payment_method=pending_order.payment_method,
            gateway_order_id=pending_order.gateway_order_id,
            gateway_payment_id=pending_order.gateway_payment_id,
            upi_ref_no=pending_order.upi_ref_no,
            receipt_image_path=pending_order.receipt_image_path,
            status=pending_order.status,
            verified_by_id=pending_order.verified_by_id,
            verified_at=pending_order.verified_at,
            admin_notes=pending_order.admin_notes,
            created_at=pending_order.created_at
        )

    # Find total amount paid by user across approved orders
    approved_orders = (
        db.query(models.PaymentOrder)
        .filter(
            models.PaymentOrder.user_id == current_user.id,
            models.PaymentOrder.status == "approved"
        )
        .all()
    )
    total_paid = sum(o.amount_inr for o in approved_orders)

    return schemas.UserSubscriptionResponse(
        tier=info["tier"],
        status=info["status"],
        is_premium=info["is_premium"],
        plan_code=info["plan_code"],
        plan_name=info["plan_name"],
        amount_paid=total_paid,
        start_date=info.get("start_date"),
        end_date=info.get("end_date"),
        days_remaining=info.get("days_remaining"),
        features=info.get("features", []),
        daily_scan_limit=info.get("daily_scan_limit", 5),
        pending_order=pending_order_resp
    )

@router.get("/upi-config", response_model=schemas.UpiConfigResponse)
def get_active_upi_config(db: Session = Depends(get_db)):
    """Retrieve active UPI payment details and instructions."""
    config = db.query(models.UpiConfig).filter(models.UpiConfig.is_active == True).first()
    if not config:
        config = models.UpiConfig(
            upi_id=settings.DEFAULT_UPI_ID,
            account_name=settings.DEFAULT_UPI_NAME,
            instructions="Scan using any UPI App (GPay, PhonePe, Paytm, BHIM). After payment, enter your UTR number and upload the screenshot.",
            is_active=True
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.post("/orders/create", response_model=schemas.PaymentOrderResponse)
def create_payment_order(
    payload: schemas.CreateOrderRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new payment order for a selected membership plan."""
    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == payload.plan_id).first()
    if not plan or not plan.is_active:
        raise HTTPException(status_code=404, detail="Selected membership plan not found or inactive")

    # If free plan, no payment order needed
    if plan.price_inr == 0:
        raise HTTPException(status_code=400, detail="The Free Tier does not require payment order creation.")

    # Unique human-readable order code
    date_prefix = datetime.datetime.utcnow().strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    order_code = f"CYV-ORD-{date_prefix}-{unique_suffix}"

    gateway_order_id = None
    if payload.payment_method == "razorpay":
        # Generate standard Razorpay order format
        gateway_order_id = f"order_{uuid.uuid4().hex[:14]}"

    new_order = models.PaymentOrder(
        order_code=order_code,
        user_id=current_user.id,
        plan_id=plan.id,
        amount_inr=plan.price_inr,
        payment_method=payload.payment_method,
        gateway_order_id=gateway_order_id,
        status="pending",
        created_at=datetime.datetime.utcnow()
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    # Log audit event
    audit = models.PaymentAuditLog(
        order_id=new_order.id,
        user_id=current_user.id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="ORDER_CREATED",
        details=json.dumps({"plan": plan.name, "amount": plan.price_inr, "method": payload.payment_method}),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    return schemas.PaymentOrderResponse(
        id=new_order.id,
        order_code=new_order.order_code,
        user_id=new_order.user_id,
        username=current_user.username,
        user_email=current_user.email,
        plan_id=plan.id,
        plan_name=plan.name,
        amount_inr=new_order.amount_inr,
        payment_method=new_order.payment_method,
        gateway_order_id=new_order.gateway_order_id,
        gateway_payment_id=new_order.gateway_payment_id,
        upi_ref_no=new_order.upi_ref_no,
        receipt_image_path=new_order.receipt_image_path,
        status=new_order.status,
        verified_by_id=new_order.verified_by_id,
        verified_at=new_order.verified_at,
        admin_notes=new_order.admin_notes,
        created_at=new_order.created_at
    )

@router.post("/orders/{order_code}/submit-upi", response_model=schemas.PaymentOrderResponse)
async def submit_upi_payment_proof(
    order_code: str,
    upi_ref_no: str = Form(...),
    receipt_file: Optional[UploadFile] = File(None),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit UPI transaction reference (UTR) and payment receipt screenshot for Admin verification."""
    order = (
        db.query(models.PaymentOrder)
        .filter(models.PaymentOrder.order_code == order_code)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404, detail="Payment order not found")

    if order.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to update this order")

    if order.status == "approved":
        raise HTTPException(status_code=400, detail="This order has already been approved.")

    clean_ref = upi_ref_no.strip()
    if not clean_ref:
        raise HTTPException(status_code=400, detail="UPI Transaction Reference / UTR number is required")

    # Duplicate transaction reference prevention
    existing_ref = (
        db.query(models.PaymentOrder)
        .filter(
            models.PaymentOrder.upi_ref_no == clean_ref,
            models.PaymentOrder.id != order.id
        )
        .first()
    )
    if existing_ref:
        raise HTTPException(
            status_code=400,
            detail=f"This UPI reference ({clean_ref}) has already been submitted on another order ({existing_ref.order_code}). Duplicate submissions are blocked."
        )

    # Save uploaded receipt image securely
    receipt_filename = order.receipt_image_path
    if receipt_file and receipt_file.filename:
        allowed_exts = {".png", ".jpg", ".jpeg", ".webp", ".pdf"}
        file_ext = os.path.splitext(receipt_file.filename)[1].lower()
        if file_ext not in allowed_exts:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file extension ({file_ext}). Allowed: PNG, JPG, JPEG, WEBP, PDF"
            )

        # Generate non-colliding sanitized filename
        safe_name = f"receipt_{order.order_code}_{uuid.uuid4().hex[:8]}{file_ext}"
        destination = os.path.join(settings.RECEIPTS_DIR, safe_name)
        
        # Write file content
        content = await receipt_file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Receipt file exceeds maximum size limit (10MB)")

        with open(destination, "wb") as f:
            f.write(content)
        receipt_filename = safe_name

    # Update order state
    order.upi_ref_no = clean_ref
    order.receipt_image_path = receipt_filename
    order.status = "pending" # Explicitly keep in pending until verified by admin!
    db.commit()
    db.refresh(order)

    # Log audit event
    audit = models.PaymentAuditLog(
        order_id=order.id,
        user_id=current_user.id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="RECEIPT_SUBMITTED",
        details=json.dumps({"utr": clean_ref, "receipt_file": receipt_filename}),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == order.plan_id).first()
    return schemas.PaymentOrderResponse(
        id=order.id,
        order_code=order.order_code,
        user_id=order.user_id,
        username=current_user.username,
        user_email=current_user.email,
        plan_id=order.plan_id,
        plan_name=plan.name if plan else None,
        amount_inr=order.amount_inr,
        payment_method=order.payment_method,
        gateway_order_id=order.gateway_order_id,
        gateway_payment_id=order.gateway_payment_id,
        upi_ref_no=order.upi_ref_no,
        receipt_image_path=order.receipt_image_path,
        status=order.status,
        verified_by_id=order.verified_by_id,
        verified_at=order.verified_at,
        admin_notes=order.admin_notes,
        created_at=order.created_at
    )

@router.post("/orders/verify-razorpay", response_model=schemas.PaymentOrderResponse)
def verify_razorpay_payment(
    payload: schemas.VerifyRazorpayRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify online payment gateway signature and submit order for Admin verification."""
    order = (
        db.query(models.PaymentOrder)
        .filter(models.PaymentOrder.order_code == payload.order_code)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to verify this order")

    # Prevent duplicate payment id re-use
    duplicate_payment = (
        db.query(models.PaymentOrder)
        .filter(
            models.PaymentOrder.gateway_payment_id == payload.razorpay_payment_id,
            models.PaymentOrder.id != order.id
        )
        .first()
    )
    if duplicate_payment:
        raise HTTPException(
            status_code=400,
            detail=f"Payment ID {payload.razorpay_payment_id} was already used on order {duplicate_payment.order_code}."
        )

    # Server-side HMAC SHA256 signature verification
    msg = f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}".encode("utf-8")
    expected_signature = hmac.new(
        settings.RAZORPAY_KEY_SECRET.encode("utf-8"),
        msg,
        hashlib.sha256
    ).hexdigest()

    # If not running in mock test mode, require signature match
    if not settings.RAZORPAY_KEY_SECRET.startswith("mock_") and payload.razorpay_signature != expected_signature:
        raise HTTPException(status_code=400, detail="Invalid Razorpay payment signature. Tampering detected.")

    order.gateway_order_id = payload.razorpay_order_id
    order.gateway_payment_id = payload.razorpay_payment_id
    order.gateway_signature = payload.razorpay_signature
    order.status = "pending" # Per requirements: admin review before activation
    db.commit()
    db.refresh(order)

    # Log audit event
    audit = models.PaymentAuditLog(
        order_id=order.id,
        user_id=current_user.id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="GATEWAY_SIGNATURE_VERIFIED",
        details=json.dumps({"payment_id": payload.razorpay_payment_id, "gateway": "razorpay"}),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == order.plan_id).first()
    return schemas.PaymentOrderResponse(
        id=order.id,
        order_code=order.order_code,
        user_id=order.user_id,
        username=current_user.username,
        user_email=current_user.email,
        plan_id=order.plan_id,
        plan_name=plan.name if plan else None,
        amount_inr=order.amount_inr,
        payment_method=order.payment_method,
        gateway_order_id=order.gateway_order_id,
        gateway_payment_id=order.gateway_payment_id,
        upi_ref_no=order.upi_ref_no,
        receipt_image_path=order.receipt_image_path,
        status=order.status,
        verified_by_id=order.verified_by_id,
        verified_at=order.verified_at,
        admin_notes=order.admin_notes,
        created_at=order.created_at
    )

@router.get("/orders/history", response_model=List[schemas.PaymentOrderResponse])
def get_user_payment_history(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve all payment orders placed by the current user."""
    orders = (
        db.query(models.PaymentOrder)
        .filter(models.PaymentOrder.user_id == current_user.id)
        .order_by(models.PaymentOrder.created_at.desc())
        .all()
    )
    result = []
    for o in orders:
        plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == o.plan_id).first()
        result.append(schemas.PaymentOrderResponse(
            id=o.id,
            order_code=o.order_code,
            user_id=o.user_id,
            username=current_user.username,
            user_email=current_user.email,
            plan_id=o.plan_id,
            plan_name=plan.name if plan else None,
            amount_inr=o.amount_inr,
            payment_method=o.payment_method,
            gateway_order_id=o.gateway_order_id,
            gateway_payment_id=o.gateway_payment_id,
            upi_ref_no=o.upi_ref_no,
            receipt_image_path=o.receipt_image_path,
            status=o.status,
            verified_by_id=o.verified_by_id,
            verified_at=o.verified_at,
            admin_notes=o.admin_notes,
            created_at=o.created_at
        ))
    return result

# ==============================================================================
# Admin Membership Management Endpoints
# ==============================================================================

@router.get("/admin/overview", response_model=schemas.AdminMembershipOverview)
def get_admin_membership_overview(
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Retrieve key platform metrics across users, memberships, and payment requests."""
    total_users = db.query(models.User).count()

    now = datetime.datetime.utcnow()
    active_premium = (
        db.query(models.Membership)
        .filter(models.Membership.status == "active", models.Membership.end_date > now)
        .count()
    )

    pending_orders = db.query(models.PaymentOrder).filter(models.PaymentOrder.status == "pending").count()
    approved_orders = db.query(models.PaymentOrder).filter(models.PaymentOrder.status == "approved").count()
    rejected_orders = db.query(models.PaymentOrder).filter(models.PaymentOrder.status == "rejected").count()

    approved_list = db.query(models.PaymentOrder).filter(models.PaymentOrder.status == "approved").all()
    total_revenue = sum(o.amount_inr for o in approved_list)

    return schemas.AdminMembershipOverview(
        total_users=total_users,
        active_premium=active_premium,
        pending_orders=pending_orders,
        approved_orders=approved_orders,
        rejected_orders=rejected_orders,
        total_revenue_inr=total_revenue
    )

@router.get("/admin/orders", response_model=List[schemas.PaymentOrderResponse])
def get_admin_orders(
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """List all user payment requests with optional status filtering for Admin review."""
    query = db.query(models.PaymentOrder)

    if status_filter:
        query = query.filter(models.PaymentOrder.status == status_filter)

    orders = query.order_by(models.PaymentOrder.created_at.desc()).all()

    result = []
    for o in orders:
        usr = db.query(models.User).filter(models.User.id == o.user_id).first()
        plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == o.plan_id).first()

        # Apply search filter across code, username, utr if supplied
        if search:
            s = search.lower()
            code_match = s in o.order_code.lower()
            user_match = usr and (s in usr.username.lower() or s in usr.email.lower())
            utr_match = o.upi_ref_no and s in o.upi_ref_no.lower()
            if not (code_match or user_match or utr_match):
                continue

        result.append(schemas.PaymentOrderResponse(
            id=o.id,
            order_code=o.order_code,
            user_id=o.user_id,
            username=usr.username if usr else "Unknown",
            user_email=usr.email if usr else "",
            plan_id=o.plan_id,
            plan_name=plan.name if plan else None,
            amount_inr=o.amount_inr,
            payment_method=o.payment_method,
            gateway_order_id=o.gateway_order_id,
            gateway_payment_id=o.gateway_payment_id,
            upi_ref_no=o.upi_ref_no,
            receipt_image_path=o.receipt_image_path,
            status=o.status,
            verified_by_id=o.verified_by_id,
            verified_at=o.verified_at,
            admin_notes=o.admin_notes,
            created_at=o.created_at
        ))
    return result

@router.post("/admin/orders/{order_id}/verify", response_model=schemas.PaymentOrderResponse)
def verify_payment_order(
    order_id: int,
    payload: schemas.VerifyOrderRequest,
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Admin endpoint to Approve or Reject a payment order with atomic membership activation."""
    order = db.query(models.PaymentOrder).filter(models.PaymentOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Payment order not found")

    if order.status == "approved" and payload.action.lower() in ["approve", "approved"]:
        raise HTTPException(status_code=400, detail="This order is already approved.")

    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == order.plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Associated membership plan not found")

    now = datetime.datetime.utcnow()

    if payload.action.lower() in ["approve", "approved"]:
        order.status = "approved"
        order.verified_by_id = current_user.id
        order.verified_at = now
        order.admin_notes = payload.admin_notes

        # -------------------------------------------------------------
        # Atomic Membership Activation
        # -------------------------------------------------------------
        # Check if user already has an active membership to extend
        active_mem = (
            db.query(models.Membership)
            .filter(
                models.Membership.user_id == order.user_id,
                models.Membership.status == "active",
                models.Membership.end_date > now
            )
            .order_by(models.Membership.end_date.desc())
            .first()
        )

        duration = plan.duration_days or 30
        if active_mem:
            # Extend existing active subscription
            active_mem.end_date = active_mem.end_date + datetime.timedelta(days=duration)
            active_mem.plan_id = plan.id
            active_mem.order_id = order.id
            active_mem.updated_at = now
        else:
            # Create new active membership
            new_mem = models.Membership(
                user_id=order.user_id,
                plan_id=plan.id,
                order_id=order.id,
                status="active",
                start_date=now,
                end_date=now + datetime.timedelta(days=duration),
                auto_renew=False,
                created_at=now
            )
            db.add(new_mem)

        # Log audit trail
        audit = models.PaymentAuditLog(
            order_id=order.id,
            user_id=order.user_id,
            actor_id=current_user.id,
            actor_username=current_user.username,
            action="PAYMENT_APPROVED",
            details=json.dumps({"order_code": order.order_code, "plan": plan.name, "amount": order.amount_inr, "notes": payload.admin_notes}),
            timestamp=now
        )
        db.add(audit)
        db.commit()

    elif payload.action.lower() in ["reject", "rejected"]:
        order.status = "rejected"
        order.verified_by_id = current_user.id
        order.verified_at = now
        order.admin_notes = payload.admin_notes or "Payment verification rejected by administrator."

        audit = models.PaymentAuditLog(
            order_id=order.id,
            user_id=order.user_id,
            actor_id=current_user.id,
            actor_username=current_user.username,
            action="PAYMENT_REJECTED",
            details=json.dumps({"order_code": order.order_code, "rejection_reason": order.admin_notes}),
            timestamp=now
        )
        db.add(audit)
        db.commit()

    else:
        raise HTTPException(status_code=400, detail="Invalid action. Allowed: 'approve', 'reject'")

    db.refresh(order)
    usr = db.query(models.User).filter(models.User.id == order.user_id).first()
    return schemas.PaymentOrderResponse(
        id=order.id,
        order_code=order.order_code,
        user_id=order.user_id,
        username=usr.username if usr else None,
        user_email=usr.email if usr else None,
        plan_id=order.plan_id,
        plan_name=plan.name,
        amount_inr=order.amount_inr,
        payment_method=order.payment_method,
        gateway_order_id=order.gateway_order_id,
        gateway_payment_id=order.gateway_payment_id,
        upi_ref_no=order.upi_ref_no,
        receipt_image_path=order.receipt_image_path,
        status=order.status,
        verified_by_id=order.verified_by_id,
        verified_at=order.verified_at,
        admin_notes=order.admin_notes,
        created_at=order.created_at
    )

@router.post("/admin/manual-activate")
def manual_membership_control(
    payload: schemas.ManualMembershipRequest,
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Admin endpoint to manually grant or revoke a user's Premium Membership."""
    target_user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")

    now = datetime.datetime.utcnow()

    if payload.action.lower() in ["grant", "activate"]:
        # Resolve plan
        plan = None
        if payload.plan_code:
            plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.code == payload.plan_code).first()
        elif payload.plan_id:
            plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == payload.plan_id).first()
        if not plan:
            plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.code == "monthly").first()

        duration = payload.duration_days or (plan.duration_days if plan else 30)

        # Deactivate previous active memberships
        db.query(models.Membership).filter(
            models.Membership.user_id == target_user.id,
            models.Membership.status == "active"
        ).update({"status": "cancelled", "updated_at": now})

        new_mem = models.Membership(
            user_id=target_user.id,
            plan_id=plan.id if plan else 1,
            order_id=None,
            status="active",
            start_date=now,
            end_date=now + datetime.timedelta(days=duration),
            auto_renew=False,
            created_at=now
        )
        db.add(new_mem)

        audit = models.PaymentAuditLog(
            order_id=None,
            user_id=target_user.id,
            actor_id=current_user.id,
            actor_username=current_user.username,
            action="MANUAL_ACTIVATION",
            details=json.dumps({"target_user": target_user.username, "duration_days": duration, "notes": payload.notes}),
            timestamp=now
        )
        db.add(audit)
        db.commit()
        return {"success": True, "message": f"Successfully activated {duration}-day Premium Membership for {target_user.username}."}

    elif payload.action == "revoke":
        db.query(models.Membership).filter(
            models.Membership.user_id == target_user.id,
            models.Membership.status == "active"
        ).update({"status": "cancelled", "end_date": now, "updated_at": now})

        audit = models.PaymentAuditLog(
            order_id=None,
            user_id=target_user.id,
            actor_id=current_user.id,
            actor_username=current_user.username,
            action="MEMBERSHIP_REVOKED",
            details=json.dumps({"target_user": target_user.username, "reason": payload.notes}),
            timestamp=now
        )
        db.add(audit)
        db.commit()
        return {"success": True, "message": f"Successfully revoked active membership for {target_user.username}."}

    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'grant' or 'revoke'.")

@router.get("/admin/plans", response_model=List[schemas.MembershipPlanResponse])
def get_all_admin_plans(
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Retrieve all membership plans for editing."""
    return db.query(models.MembershipPlan).order_by(models.MembershipPlan.sort_order.asc()).all()

@router.put("/admin/plans/{plan_id}", response_model=schemas.MembershipPlanResponse)
def update_membership_plan(
    plan_id: int,
    payload: schemas.MembershipPlanUpdate,
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Update membership plan price, duration, features, and active status."""
    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Membership plan not found")

    if payload.name is not None:
        plan.name = payload.name
    if payload.price_inr is not None:
        plan.price_inr = payload.price_inr
    if payload.duration_days is not None:
        plan.duration_days = payload.duration_days
    if payload.features is not None:
        plan.features = payload.features
    if payload.badge is not None:
        plan.badge = payload.badge
    if payload.daily_scan_limit is not None:
        plan.daily_scan_limit = payload.daily_scan_limit
    if payload.is_active is not None:
        plan.is_active = payload.is_active

    plan.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(plan)

    audit = models.PaymentAuditLog(
        order_id=None,
        user_id=None,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="PLAN_UPDATED",
        details=json.dumps({"plan_id": plan.id, "code": plan.code, "price": plan.price_inr, "duration": plan.duration_days}),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    return plan

@router.get("/admin/upi-config", response_model=schemas.UpiConfigResponse)
def get_admin_upi_config(
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Get active UPI payment configuration."""
    config = db.query(models.UpiConfig).first()
    if not config:
        config = models.UpiConfig(
            upi_id="cyvantis.pay@upi",
            account_name="CYVANTIS Cybersecurity Nexus",
            instructions="Scan QR Code or pay directly to the UPI ID.",
            is_active=True
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/admin/upi-config", response_model=schemas.UpiConfigResponse)
def update_admin_upi_config(
    payload: schemas.UpiConfigUpdate,
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Update UPI ID, Payee Account Name, and instructions."""
    config = db.query(models.UpiConfig).first()
    if not config:
        config = models.UpiConfig(is_active=True)
        db.add(config)

    if payload.upi_id:
        config.upi_id = payload.upi_id.strip()
    if payload.account_name:
        config.account_name = payload.account_name.strip()
    if payload.instructions:
        config.instructions = payload.instructions.strip()

    config.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(config)

    audit = models.PaymentAuditLog(
        order_id=None,
        user_id=None,
        actor_id=current_user.id,
        actor_username=current_user.username,
        action="UPI_CONFIG_UPDATED",
        details=json.dumps({"upi_id": config.upi_id, "name": config.account_name}),
        timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()

    return config

@router.get("/admin/audit-logs", response_model=List[schemas.PaymentAuditLogResponse])
def get_payment_audit_logs(
    limit: int = 50,
    offset: int = 0,
    current_user: models.User = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db)
):
    """Retrieve immutable payment and membership audit logs."""
    logs = (
        db.query(models.PaymentAuditLog)
        .order_by(models.PaymentAuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return logs

@router.get("/receipts/{filename}")
def get_receipt_image(
    filename: str,
    current_user: models.User = Depends(require_roles(["admin"]))
):
    """Securely serve uploaded payment receipt image for Admin verification."""
    # Prevent directory traversal
    safe_name = os.path.basename(filename)
    filepath = os.path.join(settings.RECEIPTS_DIR, safe_name)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Receipt image not found")
    return FileResponse(filepath)
