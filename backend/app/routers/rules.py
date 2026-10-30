import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models import DetectionRule, Alert, User, AuditLog
from app.schemas import (
    DetectionRuleCreate, DetectionRuleResponse, AlertResponse, AlertUpdate,
    AlertFeedbackRequest, AlertFeedbackResponse
)
from app.security import get_current_user, require_roles
from app.services.detection_evaluation import detection_evaluation_service

router = APIRouter(prefix="/rules", tags=["Detection Rules & Alerts"])

class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threshold: Optional[int] = None
    severity: Optional[str] = None
    is_enabled: Optional[bool] = None

@router.get("", response_model=List[DetectionRuleResponse])
def get_all_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(DetectionRule).order_by(DetectionRule.id.asc()).all()

@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    rule_in: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    existing = db.query(DetectionRule).filter(DetectionRule.name == rule_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule name already exists")

    rule = DetectionRule(
        name=rule_in.name,
        description=rule_in.description,
        rule_type=rule_in.rule_type,
        condition=rule_in.condition,
        threshold=rule_in.threshold,
        severity=rule_in.severity,
        is_enabled=rule_in.is_enabled,
        created_at=datetime.datetime.utcnow()
    )
    db.add(rule)

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="RULE_CREATED",
        resource="DetectionRules",
        details=f"Created detection rule: {rule_in.name}"
    )
    db.add(audit)
    db.commit()
    db.refresh(rule)
    return rule

@router.put("/{rule_id}", response_model=DetectionRuleResponse)
def update_rule(
    rule_id: int,
    rule_in: RuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule_in.name is not None:
        rule.name = rule_in.name
    if rule_in.description is not None:
        rule.description = rule_in.description
    if rule_in.threshold is not None:
        rule.threshold = rule_in.threshold
    if rule_in.severity is not None:
        rule.severity = rule_in.severity
    if rule_in.is_enabled is not None:
        rule.is_enabled = rule_in.is_enabled

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="RULE_UPDATED",
        resource="DetectionRules",
        details=f"Tuned detection rule ID {rule_id}"
    )
    db.add(audit)
    db.commit()
    db.refresh(rule)
    return rule

@router.put("/{rule_id}/toggle", response_model=DetectionRuleResponse)
def toggle_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.is_enabled = not rule.is_enabled

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="RULE_TOGGLED",
        resource="DetectionRules",
        details=f"Toggled rule ID {rule_id} status to {rule.is_enabled}"
    )
    db.add(audit)
    db.commit()
    db.refresh(rule)
    return rule

@router.get("/alerts", response_model=List[AlertResponse])
def get_all_alerts(
    status_filter: str = "all",
    severity: Optional[str] = None,
    incident_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if status_filter != "all":
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if incident_id:
        query = query.filter(Alert.incident_id == incident_id)
    return query.order_by(Alert.timestamp.desc()).limit(limit).all()

@router.put("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_acknowledged = True
    alert.status = "acknowledged"
    alert.acknowledged_by_id = current_user.id
    alert.acknowledged_at = datetime.datetime.utcnow()

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="ALERT_ACKNOWLEDGED",
        resource="Alerts",
        details=f"Acknowledged alert ID {alert_id} ({alert.title})"
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)
    return alert

@router.put("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "resolved"
    alert.is_acknowledged = True

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="ALERT_RESOLVED",
        resource="Alerts",
        details=f"Resolved alert ID {alert_id} ({alert.title})"
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/alerts/{alert_id}/feedback", response_model=AlertFeedbackResponse)
def submit_alert_feedback(
    alert_id: int,
    feedback_in: AlertFeedbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    """
    Submits human analyst feedback for an alert:
    Labels alert as 'true_positive', 'false_positive', or 'needs_review'.
    Records reviewer identity, timestamp, and audit trail without blindly mutating production thresholds.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.datetime.utcnow()
    alert.feedback_label = feedback_in.feedback.lower()
    alert.feedback_justification = feedback_in.justification
    alert.feedback_by_id = current_user.id
    alert.feedback_at = now

    audit = AuditLog(
        timestamp=now,
        user_id=current_user.id,
        username=current_user.username,
        action="ALERT_FEEDBACK_RECORDED",
        resource="Alerts",
        details=f"Analyst {current_user.username} marked alert #{alert_id} as '{feedback_in.feedback}' (Justification: {feedback_in.justification or 'None'})"
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)

    return {
        "success": True,
        "alert_id": alert.id,
        "feedback_label": alert.feedback_label,
        "feedback_justification": alert.feedback_justification,
        "reviewer_username": current_user.username,
        "timestamp": now,
        "message": f"Feedback '{alert.feedback_label}' successfully recorded for Alert #{alert_id}."
    }

@router.get("/alerts/feedback-summary")
def get_feedback_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns aggregated human analyst feedback metrics (TP rate, FP rate, Needs Review).
    Includes limitation notice if sample size is too small for statistical tuning.
    """
    return detection_evaluation_service.get_analyst_feedback_summary(db)

@router.get("/evaluation/metrics")
def get_evaluation_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Evaluates detection precision, recall, F1-score, and false positive rate
    against the standardized 20-vector synthetic ground-truth intrusion benchmark.
    """
    return detection_evaluation_service.run_benchmark(db)

@router.post("/evaluation/run-benchmark")
def run_evaluation_benchmark(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    """
    Executes the repeatable synthetic benchmark suite across detection rules and returns full performance metrics.
    """
    return detection_evaluation_service.run_benchmark(db)

@router.post("/evaluation/activate-baseline")
def activate_baseline_triage(
    sample_size: int = Query(50, ge=5, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    """
    Activates baseline ground-truth triage for production alerts in the database,
    evaluating signatures to establish initial True Positives, False Positives, and Needs Review metrics.
    """
    return detection_evaluation_service.populate_baseline_triage(
        db=db,
        sample_size=sample_size,
        reviewer_user_id=current_user.id,
        reviewer_username=current_user.username
    )

@router.post("/evaluation/toggle-guardrail")
def toggle_guardrail_policy(
    state: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    """
    Toggles the SOC guardrail safety policy between ACTIVE (Supervised Adaptive Tuning)
    and DISABLED (Manual SOC Approval Required).
    """
    return detection_evaluation_service.toggle_guardrail_policy(
        db=db,
        target_state=state,
        user_id=current_user.id,
        username=current_user.username
    )
