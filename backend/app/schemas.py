import datetime
import ipaddress
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, field_validator

# Auth & User Schemas
class Token(BaseModel):
    access_token: str
    token_type: str
    user: "UserResponse"

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: str = "analyst" # admin, analyst, viewer

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

class PasswordChangeFirstLogin(BaseModel):
    current_password: str
    new_password: str

class TotpSetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    otpauth_url: str

class TotpVerifyRequest(BaseModel):
    totp_code: str

class Login2faVerifyRequest(BaseModel):
    temp_token: str
    totp_code: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    must_change_password: bool = False
    is_totp_enabled: bool = False
    created_at: datetime.datetime
    last_login: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

# Honeypot Event Schemas
class EventCreate(BaseModel):
    eventid: str
    src_ip: str
    dst_port: int = 22
    protocol: str = "SSH"
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    file_hash: Optional[str] = None
    session_id: Optional[str] = None
    duration: float = 0.0
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "XX"
    city: Optional[str] = "Unknown"
    asn: Optional[str] = "AS0000 Unknown"
    severity: str = "medium"
    is_simulated: bool = False
    raw_payload: Optional[str] = None

class EventResponse(BaseModel):
    id: int
    eventid: str
    timestamp: datetime.datetime
    src_ip: str
    dst_port: int
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    file_hash: Optional[str] = None
    session_id: Optional[str] = None
    duration: float
    country: str
    country_code: str
    city: str
    asn: str
    severity: str
    is_simulated: bool
    data_source: Optional[str] = "cowrie"
    event_hash: Optional[str] = None
    raw_payload: Optional[str] = None

    class Config:
        from_attributes = True

class EventIngestRequest(BaseModel):
    eventid: str
    src_ip: str
    dst_port: int = Field(22, ge=1, le=65535)
    protocol: str = "SSH"
    timestamp: Optional[datetime.datetime] = None
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    file_hash: Optional[str] = None
    session_id: Optional[str] = None
    duration: float = 0.0
    country: Optional[str] = "Unknown"
    country_code: Optional[str] = "XX"
    city: Optional[str] = "Unknown"
    asn: Optional[str] = "AS0000 Unknown"
    severity: str = "low"
    data_source: Optional[str] = "api_ingest"
    raw_payload: Optional[str] = None

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v: str) -> str:
        trimmed = (v or "").strip()
        try:
            ipaddress.ip_address(trimmed)
            return trimmed
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{trimmed}'")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid_severities = {"low", "medium", "high", "critical"}
        if (v or "").lower() not in valid_severities:
            raise ValueError(f"Severity must be one of {valid_severities}, got '{v}'")
        return v.lower()

class EventIngestResponse(BaseModel):
    success: bool
    status: str # "persisted", "duplicate", "rejected"
    event_id: Optional[int] = None
    event_hash: str
    evaluated_severity: str
    findings_count: int = 0
    incident_id: Optional[int] = None
    risk_score: Optional[float] = None
    is_anomalous: bool = False
    message: str

class BatchImportRequest(BaseModel):
    events: List[EventIngestRequest]

class BatchImportResponse(BaseModel):
    total_received: int
    persisted: int
    duplicates: int
    errors: int
    alerts_generated: int
    events: List[EventIngestResponse]

class EventPaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    items: List[EventResponse]

# Investigation Schemas
class InvestigationNoteCreate(BaseModel):
    note_text: str

class InvestigationNoteResponse(BaseModel):
    id: int
    investigation_id: int
    author_id: int
    author_username: Optional[str] = None
    note_text: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "high"
    status: str = "open"
    assigned_to_id: Optional[int] = None
    related_events: Optional[List[int]] = None

class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to_id: Optional[int] = None
    related_events: Optional[List[int]] = None

class InvestigationResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    risk_score: Optional[float] = 50.0
    asset_tier: Optional[str] = "Critical Gateway"
    assigned_to_id: Optional[int] = None
    assigned_to_username: Optional[str] = None
    created_by_id: Optional[int] = None
    created_by_username: Optional[str] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime
    related_events: Optional[List[int]] = None
    notes: List[InvestigationNoteResponse] = []

    class Config:
        from_attributes = True

class ContainmentActionRequest(BaseModel):
    action: str  # BLOCK_IP, ISOLATE_ASSET, CLOSE_INCIDENT, REVOKE_SESSION
    confirmed: bool = False
    target: Optional[str] = None
    reason: Optional[str] = "Manual incident response containment"

class ContainmentActionResponse(BaseModel):
    success: bool
    action: str
    target: Optional[str] = None
    timestamp: datetime.datetime
    audit_id: int
    note_id: int
    message: str

# Alert Schemas
class AlertUpdate(BaseModel):
    status: Optional[str] = None # active, acknowledged, resolved
    is_acknowledged: Optional[bool] = None

class AlertResponse(BaseModel):
    id: int
    timestamp: datetime.datetime
    title: str
    description: Optional[str] = None
    severity: str
    rule_name: str
    src_ip: Optional[str] = None
    status: str
    risk_score: Optional[float] = 50.0
    risk_factors: Optional[str] = None
    incident_id: Optional[int] = None
    mitre_tactics: Optional[str] = None
    mitre_techniques: Optional[str] = None
    recommended_actions: Optional[str] = None
    evidence: Optional[str] = None
    is_acknowledged: bool
    acknowledged_by_id: Optional[int] = None
    acknowledged_at: Optional[datetime.datetime] = None
    feedback_label: Optional[str] = None
    feedback_justification: Optional[str] = None
    feedback_by_id: Optional[int] = None
    feedback_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class AlertFeedbackRequest(BaseModel):
    feedback: str # true_positive, false_positive, needs_review
    justification: Optional[str] = None

    @field_validator("feedback")
    @classmethod
    def validate_feedback(cls, v: str) -> str:
        valid = {"true_positive", "false_positive", "needs_review"}
        if (v or "").lower() not in valid:
            raise ValueError(f"Feedback must be one of {valid}, got '{v}'")
        return v.lower()

class AlertFeedbackResponse(BaseModel):
    success: bool
    alert_id: int
    feedback_label: str
    feedback_justification: Optional[str] = None
    reviewer_username: str
    timestamp: datetime.datetime
    message: str

# Detection Rule Schemas
class DetectionRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str
    condition: str
    threshold: int = 5
    severity: str = "high"
    is_enabled: bool = True

class DetectionRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    rule_type: str
    condition: str
    threshold: int
    severity: str
    is_enabled: bool
    created_at: datetime.datetime
    last_triggered: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

# Threat Intel IOC Schemas
class ThreatIntelIOCCreate(BaseModel):
    indicator: str
    ioc_type: str # ip, domain, hash
    threat_score: int = 50
    category: str = "Malicious Host"
    description: Optional[str] = None
    source: str = "Manual Entry"

class ThreatIntelIOCResponse(BaseModel):
    id: int
    indicator: str
    ioc_type: str
    threat_score: int
    category: str
    description: Optional[str] = None
    confidence: Optional[float] = 1.0
    expiration: Optional[datetime.datetime] = None
    raw_intel: Optional[str] = None
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    source: str

    class Config:
        from_attributes = True

# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime.datetime
    user_id: Optional[int] = None
    username: str
    action: str
    resource: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None

    class Config:
        from_attributes = True

# Setting & Backup Schemas
class PlatformSettingUpdate(BaseModel):
    value: str

class PlatformSettingResponse(BaseModel):
    id: int
    key: str
    value: str
    description: Optional[str] = None
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

class BackupRecordResponse(BaseModel):
    id: int
    timestamp: datetime.datetime
    filename: str
    file_size_bytes: int
    status: str
    is_automated: bool
    created_by: str

    class Config:
        from_attributes = True


# ==============================================================================
# Premium Membership & Payment Schemas
# ==============================================================================

class MembershipPlanResponse(BaseModel):
    id: int
    code: str
    name: str
    price_inr: int
    duration_days: int
    features: str
    tier: str
    badge: Optional[str] = None
    daily_scan_limit: int
    is_active: bool
    sort_order: int
    created_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class MembershipPlanUpdate(BaseModel):
    name: Optional[str] = None
    price_inr: Optional[int] = None
    duration_days: Optional[int] = None
    features: Optional[str] = None
    badge: Optional[str] = None
    daily_scan_limit: Optional[int] = None
    is_active: Optional[bool] = None

class CreateOrderRequest(BaseModel):
    plan_id: int
    payment_method: str = "upi_qr" # "upi_qr" or "razorpay"

class VerifyRazorpayRequest(BaseModel):
    order_code: str
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class PaymentOrderResponse(BaseModel):
    id: int
    order_code: str
    user_id: int
    username: Optional[str] = None
    user_email: Optional[str] = None
    plan_id: int
    plan_name: Optional[str] = None
    amount_inr: int
    payment_method: str
    gateway_order_id: Optional[str] = None
    gateway_payment_id: Optional[str] = None
    upi_ref_no: Optional[str] = None
    receipt_image_path: Optional[str] = None
    status: str
    verified_by_id: Optional[int] = None
    verified_at: Optional[datetime.datetime] = None
    admin_notes: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class VerifyOrderRequest(BaseModel):
    action: str # "approve" or "reject"
    admin_notes: Optional[str] = None

class ManualMembershipRequest(BaseModel):
    user_id: int
    action: Optional[str] = "grant" # "grant" or "revoke"
    plan_code: Optional[str] = None
    plan_id: Optional[int] = None
    duration_days: Optional[int] = 30
    notes: Optional[str] = None

class UserSubscriptionResponse(BaseModel):
    tier: str # "free", "premium", "enterprise_admin"
    status: str # "active", "expired", "pending_approval", "none"
    is_premium: bool
    plan_code: str
    plan_name: str
    amount_paid: int
    start_date: Optional[datetime.datetime] = None
    end_date: Optional[datetime.datetime] = None
    days_remaining: Optional[int] = None
    features: List[str]
    daily_scan_limit: int
    pending_order: Optional[PaymentOrderResponse] = None

class UpiConfigResponse(BaseModel):
    id: int
    upi_id: str
    account_name: str
    qr_image_url: Optional[str] = None
    instructions: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True

class UpiConfigUpdate(BaseModel):
    upi_id: Optional[str] = None
    account_name: Optional[str] = None
    instructions: Optional[str] = None

class PaymentAuditLogResponse(BaseModel):
    id: int
    order_id: Optional[int] = None
    user_id: Optional[int] = None
    actor_username: str
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class AdminMembershipOverview(BaseModel):
    total_users: int
    active_premium: int
    pending_orders: int
    approved_orders: int
    rejected_orders: int
    total_revenue_inr: int
