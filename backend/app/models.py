import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    role = Column(String(20), default="analyst", nullable=False) # admin, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    must_change_password = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    totp_secret = Column(String(64), nullable=True)
    is_totp_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True)
    eventid = Column(String(100), index=True, nullable=False) # cowrie.login.success, cowrie.command.input, etc.
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, default=22)
    protocol = Column(String(10), default="SSH", index=True) # SSH, Telnet
    username = Column(String(100), index=True, nullable=True)
    password = Column(String(100), nullable=True)
    command = Column(Text, nullable=True)
    file_hash = Column(String(64), nullable=True)
    session_id = Column(String(100), index=True, nullable=True)
    duration = Column(Float, default=0.0) # session duration in seconds
    country = Column(String(100), default="Unknown", index=True)
    country_code = Column(String(5), default="XX")
    city = Column(String(100), default="Unknown")
    asn = Column(String(100), default="AS0000 Unknown")
    severity = Column(String(20), default="medium", index=True) # low, medium, high, critical
    is_simulated = Column(Boolean, default=False, nullable=False)
    data_source = Column(String(50), default="cowrie", index=True) # cowrie, auth_log, network, synthetic
    event_hash = Column(String(64), index=True, nullable=True) # SHA-256 idempotency fingerprint
    raw_payload = Column(Text, nullable=True)

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="high", index=True) # low, medium, high, critical
    status = Column(String(20), default="open", index=True) # open, in_progress, resolved, closed
    risk_score = Column(Float, default=50.0)
    asset_tier = Column(String(50), default="Critical Gateway")
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    related_events = Column(Text, nullable=True) # JSON list of event IDs stringified

    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    created_by = relationship("User", foreign_keys=[created_by_id])
    notes = relationship("InvestigationNote", back_populates="investigation", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="incident")

class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="notes")
    author = relationship("User")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="high", index=True)
    rule_name = Column(String(100), nullable=False)
    src_ip = Column(String(45), index=True, nullable=True)
    status = Column(String(20), default="active", index=True) # active, acknowledged, resolved
    risk_score = Column(Float, default=50.0)
    risk_factors = Column(Text, nullable=True) # JSON string of contributing score factors
    incident_id = Column(Integer, ForeignKey("investigations.id"), nullable=True, index=True)
    mitre_tactics = Column(String(100), nullable=True)
    mitre_techniques = Column(String(100), nullable=True)
    recommended_actions = Column(Text, nullable=True) # JSON array of advisory recommendations
    evidence = Column(Text, nullable=True) # JSON event provenance IDs and evidence signals
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    feedback_label = Column(String(30), nullable=True) # true_positive, false_positive, needs_review
    feedback_justification = Column(Text, nullable=True)
    feedback_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    feedback_at = Column(DateTime, nullable=True)

    acknowledged_by = relationship("User", foreign_keys=[acknowledged_by_id])
    feedback_by = relationship("User", foreign_keys=[feedback_by_id])
    incident = relationship("Investigation", back_populates="alerts")

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(50), nullable=False) # brute_force, command_execution, payload_download, repeated_ip, anomaly, privileged_activity
    condition = Column(Text, nullable=False) # JSON or expression
    threshold = Column(Integer, default=5)
    severity = Column(String(20), default="high")
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_triggered = Column(DateTime, nullable=True)

class ThreatIntelIOC(Base):
    __tablename__ = "threat_intel_iocs"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(255), unique=True, index=True, nullable=False) # IP, Domain, Hash
    ioc_type = Column(String(20), index=True, nullable=False) # ip, domain, hash
    threat_score = Column(Integer, default=50) # 0-100
    category = Column(String(50), default="Malicious Host")
    description = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0) # 0.0 - 1.0 confidence score
    raw_intel = Column(Text, nullable=True) # JSON payload from external feed
    expiration = Column(DateTime, nullable=True) # TTL cache expiration
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    source = Column(String(100), default="CYVANTIS Honeypot")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False) # USER_LOGIN, EVENT_EXPORT, BACKUP_CREATED, USER_CREATED, etc.
    resource = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)

class PlatformSetting(Base):
    __tablename__ = "platform_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class BackupRecord(Base):
    __tablename__ = "backup_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    status = Column(String(20), default="success") # success, failed
    is_automated = Column(Boolean, default=False)
    created_by = Column(String(50), default="system")


# ==============================================================================
# Premium Membership, Subscription & Payment System Models
# ==============================================================================

class UserProfile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    full_name = Column(String(100), nullable=True)
    avatar_url = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    organization = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    role = Column(String(20), default="analyst", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", backref="profile", uselist=False)

class MembershipPlan(Base):
    __tablename__ = "membership_plans"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False) # free, monthly, quarterly, yearly
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    price_inr = Column(Integer, nullable=False) # 0, 49, 129, 399
    duration_days = Column(Integer, nullable=False) # 0, 30, 90, 365
    features = Column(Text, nullable=False) # JSON array of feature strings
    tier = Column(String(20), default="premium", nullable=False) # free, premium
    badge = Column(String(50), nullable=True) # e.g. "POPULAR", "BEST VALUE"
    daily_scan_limit = Column(Integer, default=10) # 5 for free, 100 for monthly, 250 for quarterly, -1 for unlimited
    is_active = Column(Boolean, default=True, nullable=False)
    sort_order = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class PaymentOrder(Base):
    __tablename__ = "payment_orders"

    id = Column(Integer, primary_key=True, index=True)
    order_code = Column(String(100), unique=True, index=True, nullable=False) # e.g. CYV-ORD-202610-ABCD
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("membership_plans.id"), nullable=False)
    amount_inr = Column(Integer, nullable=False)
    payment_method = Column(String(30), nullable=False) # "upi_qr" or "razorpay"
    gateway_order_id = Column(String(100), nullable=True, index=True)
    gateway_payment_id = Column(String(100), nullable=True, index=True)
    gateway_signature = Column(String(255), nullable=True)
    upi_ref_no = Column(String(100), nullable=True, index=True) # UTR or transaction ref
    receipt_image_path = Column(String(255), nullable=True) # stored filename
    status = Column(String(20), default="pending", index=True, nullable=False) # pending, approved, rejected
    verified_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    admin_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id], backref="orders")
    plan = relationship("MembershipPlan")
    verified_by = relationship("User", foreign_keys=[verified_by_id])

class Membership(Base):
    __tablename__ = "memberships"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("membership_plans.id"), nullable=False)
    order_id = Column(Integer, ForeignKey("payment_orders.id"), nullable=True)
    status = Column(String(20), default="active", index=True, nullable=False) # active, expired, cancelled
    start_date = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    end_date = Column(DateTime, nullable=False, index=True)
    auto_renew = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", backref="memberships")
    plan = relationship("MembershipPlan")
    order = relationship("PaymentOrder")

class PaymentAuditLog(Base):
    __tablename__ = "payment_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, nullable=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    actor_id = Column(Integer, nullable=True)
    actor_username = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False) # ORDER_CREATED, RECEIPT_SUBMITTED, PAYMENT_APPROVED, PAYMENT_REJECTED, MANUAL_ACTIVATION, MEMBERSHIP_REVOKED, PLAN_UPDATED, UPI_CONFIG_UPDATED
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)

class UpiConfig(Base):
    __tablename__ = "upi_configs"

    id = Column(Integer, primary_key=True, index=True)
    upi_id = Column(String(100), default="cyvantis.pay@upi", nullable=False)
    account_name = Column(String(100), default="CYVANTIS Cybersecurity Nexus", nullable=False)
    qr_image_url = Column(String(255), nullable=True)
    instructions = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
