import json
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Investigation, InvestigationNote, User, AuditLog, HoneypotEvent, Alert, ThreatIntelIOC
from app.schemas import (
    InvestigationCreate, InvestigationUpdate, InvestigationResponse,
    InvestigationNoteCreate, InvestigationNoteResponse,
    ContainmentActionRequest, ContainmentActionResponse
)
from app.security import get_current_user, require_roles
from app.config import settings
from app.services.investigation_graph import investigation_graph_service
from app.services.attack_pattern_service import attack_pattern_service
from app.services.asset_vulnerability_service import asset_vulnerability_service

router = APIRouter(prefix="/investigations", tags=["Investigation Management"])

def _format_investigation(inv: Investigation, db: Session) -> dict:
    notes_list = []
    for n in inv.notes:
        author = db.query(User).filter(User.id == n.author_id).first()
        notes_list.append({
            "id": n.id,
            "investigation_id": n.investigation_id,
            "author_id": n.author_id,
            "author_username": author.username if author else "Unknown",
            "note_text": n.note_text,
            "created_at": n.created_at
        })

    assigned_user = db.query(User).filter(User.id == inv.assigned_to_id).first() if inv.assigned_to_id else None
    created_user = db.query(User).filter(User.id == inv.created_by_id).first() if inv.created_by_id else None
    
    rel_events = []
    if inv.related_events:
        try:
            rel_events = json.loads(inv.related_events)
        except Exception:
            rel_events = []

    return {
        "id": inv.id,
        "title": inv.title,
        "description": inv.description,
        "severity": inv.severity,
        "status": inv.status,
        "risk_score": getattr(inv, "risk_score", 50.0) or 50.0,
        "asset_tier": getattr(inv, "asset_tier", "Critical Gateway") or "Critical Gateway",
        "assigned_to_id": inv.assigned_to_id,
        "assigned_to_username": assigned_user.username if assigned_user else None,
        "created_by_id": inv.created_by_id,
        "created_by_username": created_user.username if created_user else None,
        "created_at": inv.created_at,
        "updated_at": inv.updated_at,
        "related_events": rel_events,
        "notes": notes_list
    }

@router.get("", response_model=List[InvestigationResponse])
def get_all_investigations(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Investigation)
    if status_filter:
        query = query.filter(Investigation.status == status_filter)
    investigations = query.order_by(Investigation.updated_at.desc()).all()
    return [_format_investigation(inv, db) for inv in investigations]

@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def create_investigation(
    inv_in: InvestigationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    rel_events_json = json.dumps(inv_in.related_events) if inv_in.related_events else None

    inv = Investigation(
        title=inv_in.title,
        description=inv_in.description,
        severity=inv_in.severity,
        status=inv_in.status,
        assigned_to_id=inv_in.assigned_to_id or current_user.id,
        created_by_id=current_user.id,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow(),
        related_events=rel_events_json
    )
    db.add(inv)
    
    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="INVESTIGATION_CREATED",
        resource="Investigations",
        details=f"Created investigation: {inv_in.title}"
    )
    db.add(audit)
    db.commit()
    db.refresh(inv)
    return _format_investigation(inv, db)

@router.get("/{inv_id}", response_model=InvestigationResponse)
def get_investigation_detail(
    inv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return _format_investigation(inv, db)

@router.put("/{inv_id}", response_model=InvestigationResponse)
def update_investigation(
    inv_id: int,
    inv_in: InvestigationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv_in.title:
        inv.title = inv_in.title
    if inv_in.description is not None:
        inv.description = inv_in.description
    if inv_in.severity:
        inv.severity = inv_in.severity
    if inv_in.status:
        inv.status = inv_in.status
    if inv_in.assigned_to_id is not None:
        inv.assigned_to_id = inv_in.assigned_to_id
    if inv_in.related_events is not None:
        inv.related_events = json.dumps(inv_in.related_events)

    inv.updated_at = datetime.datetime.utcnow()

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="INVESTIGATION_UPDATED",
        resource="Investigations",
        details=f"Updated investigation ID {inv_id}"
    )
    db.add(audit)
    db.commit()
    db.refresh(inv)
    return _format_investigation(inv, db)

@router.post("/{inv_id}/notes", response_model=InvestigationNoteResponse)
def add_investigation_note(
    inv_id: int,
    note_in: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    note = InvestigationNote(
        investigation_id=inv_id,
        author_id=current_user.id,
        note_text=note_in.note_text,
        created_at=datetime.datetime.utcnow()
    )
    db.add(note)
    inv.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(note)

    return {
        "id": note.id,
        "investigation_id": note.investigation_id,
        "author_id": note.author_id,
        "author_username": current_user.username,
        "note_text": note.note_text,
        "created_at": note.created_at
    }

@router.get("/{inv_id}/timeline")
def get_investigation_timeline(
    inv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    rel_event_ids = []
    if inv.related_events:
        try:
            rel_event_ids = json.loads(inv.related_events)
            if not isinstance(rel_event_ids, list):
                rel_event_ids = []
        except Exception:
            rel_event_ids = []

    # Fetch events ordered chronologically
    events = []
    if rel_event_ids:
        events = db.query(HoneypotEvent).filter(HoneypotEvent.id.in_(rel_event_ids)).order_by(HoneypotEvent.timestamp.asc()).all()

    # Mask passwords if not admin
    redact = settings.CREDENTIAL_REDACTION_ENABLED and current_user.role != "admin"

    # Fetch alerts linked to this investigation
    linked_alerts = db.query(Alert).filter(Alert.incident_id == inv_id).all()
    alert_summary = [
        {
            "id": a.id,
            "title": a.title,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None
        }
        for a in linked_alerts
    ]

    # Map event ID to matching alert titles if any
    event_alert_map = {}
    for a in linked_alerts:
        if a.evidence:
            try:
                ev_data = json.loads(a.evidence)
                trig_id = ev_data.get("triggering_event_id")
                if trig_id:
                    event_alert_map.setdefault(trig_id, []).append(a.title)
            except Exception:
                pass

    timeline_items = []
    ips = set()
    protocols = set()
    for ev in events:
        ips.add(ev.src_ip)
        protocols.add(ev.protocol)
        timeline_items.append({
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "src_ip": ev.src_ip,
            "dst_port": ev.dst_port,
            "protocol": ev.protocol,
            "eventid": ev.eventid,
            "username": ev.username,
            "password": "****** (redacted)" if (redact and ev.password) else ev.password,
            "command": ev.command,
            "file_hash": ev.file_hash,
            "severity": ev.severity,
            "country": ev.country,
            "city": ev.city,
            "is_simulated": ev.is_simulated,
            "matched_alerts": event_alert_map.get(ev.id, [])
        })

    primary_ip = list(ips)[0] if len(ips) == 1 else ("Multiple IPs (" + ", ".join(list(ips)[:3]) + ")" if ips else "N/A")
    protos_str = ", ".join(protocols) if protocols else "SSH/Telnet"

    correlation_factors = [
        f"Correlated Attacker Indicator(s): {primary_ip}",
        f"Targeted Protocol(s): {protos_str}",
        f"Clustered Event Volume: {len(events)} events",
        f"Assigned Risk Tier: {inv.asset_tier or 'Critical Gateway'}"
    ]

    return {
        "investigation_id": inv.id,
        "title": inv.title,
        "severity": inv.severity,
        "status": inv.status,
        "risk_score": getattr(inv, "risk_score", 50.0) or 50.0,
        "asset_tier": getattr(inv, "asset_tier", "Critical Gateway") or "Critical Gateway",
        "correlation_summary": f"Correlated {len(events)} disparate security telemetry events under {inv.title}.",
        "correlation_factors": correlation_factors,
        "total_events": len(events),
        "timeline": timeline_items,
        "associated_alerts": alert_summary
    }

@router.post("/{inv_id}/containment", response_model=ContainmentActionResponse)
def execute_containment_action(
    inv_id: int,
    action_in: ContainmentActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if not action_in.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Consequential containment action requires explicit analyst confirmation (confirmed=True)."
        )

    action_type = action_in.action.upper()
    now = datetime.datetime.utcnow()
    target = action_in.target or "Incident Scope"

    if action_type == "BLOCK_IP":
        if not action_in.target:
            raise HTTPException(status_code=400, detail="Target IP is required for BLOCK_IP action")
        
        # Check if already in ThreatIntelIOC
        existing_ioc = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == action_in.target).first()
        if not existing_ioc:
            new_ioc = ThreatIntelIOC(
                indicator=action_in.target,
                ioc_type="ip",
                threat_score=100,
                category="Perimeter Blocklist",
                description=f"Automated containment block via Investigation #{inv_id}. Reason: {action_in.reason}",
                confidence=1.0,
                source="CYVANTIS Automated Incident Containment",
                first_seen=now,
                last_seen=now
            )
            db.add(new_ioc)
        else:
            existing_ioc.threat_score = 100
            existing_ioc.category = "Perimeter Blocklist"
            existing_ioc.last_seen = now

    elif action_type == "CLOSE_INCIDENT":
        inv.status = "closed"
        linked_alerts = db.query(Alert).filter(Alert.incident_id == inv_id).all()
        for al in linked_alerts:
            al.status = "resolved"
            al.is_acknowledged = True
            al.acknowledged_by_id = current_user.id
            al.acknowledged_at = now

    elif action_type == "RESOLVE_INCIDENT":
        inv.status = "resolved"
        linked_alerts = db.query(Alert).filter(Alert.incident_id == inv_id).all()
        for al in linked_alerts:
            al.status = "resolved"
            al.is_acknowledged = True
            al.acknowledged_by_id = current_user.id
            al.acknowledged_at = now

    # Record Audit Log entry
    audit = AuditLog(
        timestamp=now,
        user_id=current_user.id,
        username=current_user.username,
        action="CONTAINMENT_ACTION_EXECUTED",
        resource="Investigations",
        details=f"Executed {action_type} on target '{target}'. Reason: {action_in.reason} (Case #{inv_id})"
    )
    db.add(audit)

    # Append note to investigation
    note = InvestigationNote(
        investigation_id=inv_id,
        author_id=current_user.id,
        note_text=f"[CONTAINMENT ENFORCED] Action: {action_type} on '{target}'. Reason: {action_in.reason}. Operator: {current_user.username}",
        created_at=now
    )
    db.add(note)
    inv.updated_at = now

    db.commit()
    db.refresh(audit)
    db.refresh(note)

    return {
        "success": True,
        "action": action_type,
        "target": target,
        "timestamp": now,
        "audit_id": audit.id,
        "note_id": note.id,
        "message": f"Containment action {action_type} successfully enforced."
    }

@router.get("/{inv_id}/graph")
def get_investigation_graph(
    inv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns threat investigation network graph connecting events, IPs, users,
    commands, file hashes, assets, and CVE vulnerabilities.
    Explicitly tags edges as 'observed' or 'inferred'.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation_graph_service.build_investigation_graph(inv_id, db)

@router.get("/{inv_id}/attack-patterns")
def get_investigation_attack_patterns(
    inv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Identifies multi-stage attack patterns, kill-chain progression,
    distinguishes observed incidents from statistical anomalies and heuristic forecasts.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return attack_pattern_service.analyze_investigation_patterns(inv_id, db)

@router.get("/{inv_id}/asset-context")
def get_investigation_asset_context(
    inv_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns affected asset criticality, exposure, and matching CVE records.
    Explicitly tracks data source, missing fields, and scan freshness.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return asset_vulnerability_service.get_investigation_asset_context(inv_id, db)
