import csv
import io
import json
import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models import HoneypotEvent, User, AuditLog
from app.schemas import (
    EventPaginatedResponse, EventResponse,
    EventIngestRequest, EventIngestResponse,
    BatchImportRequest, BatchImportResponse
)
from app.security import get_current_user
from app.ingestion.base import NormalizedEvent
from app.services.event_pipeline import process_normalized_event
from app.ingestion.cowrie_parser import CowrieLogParser
from app.ingestion.auth_log_parser import AuthLogParser

router = APIRouter(prefix="/events", tags=["Honeypot Events"])

@router.get("", response_model=EventPaginatedResponse)
def get_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    country: Optional[str] = None,
    eventid: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(HoneypotEvent)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                HoneypotEvent.src_ip.like(pattern),
                HoneypotEvent.username.like(pattern),
                HoneypotEvent.command.like(pattern),
                HoneypotEvent.country.like(pattern),
                HoneypotEvent.session_id.like(pattern)
            )
        )

    if protocol:
        query = query.filter(HoneypotEvent.protocol == protocol)
    if severity:
        query = query.filter(HoneypotEvent.severity == severity)
    if country:
        query = query.filter(HoneypotEvent.country == country)
    if eventid:
        query = query.filter(HoneypotEvent.eventid == eventid)
    if src_ip:
        query = query.filter(HoneypotEvent.src_ip == src_ip)

    if start_date:
        try:
            dt_start = datetime.datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            query = query.filter(HoneypotEvent.timestamp >= dt_start)
        except Exception:
            pass

    if end_date:
        try:
            dt_end = datetime.datetime.fromisoformat(end_date.replace("Z", "+00:00"))
            query = query.filter(HoneypotEvent.timestamp <= dt_end)
        except Exception:
            pass

    total = query.count()
    pages = (total + page_size - 1) // page_size

    items = query.order_by(HoneypotEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()

    is_admin = current_user.role == "admin"
    sanitized_items = []
    for ev in items:
        ev_dict = {
            "id": ev.id,
            "eventid": ev.eventid,
            "timestamp": ev.timestamp,
            "src_ip": ev.src_ip,
            "dst_port": ev.dst_port,
            "protocol": ev.protocol,
            "username": ev.username,
            "password": ev.password if is_admin else ("****** (redacted)" if ev.password else None),
            "command": ev.command,
            "file_hash": ev.file_hash,
            "session_id": ev.session_id,
            "duration": ev.duration,
            "country": ev.country,
            "country_code": ev.country_code,
            "city": ev.city,
            "asn": ev.asn,
            "severity": ev.severity,
            "is_simulated": ev.is_simulated,
            "raw_payload": ev.raw_payload if is_admin else None
        }
        sanitized_items.append(ev_dict)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "items": sanitized_items
    }

@router.get("/{event_id}", response_model=EventResponse)
def get_event_detail(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    event = db.query(HoneypotEvent).filter(HoneypotEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    is_admin = current_user.role == "admin"
    return {
        "id": event.id,
        "eventid": event.eventid,
        "timestamp": event.timestamp,
        "src_ip": event.src_ip,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "username": event.username,
        "password": event.password if is_admin else ("****** (redacted)" if event.password else None),
        "command": event.command,
        "file_hash": event.file_hash,
        "session_id": event.session_id,
        "duration": event.duration,
        "country": event.country,
        "country_code": event.country_code,
        "city": event.city,
        "asn": event.asn,
        "severity": event.severity,
        "is_simulated": event.is_simulated,
        "raw_payload": event.raw_payload if is_admin else None
    }

@router.get("/export/csv")
def export_events_csv(
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(HoneypotEvent)
    if protocol:
        query = query.filter(HoneypotEvent.protocol == protocol)
    if severity:
        query = query.filter(HoneypotEvent.severity == severity)
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(HoneypotEvent.src_ip.like(pattern), HoneypotEvent.username.like(pattern)))

    events = query.order_by(HoneypotEvent.timestamp.desc()).limit(2000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "EventID", "Source IP", "Port", "Protocol",
        "Username", "Password", "Command", "Country", "ASN", "Severity", "Simulated"
    ])

    is_admin = current_user.role == "admin"
    for ev in events:
        pwd_val = ev.password if is_admin else ("****** (redacted)" if ev.password else "")
        writer.writerow([
            ev.id, ev.timestamp.isoformat(), ev.eventid, ev.src_ip, ev.dst_port,
            ev.protocol, ev.username or "", pwd_val, ev.command or "",
            ev.country, ev.asn, ev.severity, ev.is_simulated
        ])

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="EVENT_EXPORT_CSV",
        resource="EventExplorer",
        details=f"Exported {len(events)} events to CSV"
    )
    db.add(audit)
    db.commit()

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cyvantis_events_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
    )

@router.get("/export/json")
def export_events_json(
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(HoneypotEvent)
    if protocol:
        query = query.filter(HoneypotEvent.protocol == protocol)
    if severity:
        query = query.filter(HoneypotEvent.severity == severity)

    events = query.order_by(HoneypotEvent.timestamp.desc()).limit(2000).all()
    data = []
    is_admin = current_user.role == "admin"
    for ev in events:
        data.append({
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat(),
            "eventid": ev.eventid,
            "src_ip": ev.src_ip,
            "dst_port": ev.dst_port,
            "protocol": ev.protocol,
            "username": ev.username,
            "password": ev.password if is_admin else ("****** (redacted)" if ev.password else None),
            "command": ev.command,
            "country": ev.country,
            "asn": ev.asn,
            "severity": ev.severity,
            "is_simulated": ev.is_simulated
        })

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="EVENT_EXPORT_JSON",
        resource="EventExplorer",
        details=f"Exported {len(events)} events to JSON"
    )
    db.add(audit)
    db.commit()

    json_str = json.dumps(data, indent=2)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cyvantis_events_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"}
    )

@router.post("/ingest", response_model=EventIngestResponse, status_code=201)
async def ingest_event(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ingest a single security event through the end-to-end pipeline:
    Validates schema & IP address, checks for duplicates via SHA-256 event fingerprint,
    enriches GeoIP & ASN metadata, executes ML anomaly & severity inference,
    persists HoneypotEvent record, evaluates detection rules, correlates into incident,
    computes explainable risk score, and broadcasts live telemetry via WebSocket.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Viewer role is not authorized to ingest security events")

    ts = payload.timestamp or datetime.datetime.now(datetime.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)

    norm_ev = NormalizedEvent(
        event_id=payload.eventid,
        timestamp=ts,
        src_ip=payload.src_ip,
        dst_port=payload.dst_port,
        protocol=payload.protocol,
        username=payload.username,
        password=payload.password,
        command=payload.command,
        file_hash=payload.file_hash,
        session_id=payload.session_id,
        duration=payload.duration,
        country=payload.country or "Unknown",
        country_code=payload.country_code or "XX",
        city=payload.city or "Unknown",
        asn=payload.asn or "AS0000 Unknown",
        severity=payload.severity or "low",
        is_simulated=False,
        data_source=payload.data_source or "api_ingest",
        raw_payload=payload.raw_payload
    )

    res = await process_normalized_event(norm_ev, db)

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="EVENT_MANUAL_INGEST",
        resource="EventIngestion",
        details=f"Ingested event {payload.eventid} from {payload.src_ip} (Status: {res['status']})"
    )
    db.add(audit)
    db.commit()

    return res

@router.post("/import", response_model=BatchImportResponse)
async def import_events_batch(
    payload: BatchImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Batch import multiple security events via structured JSON array.
    Normalizes timestamps, deduplicates records, correlates attacks, and generates comprehensive batch metrics.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Viewer role is not authorized to import security events")

    results = []
    persisted = 0
    duplicates = 0
    errors = 0
    alerts_generated = 0

    for req in payload.events:
        try:
            ts = req.timestamp or datetime.datetime.now(datetime.timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)

            norm_ev = NormalizedEvent(
                event_id=req.eventid,
                timestamp=ts,
                src_ip=req.src_ip,
                dst_port=req.dst_port,
                protocol=req.protocol,
                username=req.username,
                password=req.password,
                command=req.command,
                file_hash=req.file_hash,
                session_id=req.session_id,
                duration=req.duration,
                country=req.country or "Unknown",
                country_code=req.country_code or "XX",
                city=req.city or "Unknown",
                asn=req.asn or "AS0000 Unknown",
                severity=req.severity or "low",
                is_simulated=False,
                data_source=req.data_source or "batch_import",
                raw_payload=req.raw_payload
            )
            res = await process_normalized_event(norm_ev, db)
            results.append(res)
            if res.get("status") == "persisted":
                persisted += 1
                if res.get("findings_count", 0) > 0:
                    alerts_generated += 1
            elif res.get("status") == "duplicate":
                duplicates += 1
        except Exception as e:
            errors += 1
            results.append({
                "success": False,
                "status": "rejected",
                "event_id": None,
                "event_hash": "",
                "evaluated_severity": "low",
                "findings_count": 0,
                "incident_id": None,
                "risk_score": None,
                "is_anomalous": False,
                "message": f"Processing error: {str(e)}"
            })

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="EVENT_BATCH_IMPORT",
        resource="EventIngestion",
        details=f"Batch imported {len(payload.events)} events (Persisted: {persisted}, Duplicates: {duplicates}, Errors: {errors})"
    )
    db.add(audit)
    db.commit()

    return {
        "total_received": len(payload.events),
        "persisted": persisted,
        "duplicates": duplicates,
        "errors": errors,
        "alerts_generated": alerts_generated,
        "events": results
    }

@router.post("/upload", response_model=BatchImportResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ingest a security log file (.json, .jsonl, .log).
    Automatically identifies Cowrie honeypot or Linux PAM/syslog format,
    normalizes all entries, persists records, and updates alerts and incidents.
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Viewer role is not authorized to upload security logs")

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds 10MB limit")

    text = content.decode("utf-8", errors="ignore")
    cowrie_parser = CowrieLogParser()
    auth_parser = AuthLogParser()

    norm_events = []
    stripped = text.strip()

    # Case 1: JSON array format
    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            arr = json.loads(stripped)
            for item in arr:
                line_str = json.dumps(item)
                ev = cowrie_parser.parse_line(line_str)
                if ev:
                    norm_events.append(ev)
        except Exception:
            pass

    # Case 2: Line by line (JSON lines or Syslog)
    if not norm_events:
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            ev = None
            if line_str.startswith("{"):
                ev = cowrie_parser.parse_line(line_str)
            else:
                ev = auth_parser.parse_line(line_str)
            if ev:
                norm_events.append(ev)

    results = []
    persisted = 0
    duplicates = 0
    errors = 0
    alerts_generated = 0

    for norm_ev in norm_events:
        try:
            res = await process_normalized_event(norm_ev, db)
            results.append(res)
            if res.get("status") == "persisted":
                persisted += 1
                if res.get("findings_count", 0) > 0:
                    alerts_generated += 1
            elif res.get("status") == "duplicate":
                duplicates += 1
        except Exception as e:
            errors += 1
            results.append({
                "success": False,
                "status": "rejected",
                "event_id": None,
                "event_hash": norm_ev.event_hash or "",
                "evaluated_severity": "low",
                "findings_count": 0,
                "incident_id": None,
                "risk_score": None,
                "is_anomalous": False,
                "message": f"Processing error: {str(e)}"
            })

    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="LOG_FILE_UPLOAD",
        resource="EventIngestion",
        details=f"Uploaded {file.filename} ({len(norm_events)} events parsed. Persisted: {persisted}, Duplicates: {duplicates})"
    )
    db.add(audit)
    db.commit()

    return {
        "total_received": len(norm_events),
        "persisted": persisted,
        "duplicates": duplicates,
        "errors": errors,
        "alerts_generated": alerts_generated,
        "events": results
    }
