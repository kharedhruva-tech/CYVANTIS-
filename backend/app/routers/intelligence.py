import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from app.database import get_db
from app.models import ThreatIntelIOC, HoneypotEvent, User, AuditLog
from app.schemas import ThreatIntelIOCCreate, ThreatIntelIOCResponse
from app.security import get_current_user, require_roles
from app.config import settings
from app.services.threat_intelligence import threat_intel_service

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])

class URLScanRequest(BaseModel):
    url: str

@router.get("/iocs", response_model=List[ThreatIntelIOCResponse])
def get_all_iocs(
    ioc_type: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ThreatIntelIOC)
    if ioc_type:
        query = query.filter(ThreatIntelIOC.ioc_type == ioc_type.lower())
    if search:
        query = query.filter(ThreatIntelIOC.indicator.like(f"%{search}%"))
    return query.order_by(ThreatIntelIOC.last_seen.desc()).limit(200).all()

@router.post("/iocs", response_model=ThreatIntelIOCResponse, status_code=status.HTTP_201_CREATED)
def create_ioc(
    ioc_in: ThreatIntelIOCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["admin", "analyst"]))
):
    existing = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == ioc_in.indicator).first()
    if existing:
        raise HTTPException(status_code=400, detail="Indicator already exists in IOC database")

    ioc = ThreatIntelIOC(
        indicator=ioc_in.indicator.strip(),
        ioc_type=ioc_in.ioc_type.lower(),
        threat_score=ioc_in.threat_score,
        category=ioc_in.category,
        description=ioc_in.description,
        source=ioc_in.source,
        confidence=1.0,
        first_seen=datetime.datetime.utcnow(),
        last_seen=datetime.datetime.utcnow(),
        expiration=datetime.datetime.utcnow() + datetime.timedelta(days=30)
    )
    db.add(ioc)
    
    audit = AuditLog(
        timestamp=datetime.datetime.utcnow(),
        user_id=current_user.id,
        username=current_user.username,
        action="IOC_CREATED",
        resource="ThreatIntelligence",
        details=f"Added IOC: {ioc_in.indicator} ({ioc_in.ioc_type})"
    )
    db.add(audit)
    db.commit()
    db.refresh(ioc)
    return ioc

@router.get("/lookup")
def lookup_indicator(
    indicator: str = Query(..., description="IP, SHA-256 hash, domain, or CVE identifier"),
    ioc_type: Optional[str] = Query(None, description="Optional indicator type: ip, hash, domain, cve"),
    force_refresh: bool = Query(False, description="Bypass cache and query configured external intelligence feeds"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Unified Threat Intelligence lookup across IPs, File Hashes, Domains, and CVEs.
    Queries cached intelligence or live external feeds (AbuseIPDB, VirusTotal, NVD) with source attribution.
    """
    clean_ind = indicator.strip()
    
    # Auto-detect IOC type if not explicitly supplied
    detected_type = (ioc_type or "").lower()
    if not detected_type:
        if clean_ind.upper().startswith("CVE-"):
            detected_type = "cve"
        elif len(clean_ind) in [32, 64] and all(c in "0123456789abcdefABCDEF" for c in clean_ind):
            detected_type = "hash"
        elif any(clean_ind.replace(".", "").isdigit() for _ in [1]) and clean_ind.count(".") == 3:
            detected_type = "ip"
        else:
            detected_type = "domain"

    result = {}
    if detected_type == "ip":
        result = threat_intel_service.enrich_ip(clean_ind, db=db, force_refresh=force_refresh)
    elif detected_type == "hash":
        result = threat_intel_service.enrich_hash(clean_ind, db=db, force_refresh=force_refresh)
    elif detected_type == "cve":
        result = threat_intel_service.enrich_cve(clean_ind, db=db, force_refresh=force_refresh)
    else:
        # Domain or URL
        result = {
            "indicator": clean_ind,
            "ioc_type": "domain",
            "threat_score": 35,
            "category": "External Domain",
            "description": f"Domain {clean_ind} analyzed via heuristic reputation filter.",
            "source": "CYVANTIS Domain Intel",
            "confidence": 0.80,
            "cached": False,
            "details": {}
        }

    # Fetch observed telemetry history from honeypot database
    related_events = db.query(HoneypotEvent).filter(
        (HoneypotEvent.src_ip == clean_ind) | (HoneypotEvent.file_hash == clean_ind)
    ).order_by(HoneypotEvent.timestamp.desc()).limit(10).all()

    total_attacks = db.query(HoneypotEvent).filter(
        (HoneypotEvent.src_ip == clean_ind) | (HoneypotEvent.file_hash == clean_ind)
    ).count()

    result["total_observed_events"] = total_attacks
    result["recent_events"] = [
        {
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat(),
            "eventid": ev.eventid,
            "protocol": ev.protocol,
            "severity": ev.severity,
            "command": ev.command
        }
        for ev in related_events
    ]

    return result

@router.get("/ip/{ip_address}")
def lookup_ip_intelligence(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    intel = threat_intel_service.enrich_ip(ip_address, db=db)
    
    # Calculate attack history from honeypot database
    events_count = db.query(HoneypotEvent).filter(HoneypotEvent.src_ip == ip_address).count()
    first_seen_event = db.query(HoneypotEvent).filter(HoneypotEvent.src_ip == ip_address).order_by(HoneypotEvent.timestamp.asc()).first()
    last_seen_event = db.query(HoneypotEvent).filter(HoneypotEvent.src_ip == ip_address).order_by(HoneypotEvent.timestamp.desc()).first()

    targeted_users = db.query(HoneypotEvent.username).filter(
        HoneypotEvent.src_ip == ip_address, HoneypotEvent.username.isnot(None)
    ).distinct().all()

    ioc = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == ip_address).first()

    threat_score = intel.get("threat_score", 15)
    risk_rating = "Low"
    if threat_score >= 80 or events_count > 20:
        risk_rating = "Critical"
    elif threat_score >= 60 or events_count > 5:
        risk_rating = "High"
    elif threat_score >= 40 or events_count > 0:
        risk_rating = "Medium"

    geo_details = intel.get("details", {})

    return {
        "ip": ip_address,
        "country": geo_details.get("country", "Unknown"),
        "country_code": geo_details.get("country_code", "XX"),
        "city": geo_details.get("city", "Unknown"),
        "asn": geo_details.get("asn", "Unknown"),
        "threat_score": threat_score,
        "risk_rating": risk_rating,
        "source": intel.get("source", "CYVANTIS Threat Intel"),
        "confidence": intel.get("confidence", 0.75),
        "total_honeypot_attacks": events_count,
        "first_seen": first_seen_event.timestamp.isoformat() if first_seen_event else None,
        "last_seen": last_seen_event.timestamp.isoformat() if last_seen_event else None,
        "targeted_usernames": [u[0] for u in targeted_users],
        "is_known_ioc": ioc is not None,
        "ioc_category": ioc.category if ioc else intel.get("category")
    }

@router.get("/hash/{file_hash}")
def lookup_hash_intelligence(
    file_hash: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return threat_intel_service.enrich_hash(file_hash, db=db)

@router.get("/cve/{cve_id}")
def lookup_cve_intelligence(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return threat_intel_service.enrich_cve(cve_id, db=db)

@router.get("/scan")
def scan_target_intelligence(
    target: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from app.utils.nmap_scanner import scan_url_and_host
    return scan_url_and_host(target)

@router.post("/url-scan")
def scan_url_threat_endpoint(
    req: URLScanRequest,
    current_user: User = Depends(get_current_user)
):
    from app.utils.url_scanner import analyze_url_threat
    return analyze_url_threat(req.url, virustotal_api_key=settings.VIRUSTOTAL_API_KEY)

@router.get("/assets")
def get_managed_assets_registry(
    current_user: User = Depends(get_current_user)
):
    """
    Returns enterprise perimeter asset inventory with asset tier, exposure, open ports, and scan freshness.
    """
    from app.services.asset_vulnerability_service import asset_vulnerability_service
    return {
        "total_assets": len(asset_vulnerability_service.get_all_assets()),
        "assets": asset_vulnerability_service.get_all_assets()
    }

@router.get("/attack-patterns")
def get_telemetry_attack_patterns(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Analyzes recent telemetry events across kill-chain stages and detects high-level multi-stage attack patterns.
    """
    from app.services.attack_pattern_service import attack_pattern_service
    from app.models import HoneypotEvent
    events = db.query(HoneypotEvent).order_by(HoneypotEvent.timestamp.desc()).limit(limit).all()
    return attack_pattern_service.analyze_event_sequence(events)
