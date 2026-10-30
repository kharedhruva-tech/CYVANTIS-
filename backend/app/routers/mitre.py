import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import get_current_user
from app.services.mitre_attack import mitre_attack_service

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK Framework Intelligence"])

@router.get("/catalog")
def get_mitre_catalog(
    current_user: User = Depends(get_current_user)
):
    """
    Returns authoritative MITRE ATT&CK Enterprise Matrix v15.1 technique catalog,
    tactics taxonomy, metadata, and non-definitive disclaimer.
    """
    return mitre_attack_service.get_catalog_metadata()

@router.get("/matrix")
def get_mitre_matrix(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns live ATT&CK matrix coverage with active alert counts across Enterprise tactics.
    """
    return mitre_attack_service.get_live_matrix_coverage(db)

@router.get("/techniques/{technique_id}")
def get_technique_detail(
    technique_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Returns detailed technique profile including rationale, official ATT&CK link, and disclaimer.
    """
    tech = mitre_attack_service.get_technique_by_id(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"MITRE Technique '{technique_id}' not found in catalog")
    return tech

