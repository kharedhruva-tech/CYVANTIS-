import datetime
import bcrypt
from typing import Optional, List
from fastapi import Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app import models, schemas

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    # Truncate password to 72 bytes if needed (bcrypt spec max length)
    pwd_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def get_current_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    token_query: Optional[str] = Query(None, alias="token")
) -> models.User:
    auth_token = token or token_query
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not auth_token:
        raise credentials_exception

    try:
        payload = jwt.decode(auth_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user account")
    return user

def get_current_user_optional(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme),
    token_query: Optional[str] = Query(None, alias="token")
) -> Optional[models.User]:
    auth_token = token or token_query
    if not auth_token:
        return None
    try:
        payload = jwt.decode(auth_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        user = db.query(models.User).filter(models.User.username == username).first()
        if user and user.is_active:
            return user
    except Exception:
        pass
    return None

def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User role '{current_user.role}' is not authorized to perform this operation. Allowed: {allowed_roles}"
            )
        return current_user
    return role_checker


def check_user_membership(user: models.User, db: Session) -> dict:
    """Checks the live membership and subscription status of a user."""
    # 1. Chief SOC Administrator has permanent unlimited Enterprise clearance
    if user.role == "admin":
        return {
            "tier": "enterprise_admin",
            "is_premium": True,
            "status": "active",
            "plan_code": "yearly",
            "plan_name": "Chief SOC Administrator Clearance",
            "start_date": None,
            "end_date": None,
            "days_remaining": 9999,
            "daily_scan_limit": -1,
            "features": ["All Enterprise Capabilities", "Full Administrative Access", "Unlimited Scans"]
        }

    now = datetime.datetime.utcnow()
    # 2. Check active membership record
    active_mem = (
        db.query(models.Membership)
        .filter(
            models.Membership.user_id == user.id,
            models.Membership.status == "active",
            models.Membership.end_date > now
        )
        .order_by(models.Membership.end_date.desc())
        .first()
    )

    if active_mem:
        plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == active_mem.plan_id).first()
        import json
        features_list = json.loads(plan.features) if plan and plan.features else []
        days_rem = max(0, (active_mem.end_date - now).days)
        return {
            "tier": plan.tier if plan else "premium",
            "is_premium": True,
            "status": "active",
            "plan_code": plan.code if plan else "premium",
            "plan_name": plan.name if plan else "Premium Plan",
            "start_date": active_mem.start_date,
            "end_date": active_mem.end_date,
            "days_remaining": days_rem,
            "daily_scan_limit": plan.daily_scan_limit if plan else 100,
            "features": features_list
        }

    # 3. Check if membership has expired
    expired_mem = (
        db.query(models.Membership)
        .filter(models.Membership.user_id == user.id)
        .order_by(models.Membership.end_date.desc())
        .first()
    )

    if expired_mem and expired_mem.end_date <= now:
        plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == expired_mem.plan_id).first()
        return {
            "tier": "free",
            "is_premium": False,
            "status": "expired",
            "plan_code": "free",
            "plan_name": "Free Tier (Expired)",
            "start_date": expired_mem.start_date,
            "end_date": expired_mem.end_date,
            "days_remaining": 0,
            "daily_scan_limit": 5,
            "features": ["Basic cybersecurity tools", "5 daily scans", "Standard dashboard access"]
        }

    # 4. Check for pending payment orders
    pending_order = (
        db.query(models.PaymentOrder)
        .filter(
            models.PaymentOrder.user_id == user.id,
            models.PaymentOrder.status == "pending"
        )
        .order_by(models.PaymentOrder.created_at.desc())
        .first()
    )

    status_str = "pending_approval" if pending_order else "none"

    return {
        "tier": "free",
        "is_premium": False,
        "status": status_str,
        "plan_code": "free",
        "plan_name": "Free Tier",
        "start_date": None,
        "end_date": None,
        "days_remaining": None,
        "daily_scan_limit": 5,
        "features": ["Basic cybersecurity tools", "5 daily scans", "Standard dashboard access"]
    }

def require_premium_access(feature_name: str = "This Cybersecurity Tool"):
    """Server-side dependency enforcing active premium subscription before executing protected operations."""
    def membership_checker(
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        info = check_user_membership(current_user, db)
        if not info["is_premium"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: '{feature_name}' requires an active CYVANTIS Premium Membership. Please upgrade your subscription.",
                headers={"X-Upgrade-Required": "true"}
            )
        return current_user
    return membership_checker
