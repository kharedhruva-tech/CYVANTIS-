import asyncio
import time
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import User
from app.utils.seed_data import seed_database
from app.cowrie_watcher import start_cowrie_monitoring
from app.websocket import manager

from app.routers import (
    auth, users, events, analytics, intelligence, investigations,
    rules, reports, admin_data, storage, health, audit, security_audit, tools, advisories, settings as settings_router, ml, recon, pentest_guardrails, advanced_pentest, living_telemetry,
    domain_intel, offensive_testing, cli_router, defensive_suite, elite_ops, ai_terminal, mitre, memberships
)

# Initialize database schema
Base.metadata.create_all(bind=engine)

# Auto-migrate missing schema columns if upgrading existing database
with engine.connect() as conn:
    from sqlalchemy import text
    for alter_cmd in [
        "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 1 NOT NULL",
        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0 NOT NULL",
        "ALTER TABLE users ADD COLUMN locked_until DATETIME",
        "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN is_totp_enabled BOOLEAN DEFAULT 0 NOT NULL",
        "ALTER TABLE honeypot_events ADD COLUMN data_source VARCHAR(50) DEFAULT 'cowrie'",
        "ALTER TABLE honeypot_events ADD COLUMN event_hash VARCHAR(64)",
        "ALTER TABLE alerts ADD COLUMN risk_score FLOAT DEFAULT 50.0",
        "ALTER TABLE alerts ADD COLUMN risk_factors TEXT",
        "ALTER TABLE alerts ADD COLUMN incident_id INTEGER",
        "ALTER TABLE alerts ADD COLUMN mitre_tactics VARCHAR(100)",
        "ALTER TABLE alerts ADD COLUMN mitre_techniques VARCHAR(100)",
        "ALTER TABLE alerts ADD COLUMN recommended_actions TEXT",
        "ALTER TABLE alerts ADD COLUMN evidence TEXT",
        "ALTER TABLE threat_intel_iocs ADD COLUMN confidence FLOAT DEFAULT 1.0",
        "ALTER TABLE threat_intel_iocs ADD COLUMN raw_intel TEXT",
        "ALTER TABLE threat_intel_iocs ADD COLUMN expiration DATETIME",
        "ALTER TABLE investigations ADD COLUMN risk_score FLOAT DEFAULT 50.0",
        "ALTER TABLE investigations ADD COLUMN asset_tier VARCHAR(50) DEFAULT 'Critical Gateway'",
        "ALTER TABLE alerts ADD COLUMN feedback_label VARCHAR(30)",
        "ALTER TABLE alerts ADD COLUMN feedback_justification TEXT",
        "ALTER TABLE alerts ADD COLUMN feedback_by_id INTEGER",
        "ALTER TABLE alerts ADD COLUMN feedback_at DATETIME"
    ]:
        try:
            conn.execute(text(alter_cmd))
            conn.commit()
        except Exception:
            pass

# Seed database on boot and ensure default accounts bypass forced password reset
db = SessionLocal()
try:
    seed_database(db)
    db.query(User).filter(User.username.in_(['admin', 'analyst', 'viewer'])).update(
        {'must_change_password': False}, synchronize_session=False
    )
    db.commit()
finally:
    db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("[+] ================================================================", flush=True)
    print("[+] CYVANTIS SOC Gateway Backend Online!", flush=True)
    print(f"[+] Base API URL: http://localhost:8000{settings.API_V1_STR}", flush=True)
    print(f"[+] Swagger Docs: http://localhost:8000{settings.API_V1_STR}/docs", flush=True)
    print("[+] Honeypot Ingestion Engine: ACTIVE", flush=True)
    print("[+] ================================================================", flush=True)
    monitor_task = asyncio.create_task(start_cowrie_monitoring())
    try:
        yield
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan
)

# OWASP Defensive Security Headers Middleware
@app.middleware("http")
async def add_owasp_security_headers(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 1)
    client_ip = request.client.host if request.client else "unknown"
    now_str = datetime.now().strftime("%H:%M:%S")
    # Formatted non-sensitive request log
    print(f"[*] [{now_str}] HTTP {request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms) [{client_ip}]", flush=True)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "connect-src 'self' ws: wss: http: https:;"
    )
    return response

# Strict & Configured CORS Setup
cors_origins = settings.get_cors_origins()
if "*" in cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

# Include Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(users.router, prefix=settings.API_V1_STR)
app.include_router(events.router, prefix=settings.API_V1_STR)
app.include_router(analytics.router, prefix=settings.API_V1_STR)
app.include_router(intelligence.router, prefix=settings.API_V1_STR)
app.include_router(investigations.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(admin_data.router, prefix=settings.API_V1_STR)
app.include_router(storage.router, prefix=settings.API_V1_STR)
app.include_router(health.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)
app.include_router(security_audit.router, prefix=settings.API_V1_STR)
app.include_router(tools.router, prefix=settings.API_V1_STR)
app.include_router(advisories.router, prefix=settings.API_V1_STR)
app.include_router(settings_router.router, prefix=settings.API_V1_STR)
app.include_router(ml.router, prefix=settings.API_V1_STR)
app.include_router(recon.router, prefix=settings.API_V1_STR)
app.include_router(pentest_guardrails.router, prefix=settings.API_V1_STR)
app.include_router(advanced_pentest.router, prefix=settings.API_V1_STR)
app.include_router(living_telemetry.router, prefix=settings.API_V1_STR)
app.include_router(domain_intel.router, prefix=settings.API_V1_STR)
app.include_router(offensive_testing.router, prefix=settings.API_V1_STR)
app.include_router(cli_router.router, prefix=settings.API_V1_STR)
app.include_router(defensive_suite.router, prefix=settings.API_V1_STR)
app.include_router(elite_ops.router, prefix=settings.API_V1_STR)
app.include_router(ai_terminal.router, prefix=settings.API_V1_STR)
app.include_router(mitre.router, prefix=settings.API_V1_STR)
app.include_router(memberships.router, prefix=settings.API_V1_STR)

# Protected WebSocket endpoint for Live Honeypot & Incident Feed
@app.websocket("/api/v1/ws/events")
async def websocket_events_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    auth_token = token
    subprotocol_to_accept = None
    if not auth_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            auth_token = auth_header.split(" ")[1]

    # Inspect Sec-WebSocket-Protocol for browser client subprotocol negotiations
    req_subprotocols = websocket.headers.get("sec-websocket-protocol", "")
    if req_subprotocols:
        protocols = [p.strip() for p in req_subprotocols.split(",") if p.strip()]
        if "cyvantis.bearer" in protocols:
            subprotocol_to_accept = "cyvantis.bearer"
        if not auth_token:
            for p in protocols:
                if p != "cyvantis.bearer":
                    auth_token = p
                    break

    if not auth_token:
        # Reject unauthorized WebSocket client per Section 11 security hardening
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(auth_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role", "analyst")
        if not username:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    user_meta = {"username": username, "role": role}
    await manager.connect(websocket, user_meta=user_meta, subprotocol=subprotocol_to_accept)
    client_ip = websocket.client.host if websocket.client else "unknown"
    now_str = datetime.now().strftime("%H:%M:%S")
    print(f"[*] [{now_str}] [WS CONNECTED] Authenticated client '{username}' ({role}) from {client_ip}", flush=True)

    try:
        while True:
            # Keep connection alive, listen for ping/messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print(f"[*] [{datetime.now().strftime('%H:%M:%S')}] [WS DISCONNECTED] Client '{username}' disconnected", flush=True)
    except Exception:
        manager.disconnect(websocket)

@app.get("/")
def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs": f"{settings.API_V1_STR}/docs"
    }
