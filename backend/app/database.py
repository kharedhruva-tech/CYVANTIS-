import os
from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

# Create database engine for SQLite with 30s connection timeout
connect_args = {"check_same_thread": False, "timeout": 30.0} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

# Enable Write-Ahead Logging (WAL) and busy timeout for concurrent SQLite access
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

# Auto-migrate schema columns across all database connections
with engine.connect() as conn:
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

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
