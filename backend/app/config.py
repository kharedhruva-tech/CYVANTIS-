import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "CYVANTIS - Enterprise Gateway Intelligence & Security Nexus"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cyvantis_super_secret_jwt_key_2026_soc_enterprise_mode_secure")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    CREDENTIAL_REDACTION_ENABLED: bool = True

    # Rotated Default Administrative Credentials (Configurable via Environment Variables)
    ADMIN_DEFAULT_PASSWORD: str = os.getenv("ADMIN_DEFAULT_PASSWORD", "Cyv@ntis#Adm!n$Sec9821")
    ANALYST_DEFAULT_PASSWORD: str = os.getenv("ANALYST_DEFAULT_PASSWORD", "Cyv@ntis#An@lyst$Sec5614")
    VIEWER_DEFAULT_PASSWORD: str = os.getenv("VIEWER_DEFAULT_PASSWORD", "Cyv@ntis#V!ew$Sec2390")

    # CORS
    CORS_ORIGINS: str = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000,http://localhost,http://127.0.0.1"
    )
    
    # Database - SQLite Primary Storage (NO PostgreSQL)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyvantis.db")
    
    # Cowrie Honeypot Integration & Real Log Ingestion
    COWRIE_LOG_PATH: str = os.getenv("COWRIE_LOG_PATH", "./data/cowrie.json")
    SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "true").lower() in ("true", "1", "yes")
    SIMULATION_INTERVAL_SECONDS: float = float(os.getenv("SIMULATION_INTERVAL_SECONDS", "3.0"))
    
    # Threat Intelligence Integration
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_API_URL: str = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    
    # Storage & Backups
    BACKUP_DIR: str = os.getenv("BACKUP_DIR", "./backups")
    RETENTION_DAYS: int = int(os.getenv("RETENTION_DAYS", "90"))

    # Premium Membership & Payment System
    RAZORPAY_KEY_ID: str = os.getenv("RAZORPAY_KEY_ID", "rzp_test_CYVANTIS2026")
    RAZORPAY_KEY_SECRET: str = os.getenv("RAZORPAY_KEY_SECRET", "mock_sec_cyvantis_razorpay")
    DEFAULT_UPI_ID: str = os.getenv("DEFAULT_UPI_ID", "cyvantis.pay@upi")
    DEFAULT_UPI_NAME: str = os.getenv("DEFAULT_UPI_NAME", "CYVANTIS Cybersecurity")
    RECEIPTS_DIR: str = os.getenv("RECEIPTS_DIR", "./data/receipts")
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")

    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env", extra="allow")

    def get_cors_origins(self) -> List[str]:
        if not self.CORS_ORIGINS:
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

settings = Settings()
