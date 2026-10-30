from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import hashlib
import json

@dataclass
class NormalizedEvent:
    event_id: str                      # cowrie.login.failed, auth.login_failed, etc.
    timestamp: datetime                # Always UTC datetime
    src_ip: str
    dst_port: int = 22
    protocol: str = "SSH"              # SSH, Telnet, HTTP, etc.
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    file_hash: Optional[str] = None
    session_id: Optional[str] = None
    duration: float = 0.0
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    asn: str = "AS0000 Unknown"
    severity: str = "medium"           # low, medium, high, critical
    is_simulated: bool = False
    data_source: str = "cowrie"        # cowrie, auth_log, network, synthetic
    raw_payload: Optional[str] = None
    event_hash: Optional[str] = None   # Idempotency SHA-256 fingerprint

    def compute_hash(self) -> str:
        """Calculates deterministic SHA-256 fingerprint for duplicate detection."""
        key_fields = [
            self.event_id,
            self.timestamp.isoformat() if self.timestamp else "",
            self.src_ip or "",
            str(self.dst_port or 22),
            self.protocol or "",
            self.username or "",
            self.session_id or "",
            self.command or "",
            self.file_hash or ""
        ]
        raw_key = "|".join(key_fields)
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "eventid": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else datetime.now(timezone.utc).isoformat(),
            "src_ip": self.src_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "username": self.username,
            "password": self.password,
            "command": self.command,
            "file_hash": self.file_hash,
            "session_id": self.session_id,
            "duration": self.duration,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "asn": self.asn,
            "severity": self.severity,
            "is_simulated": self.is_simulated,
            "data_source": self.data_source,
            "event_hash": self.event_hash or self.compute_hash(),
            "raw_payload": self.raw_payload
        }

class BaseLogSource(ABC):
    """
    Documented extensible interface for all security data ingestion sources
    (Cowrie, Linux Auth, Suricata, Zeek, Windows Events, Firewall logs).
    """
    def __init__(self, source_name: str, source_type: str):
        self.source_name = source_name
        self.source_type = source_type

    @abstractmethod
    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        """Parses a single line or payload into a NormalizedEvent."""
        pass

    @abstractmethod
    def parse_bulk(self, raw_data: str) -> List[NormalizedEvent]:
        """Parses multiple events from a string blob."""
        pass
