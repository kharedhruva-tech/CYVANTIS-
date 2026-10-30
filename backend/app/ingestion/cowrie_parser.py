import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from .base import BaseLogSource, NormalizedEvent

logger = logging.getLogger(__name__)

class CowrieLogParser(BaseLogSource):
    """
    Production-grade parser for Cowrie SSH/Telnet honeypot JSON logs.
    Normalizes varied Cowrie event schemas into standardized CYVANTIS NormalizedEvent records.
    """
    def __init__(self):
        super().__init__(source_name="Cowrie Honeypot", source_type="honeypot_json")

    def parse_timestamp(self, ts_str: Optional[str]) -> datetime:
        """Parses ISO8601 timestamp string into a timezone-aware UTC datetime."""
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def determine_severity(self, eventid: str, command: Optional[str], file_hash: Optional[str]) -> str:
        cmd_lower = (command or "").lower()
        if eventid == "cowrie.session.file_download" or file_hash:
            return "critical"
        if eventid == "cowrie.login.success":
            return "high"
        if eventid == "cowrie.command.input":
            if any(k in cmd_lower for k in ["wget", "curl", "chmod +x", "nc -e", "/dev/tcp", "sh -i", "miner"]):
                return "critical"
            if any(k in cmd_lower for k in ["uname", "cat /etc", "id", "whoami", "ps aux", "netstat"]):
                return "medium"
            return "high"
        if eventid == "cowrie.login.failed":
            return "low"
        return "low"

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        """Parses a single Cowrie JSON line into a NormalizedEvent."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            data: Dict[str, Any] = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug("Failed to parse malformed Cowrie JSON line: %s", e)
            return None

        if not isinstance(data, dict):
            return None

        eventid = str(data.get("eventid", "cowrie.generic.event")).strip()
        ts = self.parse_timestamp(data.get("timestamp"))
        src_ip = str(data.get("src_ip", "0.0.0.0")).strip()
        if not src_ip or src_ip == "None":
            src_ip = "0.0.0.0"

        dst_port = int(data.get("dst_port", 22) or 22)
        protocol = str(data.get("protocol", "SSH")).upper()
        if protocol not in ["SSH", "TELNET"]:
            protocol = "SSH"

        username = data.get("username")
        password = data.get("password")
        
        command = data.get("input") or data.get("command") or data.get("message")
        if isinstance(command, list):
            command = " ".join(str(c) for c in command)

        file_hash = data.get("shasum") or data.get("file_hash") or data.get("hash")
        session_id = data.get("session") or data.get("session_id")
        duration = float(data.get("duration", 0.0) or 0.0)

        severity = self.determine_severity(eventid, command, file_hash)

        event = NormalizedEvent(
            event_id=eventid,
            timestamp=ts,
            src_ip=src_ip,
            dst_port=dst_port,
            protocol=protocol,
            username=str(username) if username is not None else None,
            password=str(password) if password is not None else None,
            command=str(command) if command is not None else None,
            file_hash=str(file_hash) if file_hash is not None else None,
            session_id=str(session_id) if session_id is not None else None,
            duration=duration,
            severity=severity,
            is_simulated=False, # Real ingested log
            data_source="cowrie",
            raw_payload=json.dumps(data)
        )
        event.event_hash = event.compute_hash()
        return event

    def parse_bulk(self, raw_data: str) -> List[NormalizedEvent]:
        events = []
        for line in raw_data.splitlines():
            ev = self.parse_line(line)
            if ev:
                events.append(ev)
        return events
