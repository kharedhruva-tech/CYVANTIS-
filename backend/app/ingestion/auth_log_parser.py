import re
from datetime import datetime, timezone
from typing import Optional, List
from .base import BaseLogSource, NormalizedEvent

class AuthLogParser(BaseLogSource):
    """
    Parser for standard Linux PAM and OpenSSH syslog records (/var/log/auth.log, /var/log/secure).
    Extracts failed/successful logins, brute-force patterns, IPs, and usernames.
    """
    # Regex patterns for SSH authentication log entries
    FAILED_PATTERN = re.compile(
        r'sshd\[(?P<pid>\d+)\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    )
    ACCEPTED_PATTERN = re.compile(
        r'sshd\[(?P<pid>\d+)\]:\s+Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)',
        re.IGNORECASE
    )

    def __init__(self):
        super().__init__(source_name="Linux Auth Log", source_type="syslog_auth")

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        stripped = line.strip()
        if not stripped or "sshd" not in stripped:
            return None

        now = datetime.now(timezone.utc)
        
        # Check failed login
        failed_match = self.FAILED_PATTERN.search(stripped)
        if failed_match:
            user = failed_match.group("user")
            ip = failed_match.group("ip")
            port = int(failed_match.group("port"))
            pid = failed_match.group("pid")

            ev = NormalizedEvent(
                event_id="auth.login.failed",
                timestamp=now,
                src_ip=ip,
                dst_port=port,
                protocol="SSH",
                username=user,
                session_id=f"sshd-{pid}",
                severity="low",
                is_simulated=False,
                data_source="auth_log",
                raw_payload=stripped
            )
            ev.event_hash = ev.compute_hash()
            return ev

        # Check accepted login
        accepted_match = self.ACCEPTED_PATTERN.search(stripped)
        if accepted_match:
            user = accepted_match.group("user")
            ip = accepted_match.group("ip")
            port = int(accepted_match.group("port"))
            pid = accepted_match.group("pid")

            ev = NormalizedEvent(
                event_id="auth.login.success",
                timestamp=now,
                src_ip=ip,
                dst_port=port,
                protocol="SSH",
                username=user,
                session_id=f"sshd-{pid}",
                severity="high",
                is_simulated=False,
                data_source="auth_log",
                raw_payload=stripped
            )
            ev.event_hash = ev.compute_hash()
            return ev

        return None

    def parse_bulk(self, raw_data: str) -> List[NormalizedEvent]:
        events = []
        for line in raw_data.splitlines():
            ev = self.parse_line(line)
            if ev:
                events.append(ev)
        return events
