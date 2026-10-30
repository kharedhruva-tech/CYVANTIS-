"""
CYVANTIS Attack Pattern & Multi-Stage Sequence Analysis Service
Analyzes ordered telemetry sequences, detects cyber kill-chain progression,
and distinguishes OBSERVED INCIDENTS from ANOMALIES and HEURISTIC FORECASTS.
"""

from typing import Dict, Any, List, Optional
import datetime
import json
from sqlalchemy.orm import Session
from app.models import HoneypotEvent, Investigation

class AttackPatternService:
    """Deterministic sequence rules and kill-chain stage progression analyzer."""

    KILL_CHAIN_STAGES = [
        {"stage": "reconnaissance", "name": "Reconnaissance & Port Probe", "order": 1},
        {"stage": "credential_access", "name": "Credential Access & Password Spray", "order": 2},
        {"stage": "initial_access", "name": "Initial Foothold & Compromise", "order": 3},
        {"stage": "discovery", "name": "System Discovery & Enumeration", "order": 4},
        {"stage": "privilege_escalation", "name": "Privilege Escalation & Account Manipulation", "order": 5},
        {"stage": "ingress_and_c2", "name": "Tool Ingress & C2 Execution", "order": 6}
    ]

    def analyze_event_sequence(self, events: List[HoneypotEvent]) -> Dict[str, Any]:
        """
        Evaluates ordered events against deterministic attack pattern sequence rules.
        Distinguishes:
        1. Observed Incidents (verifiable factual progression)
        2. Statistical Anomalies (volume or timing outliers)
        3. Heuristic Forecasts (probabilistic next-step projection with disclaimer)
        """
        if not events:
            return {
                "pattern_detected": False,
                "pattern_name": "No telemetry sequence observed",
                "progression_percentage": 0.0,
                "confidence": 0.0,
                "stages_observed": [],
                "observed_incidents": [],
                "statistical_anomalies": [],
                "heuristic_forecast": None,
                "time_range": None,
                "explanation": "Insufficient event records to perform sequence correlation."
            }

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp
        duration_seconds = max(0, int((end_time - start_time).total_seconds()))

        observed_stages = []
        observed_incidents = []
        anomalies = []

        has_connect = any(e.eventid == "cowrie.session.connect" for e in sorted_events)
        failed_logins = [e for e in sorted_events if e.eventid in ["cowrie.login.failed", "auth.login.failed"]]
        successful_logins = [e for e in sorted_events if e.eventid in ["cowrie.login.success", "auth.login.accepted"]]
        commands = [e for e in sorted_events if e.command]
        file_downloads = [e for e in sorted_events if e.file_hash or e.eventid == "cowrie.session.file_download"]

        # Stage 1: Reconnaissance
        if has_connect or len(sorted_events) > 1:
            observed_stages.append({
                "stage": "reconnaissance",
                "name": "Reconnaissance & Port Probe",
                "status": "OBSERVED",
                "evidence_count": len(sorted_events)
            })

        # Stage 2: Credential Access
        if len(failed_logins) >= 2:
            observed_stages.append({
                "stage": "credential_access",
                "name": "Credential Access & Password Spray",
                "status": "OBSERVED",
                "evidence_count": len(failed_logins),
                "details": f"{len(failed_logins)} failed authentication attempts observed"
            })
            observed_incidents.append(f"Brute-force spray of {len(failed_logins)} attempts")

        # Stage 3: Initial Access
        if successful_logins:
            observed_stages.append({
                "stage": "initial_access",
                "name": "Initial Foothold & Compromise",
                "status": "OBSERVED",
                "evidence_count": len(successful_logins),
                "details": f"Authenticated session established as user '{successful_logins[0].username}'"
            })
            observed_incidents.append(f"Successful authentication as '{successful_logins[0].username}'")

        # Stage 4: Discovery
        disc_commands = [c for c in commands if any(k in (c.command or "").lower() for k in ["uname", "id", "whoami", "ps", "netstat", "ifconfig"])]
        if disc_commands:
            observed_stages.append({
                "stage": "discovery",
                "name": "System Discovery & Enumeration",
                "status": "OBSERVED",
                "evidence_count": len(disc_commands),
                "details": f"Executed discovery commands: {[c.command for c in disc_commands[:3]]}"
            })
            observed_incidents.append(f"System discovery commands executed: {len(disc_commands)}")

        # Stage 5: Privilege Escalation
        priv_commands = [c for c in commands if any(k in (c.command or "").lower() for k in ["/etc/shadow", "/etc/passwd", "sudo", "chmod +x", "authorized_keys"])]
        if priv_commands:
            observed_stages.append({
                "stage": "privilege_escalation",
                "name": "Privilege Escalation & Account Manipulation",
                "status": "OBSERVED",
                "evidence_count": len(priv_commands),
                "details": f"Privileged command attempts: {[c.command for c in priv_commands[:2]]}"
            })
            observed_incidents.append("Privileged credential or access manipulation attempt")

        # Stage 6: Tool Ingress & C2
        ingress_commands = [c for c in commands if any(k in (c.command or "").lower() for k in ["wget", "curl", "miner", "http://", "https://", "ftp://"])]
        if file_downloads or ingress_commands:
            observed_stages.append({
                "stage": "ingress_and_c2",
                "name": "Tool Ingress & C2 Execution",
                "status": "OBSERVED",
                "evidence_count": len(file_downloads) + len(ingress_commands),
                "details": "Malicious payload download or outbound C2 dropper invocation"
            })
            observed_incidents.append("Dropper retrieval or external C2 callback detected")

        # Statistical Anomaly Check: Rapid burst execution
        if duration_seconds < 10 and len(sorted_events) >= 5:
            anomalies.append({
                "type": "HIGH_FREQUENCY_BURST",
                "metric": f"{len(sorted_events)} events in {duration_seconds}s",
                "severity": "HIGH",
                "description": "Event velocity significantly exceeds human interactive keystroke baseline (automated scripted tool suspected)"
            })

        # Calculate progression percentage (out of 6 stages)
        progression_pct = round((len(observed_stages) / 6.0) * 100, 1)

        # Pattern identification & naming
        if len(observed_stages) >= 4 and any(s["stage"] == "ingress_and_c2" for s in observed_stages):
            pattern_name = "Automated Multi-Stage Dropper & C2 Execution"
            confidence = 0.94
            explanation = (
                "Adversary completed an end-to-end multi-stage intrusion sequence: initial probe, credential bypass, "
                "local enumeration, and tool ingress transfer."
            )
        elif any(s["stage"] == "credential_access" for s in observed_stages) and successful_logins:
            pattern_name = "Dictionary Brute Force Leading to Foothold"
            confidence = 0.88
            explanation = (
                f"Adversary launched brute-force dictionary attempts that culminated in authenticated session access "
                f"for user '{successful_logins[0].username}'."
            )
        elif len(failed_logins) >= 5:
            pattern_name = "Distributed Credential Spraying Campaign"
            confidence = 0.85
            explanation = f"High-volume repetitive authentication failures targeting administrative gateway users."
        else:
            pattern_name = "Host Probing & Preliminary Reconnaissance"
            confidence = 0.72
            explanation = "Adversary conducted reconnaissance connections without deep lateral progression."

        # Heuristic Forecast (Non-deterministic projection)
        forecast = None
        if len(observed_stages) >= 3:
            if not any(s["stage"] == "ingress_and_c2" for s in observed_stages):
                forecast = {
                    "projected_next_stage": "Tool Ingress / Binary Dropper Download",
                    "predicted_actions": ["wget/curl execution of remote payload", "bash reverse shell setup", "cron persistence"],
                    "confidence": 0.76,
                    "disclaimer": "HEURISTIC FORECAST: Based on statistical progression of honeypot attack patterns. Not a guarantee of adversary intent. Validate against host logs before containment."
                }
            else:
                forecast = {
                    "projected_next_stage": "Cryptomining or C2 Beaconing",
                    "predicted_actions": ["Background execution of miner payload", "Outbound DNS beaconing to external C2", "Log clearing (/var/log/lastlog)"],
                    "confidence": 0.82,
                    "disclaimer": "HEURISTIC FORECAST: Based on statistical progression of honeypot attack patterns. Not a guarantee of adversary intent. Validate against host logs before containment."
                }

        return {
            "pattern_detected": True,
            "pattern_name": pattern_name,
            "progression_percentage": progression_pct,
            "confidence": confidence,
            "stages_observed": observed_stages,
            "total_stages_count": 6,
            "observed_incidents": observed_incidents,
            "statistical_anomalies": anomalies,
            "heuristic_forecast": forecast,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": duration_seconds
            },
            "explanation": explanation
        }

    def analyze_investigation_patterns(self, inv_id: int, db: Session) -> Dict[str, Any]:
        """Analyzes attack patterns for a specific investigation case."""
        incident = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not incident or not incident.related_events:
            return self.analyze_event_sequence([])

        try:
            ev_ids = json.loads(incident.related_events)
            events = db.query(HoneypotEvent).filter(HoneypotEvent.id.in_(ev_ids)).all()
        except Exception:
            events = []

        result = self.analyze_event_sequence(events)
        result["investigation_id"] = inv_id
        result["investigation_title"] = incident.title
        return result

attack_pattern_service = AttackPatternService()

