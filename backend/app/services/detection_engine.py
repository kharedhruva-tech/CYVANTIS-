import datetime
import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models import DetectionRule, HoneypotEvent, ThreatIntelIOC
from app.ingestion.base import NormalizedEvent

class DetectionFinding:
    def __init__(
        self,
        rule_name: str,
        title: str,
        severity: str,
        confidence: float,
        explanation: str,
        evidence: Dict[str, Any],
        mitre_tactics: str = "Initial Access",
        mitre_techniques: str = "T1078 Valid Accounts",
        recommended_actions: Optional[List[Dict[str, Any]]] = None,
        rule_id: Optional[int] = None
    ):
        self.rule_name = rule_name
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.explanation = explanation
        self.evidence = evidence
        self.mitre_tactics = mitre_tactics
        self.mitre_techniques = mitre_techniques
        self.recommended_actions = recommended_actions or []
        self.rule_id = rule_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "rule_id": self.rule_id
        }

class DetectionEngine:
    """
    Explainable Detection Engine combining rule-based heuristics and anomaly verification.
    Evaluates events against configurable database detection rules and known threat indicators.
    """

    def evaluate_event(
        self,
        event: NormalizedEvent,
        db: Session,
        ml_prediction: Optional[Dict[str, Any]] = None
    ) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if not db:
            return findings

        # Fetch all enabled detection rules
        active_rules = db.query(DetectionRule).filter(DetectionRule.is_enabled == True).all()
        rules_by_type = {r.rule_type: r for r in active_rules}

        now = datetime.datetime.utcnow()
        time_window = now - datetime.timedelta(minutes=15)

        # ------------------------------------------------------------------
        # Rule 1: Brute Force / Repeated Failed Authentications
        # ------------------------------------------------------------------
        rule_bf = rules_by_type.get("brute_force")
        threshold_bf = rule_bf.threshold if rule_bf else 5
        if event.event_id in ["cowrie.login.failed", "auth.login.failed"]:
            recent_fails = db.query(func.count(HoneypotEvent.id)).filter(
                HoneypotEvent.src_ip == event.src_ip,
                HoneypotEvent.eventid.in_(["cowrie.login.failed", "auth.login.failed"]),
                HoneypotEvent.timestamp >= time_window
            ).scalar() or 0

            # Include current event
            total_fails = recent_fails + 1
            if total_fails >= threshold_bf:
                findings.append(DetectionFinding(
                    rule_name="SSH Brute Force Detection",
                    title=f"SSH Credential Brute-Force from {event.src_ip}",
                    severity="high" if total_fails < 15 else "critical",
                    confidence=0.92,
                    explanation=(
                        f"Detected {total_fails} failed authentication attempts from IP {event.src_ip} "
                        f"within a 15-minute window, exceeding threshold of {threshold_bf}."
                    ),
                    evidence={
                        "src_ip": event.src_ip,
                        "failed_attempts": total_fails,
                        "window_minutes": 15,
                        "targeted_username": event.username,
                        "protocol": event.protocol
                    },
                    mitre_tactics="Credential Access",
                    mitre_techniques="T1110.001 Password Guessing",
                    recommended_actions=[
                        {
                            "action": "Enforce Rate Limiting / Drop Inbound Traffic",
                            "reason": "Exceeded failed authentication security policy threshold",
                            "priority": "HIGH",
                            "confidence": 0.90
                        },
                        {
                            "action": "Cross-reference IP with AbuseIPDB Watchlist",
                            "reason": "Verify whether source IP is known botnet node",
                            "priority": "MEDIUM",
                            "confidence": 0.85
                        }
                    ],
                    rule_id=rule_bf.id if rule_bf else None
                ))

        # ------------------------------------------------------------------
        # Rule 2: Unexpected Privileged Activity & Root Compromise
        # ------------------------------------------------------------------
        rule_priv = rules_by_type.get("privileged_activity")
        cmd_text = (event.command or "").lower()
        priv_keywords = ["cat /etc/shadow", "chmod +x", "chown", "authorized_keys", "visudo", "sudoers", "passwd", "useradd"]
        if any(kw in cmd_text for kw in priv_keywords):
            findings.append(DetectionFinding(
                rule_name="Privileged System Activity",
                title=f"Unauthorized Privileged Execution Attempt by {event.username or 'unknown'}",
                severity="critical" if "shadow" in cmd_text or "authorized_keys" in cmd_text else "high",
                confidence=0.95,
                explanation=f"Observed unauthorized command attempting privileged persistence or credential access: '{event.command}'.",
                evidence={
                    "src_ip": event.src_ip,
                    "command": event.command,
                    "username": event.username,
                    "session_id": event.session_id
                },
                mitre_tactics="Privilege Escalation / Persistence",
                mitre_techniques="T1098 Account Manipulation / T1003 OS Credential Dumping",
                recommended_actions=[
                    {
                        "action": "Isolate Affected Host Session",
                        "reason": "Adversary attempted unauthorized privilege escalation",
                        "priority": "CRITICAL",
                        "confidence": 0.95
                    },
                    {
                        "action": "Inspect SSH Authorized Keys",
                        "reason": "Prevent backdoored SSH key persistence",
                        "priority": "HIGH",
                        "confidence": 0.92
                    }
                ],
                rule_id=rule_priv.id if rule_priv else None
            ))

        # ------------------------------------------------------------------
        # Rule 3: Malicious Ingress Payload Download
        # ------------------------------------------------------------------
        rule_dl = rules_by_type.get("payload_download")
        if event.event_id == "cowrie.session.file_download" or any(k in cmd_text for k in ["wget ", "curl -", "curl http", "tftp "]):
            findings.append(DetectionFinding(
                rule_name="Suspicious Ingress Binary Download",
                title=f"Malicious Stager Download Detected from {event.src_ip}",
                severity="critical",
                confidence=0.94,
                explanation=f"Session executed external downloader command: '{event.command or event.file_hash}'.",
                evidence={
                    "src_ip": event.src_ip,
                    "command": event.command,
                    "file_hash": event.file_hash,
                    "session_id": event.session_id
                },
                mitre_tactics="Command and Control / Execution",
                mitre_techniques="T1105 Ingress Tool Transfer",
                recommended_actions=[
                    {
                        "action": "Submit File Hash to Threat Intelligence Sandbox",
                        "reason": "Analyze binary payload behavior and static indicators",
                        "priority": "HIGH",
                        "confidence": 0.95
                    },
                    {
                        "action": "Block External Stager Destination Domain/IP",
                        "reason": "Sever outbound C2 download connectivity",
                        "priority": "HIGH",
                        "confidence": 0.90
                    }
                ],
                rule_id=rule_dl.id if rule_dl else None
            ))

        # ------------------------------------------------------------------
        # Rule 4: Known Threat Intel IOC Match
        # ------------------------------------------------------------------
        rule_ioc = rules_by_type.get("ioc_match")
        ioc_match = db.query(ThreatIntelIOC).filter(
            ThreatIntelIOC.indicator.in_([event.src_ip, event.file_hash or ""])
        ).first()
        if ioc_match and ioc_match.threat_score >= 60:
            findings.append(DetectionFinding(
                rule_name="Known Malicious IOC Match",
                title=f"Activity from Known Malicious Indicator: {ioc_match.indicator}",
                severity="high" if ioc_match.threat_score < 85 else "critical",
                confidence=ioc_match.confidence or 0.90,
                explanation=(
                    f"Traffic originated from indicator '{ioc_match.indicator}' catalogued in Threat Intelligence. "
                    f"Category: {ioc_match.category}. Reputation score: {ioc_match.threat_score}/100."
                ),
                evidence={
                    "indicator": ioc_match.indicator,
                    "ioc_type": ioc_match.ioc_type,
                    "threat_score": ioc_match.threat_score,
                    "category": ioc_match.category,
                    "source": ioc_match.source
                },
                mitre_tactics="Initial Access",
                mitre_techniques="T1190 Exploit Public-Facing Application",
                recommended_actions=[
                    {
                        "action": "Add Indicator to Active Perimeter Watchlist",
                        "reason": f"Corroborated by {ioc_match.source}",
                        "priority": "HIGH",
                        "confidence": ioc_match.confidence or 0.90
                    }
                ],
                rule_id=rule_ioc.id if rule_ioc else None
            ))

        # ------------------------------------------------------------------
        # Rule 5: Interactive Shell Spawn / Command Execution
        # ------------------------------------------------------------------
        if any(k in cmd_text for k in ["/dev/tcp/", "mkfifo", "nc -e", "sh -i", "bash -i", "/bin/sh"]):
            findings.append(DetectionFinding(
                rule_name="Reverse Shell Execution Vector",
                title=f"Interactive Reverse Shell Payload Detected from {event.src_ip}",
                severity="critical",
                confidence=0.98,
                explanation=f"Command matched known interactive reverse shell socket pattern: '{event.command}'.",
                evidence={"src_ip": event.src_ip, "command": event.command, "session_id": event.session_id},
                mitre_tactics="Execution",
                mitre_techniques="T1059.004 Unix Shell",
                recommended_actions=[
                    {
                        "action": "Terminate Associated Process Tree and Network Socket",
                        "reason": "Active interactive reverse shell identified",
                        "priority": "CRITICAL",
                        "confidence": 0.98
                    }
                ]
            ))

        # ------------------------------------------------------------------
        # Rule 6: Machine Learning Statistical Anomaly Flag
        # ------------------------------------------------------------------
        if ml_prediction and ml_prediction.get("is_anomalous"):
            findings.append(DetectionFinding(
                rule_name="ML Statistical Telemetry Anomaly",
                title=f"Behavioral Anomaly Flagged by Isolation Forest ({event.src_ip})",
                severity="medium" if ml_prediction.get("predicted_severity") == "low" else "high",
                confidence=0.75,
                explanation=(
                    f"Unsupervised Isolation Forest identified atypical behavioral pattern "
                    f"(anomaly score: {ml_prediction.get('anomaly_score')}). "
                    f"Note: Anomaly alone does not confirm attack; correlates with rule observations."
                ),
                evidence={
                    "anomaly_score": ml_prediction.get("anomaly_score"),
                    "predicted_severity": ml_prediction.get("predicted_severity"),
                    "class_probabilities": ml_prediction.get("class_probabilities")
                },
                mitre_tactics="Defense Evasion",
                mitre_techniques="T1036 Masquerading",
                recommended_actions=[
                    {
                        "action": "Perform Deep Log Forensics on Session",
                        "reason": "Statistical anomaly detected in session parameters",
                        "priority": "LOW",
                        "confidence": 0.70
                    }
                ]
            ))

        return findings

detection_engine = DetectionEngine()
