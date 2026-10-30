"""
CYVANTIS Authoritative MITRE ATT&CK Mapping Service
Framework: MITRE ATT&CK Enterprise Matrix v15.1 (Released October 2024)
Maintained local knowledge base linking detection rules, honeypot events, and incidents to tactics & techniques.
"""

from typing import Dict, Any, List, Optional
import datetime
from sqlalchemy.orm import Session
from app.models import Alert, HoneypotEvent, Investigation

MITRE_VERSION = "v15.1"
MITRE_LAST_UPDATED = "2024-10-24"
MITRE_SOURCE = "MITRE ATT&CK Enterprise Matrix v15.1 (Authoritative Local Knowledge Base)"
MITRE_DISCLAIMER = (
    "MITRE ATT&CK mapping represents observed behavioral alignment with threat actor tactics and techniques, "
    "and does not alone constitute definitive forensic proof of a confirmed adversary attack."
)

# Authoritative Enterprise ATT&CK Techniques Knowledge Base
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1110.001": {
        "id": "T1110.001",
        "parent_id": "T1110",
        "name": "Brute Force: Password Guessing",
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "description": "Adversaries may systematically or randomly guess passwords to attempt authentication onto external services such as SSH or Telnet.",
        "rationale": "High frequency of repeated authentication failures against service daemon using common dictionaries.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "default_confidence": 0.92,
        "supported_rules": ["brute_force", "rapid_auth_failure"]
    },
    "T1059.004": {
        "id": "T1059.004",
        "parent_id": "T1059",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic_id": "TA0002",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shells (e.g., /bin/sh, /bin/bash) to execute arbitrary commands, scripts, or post-exploitation commands.",
        "rationale": "Execution of shell commands or multi-call binaries observed inside honeypot shell sessions.",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "default_confidence": 0.95,
        "supported_rules": ["command_execution", "shell_interaction"]
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing administrative or service accounts (e.g., root, admin) to gain initial access.",
        "rationale": "Successful authentication into honeypot gateway with standard administrative or system usernames.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "default_confidence": 0.88,
        "supported_rules": ["login_success", "privileged_activity"]
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic_id": "TA0011",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment using utilities like wget, curl, or ftp.",
        "rationale": "Observed execution of file retrieval utilities (wget, curl, tftp) or session payload downloads.",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "default_confidence": 0.94,
        "supported_rules": ["payload_download", "c2_dropper"]
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic_id": "TA0007",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable entrypoints.",
        "rationale": "Probing and connection attempts across honeypot perimeter listening ports (SSH 22, Telnet 23).",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "default_confidence": 0.85,
        "supported_rules": ["port_scan", "service_connect"]
    },
    "T1003.008": {
        "id": "T1003.008",
        "parent_id": "T1003",
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from Linux system authentication files (/etc/passwd, /etc/shadow).",
        "rationale": "Commands reading or targeting /etc/shadow or /etc/passwd detected in session.",
        "url": "https://attack.mitre.org/techniques/T1003/008/",
        "default_confidence": 0.96,
        "supported_rules": ["privileged_activity", "credential_dump"]
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic_id": "TA0003",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain access, such as appending public keys to ~/.ssh/authorized_keys or modifying user privileges.",
        "rationale": "Adversary attempted to modify authorized_keys or create persistent backdoors.",
        "url": "https://attack.mitre.org/techniques/T1098/",
        "default_confidence": 0.90,
        "supported_rules": ["privileged_activity", "persistence_backdoor"]
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic_id": "TA0005",
        "tactic": "Defense Evasion",
        "description": "Adversaries may manipulate process names, file locations, or metadata to mimic legitimate system components.",
        "rationale": "Hiding processes or executing hidden scripts from /tmp or /var/tmp.",
        "url": "https://attack.mitre.org/techniques/T1036/",
        "default_confidence": 0.82,
        "supported_rules": ["anomaly", "evasion"]
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing programs (e.g. OpenSSH, Web server, Telnet daemon).",
        "rationale": "Targeted exploit attempt or known CVE vulnerability probe detected.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "default_confidence": 0.89,
        "supported_rules": ["ioc_match", "exploit_probe"]
    }
}

TACTICS_METADATA = [
    {"id": "TA0001", "name": "Initial Access", "description": "Techniques used to gain initial foothold on target."},
    {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running."},
    {"id": "TA0003", "name": "Persistence", "description": "Techniques to maintain access across restarts or credential changes."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques to avoid detection by defensive tools."},
    {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials such as passwords and hashes."},
    {"id": "TA0007", "name": "Discovery", "description": "Techniques to observe the system and network environment."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques to extend access to other remote systems."},
    {"id": "TA0009", "name": "Collection", "description": "Techniques used to gather data of interest before exfiltration."},
    {"id": "TA0011", "name": "Command and Control", "description": "Techniques to communicate with systems under adversary control."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Techniques used to steal and package data from the target."},
    {"id": "TA0040", "name": "Impact", "description": "Techniques that disrupt availability or compromise integrity."}
]

class MitreAttackService:
    """Provides authoritative ATT&CK catalog metadata, dynamic mapping, and active matrix coverage."""

    def __init__(self):
        self.version = MITRE_VERSION
        self.last_updated = MITRE_LAST_UPDATED
        self.source = MITRE_SOURCE
        self.disclaimer = MITRE_DISCLAIMER

    def get_catalog_metadata(self) -> Dict[str, Any]:
        """Returns catalog version metadata, tactics list, and disclaimer."""
        return {
            "version": self.version,
            "last_updated": self.last_updated,
            "source": self.source,
            "disclaimer": self.disclaimer,
            "tactics_count": len(TACTICS_METADATA),
            "techniques_count": len(MITRE_TECHNIQUES),
            "tactics": TACTICS_METADATA,
            "techniques": list(MITRE_TECHNIQUES.values())
        }

    def get_technique_by_id(self, tech_id: str) -> Optional[Dict[str, Any]]:
        """Lookup authoritative technique details by ID (e.g. T1110.001 or T1105)."""
        clean_id = tech_id.strip().upper()
        if clean_id in MITRE_TECHNIQUES:
            item = dict(MITRE_TECHNIQUES[clean_id])
            item["version"] = self.version
            item["source"] = self.source
            item["disclaimer"] = self.disclaimer
            return item
        # Fallback to search by prefix if parent technique provided
        for tid, tdata in MITRE_TECHNIQUES.items():
            if tid.startswith(clean_id):
                item = dict(tdata)
                item["version"] = self.version
                item["source"] = self.source
                item["disclaimer"] = self.disclaimer
                return item
        return None

    def map_evidence_to_techniques(self, finding_title: str, rule_name: str, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Maps an alert or finding to one or more evidence-supported ATT&CK techniques."""
        matched: List[Dict[str, Any]] = []
        rule_lower = rule_name.lower()
        title_lower = finding_title.lower()

        # Rule-specific mappings
        if "brute_force" in rule_lower or "auth" in rule_lower:
            t = dict(MITRE_TECHNIQUES["T1110.001"])
            t["confidence"] = 0.95
            t["evidence_signals"] = [evidence.get("command") or f"Threshold exceeded on {evidence.get('src_ip')}"]
            matched.append(t)

        if "privileged" in rule_lower or "shadow" in title_lower or "passwd" in title_lower:
            t = dict(MITRE_TECHNIQUES["T1003.008"])
            t["confidence"] = 0.98
            t["evidence_signals"] = [evidence.get("command") or "Access to /etc/shadow or /etc/passwd"]
            matched.append(t)

        if "download" in rule_lower or "dropper" in title_lower or "wget" in title_lower or "curl" in title_lower:
            t = dict(MITRE_TECHNIQUES["T1105"])
            t["confidence"] = 0.96
            t["evidence_signals"] = [evidence.get("command") or evidence.get("file_hash") or "Ingress transfer command"]
            matched.append(t)

        if "command" in rule_lower or "shell" in title_lower:
            t = dict(MITRE_TECHNIQUES["T1059.004"])
            t["confidence"] = 0.92
            t["evidence_signals"] = [evidence.get("command") or "Interactive shell invocation"]
            matched.append(t)

        if "ioc" in rule_lower or "threat" in title_lower:
            t = dict(MITRE_TECHNIQUES["T1190"])
            t["confidence"] = 0.88
            t["evidence_signals"] = [f"Threat Intel match for {evidence.get('src_ip')}"]
            matched.append(t)

        # Fallback if no specific rule matched
        if not matched:
            t = dict(MITRE_TECHNIQUES["T1046"])
            t["confidence"] = 0.70
            t["evidence_signals"] = ["General network reconnaissance against gateway port"]
            matched.append(t)

        for m in matched:
            m["version"] = self.version
            m["source"] = self.source
            m["disclaimer"] = self.disclaimer

        return matched

    def get_live_matrix_coverage(self, db: Session) -> Dict[str, Any]:
        """Calculates live ATT&CK matrix coverage based on active database alerts and events."""
        alerts = db.query(Alert).all()
        
        # Aggregate by technique ID
        technique_counts: Dict[str, int] = {}
        tactic_counts: Dict[str, int] = {}

        for al in alerts:
            tech_str = al.mitre_techniques or ""
            tactic_str = al.mitre_tactics or ""
            
            # Extract technique ID token (e.g. T1110.001)
            for token in tech_str.replace(";", " ").replace("/", " ").split():
                if token.startswith("T") and len(token) >= 5:
                    technique_counts[token] = technique_counts.get(token, 0) + 1

            for tac in tactic_str.split("/"):
                tac_clean = tac.strip()
                if tac_clean:
                    tactic_counts[tac_clean] = tactic_counts.get(tac_clean, 0) + 1

        # Populate matrix cells
        matrix_tactics = []
        for tac in TACTICS_METADATA:
            mapped_techs = [
                t for t in MITRE_TECHNIQUES.values()
                if t["tactic_id"] == tac["id"] or t["tactic"].lower() == tac["name"].lower()
            ]
            tech_items = []
            for t in mapped_techs:
                cnt = technique_counts.get(t["id"], 0)
                tech_items.append({
                    "id": t["id"],
                    "name": t["name"],
                    "url": t["url"],
                    "active_alerts_count": cnt,
                    "confidence": t["default_confidence"]
                })

            matrix_tactics.append({
                "tactic_id": tac["id"],
                "tactic_name": tac["name"],
                "description": tac["description"],
                "active_alerts_count": tactic_counts.get(tac["name"], 0),
                "techniques": tech_items
            })

        return {
            "version": self.version,
            "last_updated": self.last_updated,
            "source": self.source,
            "disclaimer": self.disclaimer,
            "total_alerts_analyzed": len(alerts),
            "matrix": matrix_tactics
        }

mitre_attack_service = MitreAttackService()

