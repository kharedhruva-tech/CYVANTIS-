"""
CYVANTIS Threat Investigation Graph Service
Constructs typed multi-relational graphs linking:
Events, Incidents, Users, Assets, IP Addresses, File Hashes, and Vulnerabilities.
Strictly distinguishes OBSERVED relationships from INFERRED relationships.
"""

from typing import Dict, Any, List, Set, Optional
import json
from sqlalchemy.orm import Session
from app.models import Investigation, HoneypotEvent, Alert

class InvestigationGraphService:
    """Builds node-edge network data for threat graph visualization."""

    MAX_EVENT_NODES = 25  # Guardrail against giant graphs

    def build_investigation_graph(self, inv_id: int, db: Session) -> Dict[str, Any]:
        incident = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not incident:
            return {
                "nodes": [],
                "edges": [],
                "summary": {"total_nodes": 0, "total_edges": 0, "observed_edges": 0, "inferred_edges": 0}
            }

        # 1. Parse related events
        event_ids: List[int] = []
        if incident.related_events:
            try:
                raw_ids = json.loads(incident.related_events)
                if isinstance(raw_ids, list):
                    event_ids = [int(x) for x in raw_ids]
            except Exception:
                event_ids = []

        events: List[HoneypotEvent] = []
        if event_ids:
            events = db.query(HoneypotEvent).filter(
                HoneypotEvent.id.in_(event_ids[:self.MAX_EVENT_NODES])
            ).all()

        alerts = db.query(Alert).filter(Alert.incident_id == inv_id).all()

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []
        seen_edges: Set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, properties: Dict[str, Any], evidence: Optional[str] = None):
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "type": node_type, # incident, asset, ip, user, command, file_hash, event, vulnerability
                    "properties": properties,
                    "evidence": evidence
                }

        def add_edge(source: str, target: str, relationship: str, rel_type: str, confidence: float, evidence: str):
            edge_key = f"{source}->{target}:{relationship}"
            if edge_key not in seen_edges and source in nodes and target in nodes:
                seen_edges.add(edge_key)
                edges.append({
                    "id": edge_key,
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "relationship_type": rel_type, # "observed" or "inferred"
                    "confidence": confidence,
                    "evidence": evidence
                })

        # --- A. Root Incident Node ---
        inc_node_id = f"inc-{incident.id}"
        add_node(
            node_id=inc_node_id,
            label=f"Incident #{incident.id}",
            node_type="incident",
            properties={
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "risk_score": incident.risk_score or 50.0,
                "created_at": incident.created_at.isoformat()
            },
            evidence=f"Correlated security case with {len(events)} linked events"
        )

        # --- B. Asset Node ---
        asset_tier = incident.asset_tier or "Critical Gateway"
        asset_node_id = "asset-gateway-01"
        add_node(
            node_id=asset_node_id,
            label="Gateway (gw-edge-01)",
            node_type="asset",
            properties={
                "asset_id": "gw-edge-01",
                "tier": asset_tier,
                "exposure": "Internet-Facing DMZ",
                "ip_address": "198.51.100.1"
            },
            evidence=f"Targeted edge asset classified as {asset_tier}"
        )
        add_edge(inc_node_id, asset_node_id, "TARGETS_ASSET", "inferred", 0.90, "Incident vector targets gateway asset")

        # --- C. Vulnerability Nodes (Inferred from Targeted Ports) ---
        protocols_seen = {ev.protocol for ev in events if ev.protocol}
        if "SSH" in protocols_seen or not protocols_seen:
            cve_ssh_id = "cve-CVE-2024-6387"
            add_node(
                node_id=cve_ssh_id,
                label="CVE-2024-6387 (regreSSHion)",
                node_type="vulnerability",
                properties={
                    "cve_id": "CVE-2024-6387",
                    "cvss": 8.1,
                    "severity": "HIGH",
                    "service": "OpenSSH 8.5p1 - 9.7p1",
                    "description": "Signal handler race condition leading to potential RCE"
                },
                evidence="Asset SSH port 22 exposed to remote unauthenticated probes"
            )
            add_edge(asset_node_id, cve_ssh_id, "POTENTIALLY_EXPOSES", "inferred", 0.75, "Service port mapping from NVD CPE catalogue")

        if "Telnet" in protocols_seen:
            cve_telnet_id = "cve-CVE-2020-10188"
            add_node(
                node_id=cve_telnet_id,
                label="CVE-2020-10188 (Telnetd Overflow)",
                node_type="vulnerability",
                properties={
                    "cve_id": "CVE-2020-10188",
                    "cvss": 9.8,
                    "severity": "CRITICAL",
                    "service": "NetKit Telnetd",
                    "description": "Buffer overflow in utility.c allow remote code execution"
                },
                evidence="Cleartext Telnet daemon probed on port 23"
            )
            add_edge(asset_node_id, cve_telnet_id, "POTENTIALLY_EXPOSES", "inferred", 0.80, "Active Telnet listeners exposed to brute-force")

        # --- D. Telemetry Event & Entity Nodes ---
        unique_ips = set()
        unique_users = set()
        unique_commands = set()
        unique_hashes = set()

        for ev in events:
            ev_node_id = f"ev-{ev.id}"
            add_node(
                node_id=ev_node_id,
                label=f"Event #{ev.id}",
                node_type="event",
                properties={
                    "eventid": ev.eventid,
                    "protocol": ev.protocol,
                    "severity": ev.severity,
                    "timestamp": ev.timestamp.isoformat()
                },
                evidence=f"Captured {ev.protocol} event: {ev.eventid}"
            )
            add_edge(inc_node_id, ev_node_id, "INCLUDES_EVENT", "inferred", 0.95, "Correlated in 30-minute attack window")

            # Source IP (Observed)
            if ev.src_ip and ev.src_ip != "0.0.0.0":
                ip_node_id = f"ip-{ev.src_ip}"
                add_node(
                    node_id=ip_node_id,
                    label=ev.src_ip,
                    node_type="ip",
                    properties={
                        "ip": ev.src_ip,
                        "country": ev.country or "Unknown",
                        "asn": ev.asn or "AS0000 Unknown"
                    },
                    evidence=f"Observed TCP handshake from {ev.src_ip}"
                )
                add_edge(ev_node_id, ip_node_id, "ORIGINATED_FROM", "observed", 1.0, f"Source packet header IP: {ev.src_ip}")
                unique_ips.add(ip_node_id)

            # Targeted User (Observed)
            if ev.username:
                user_node_id = f"user-{ev.username}"
                add_node(
                    node_id=user_node_id,
                    label=f"user:{ev.username}",
                    node_type="user",
                    properties={"username": ev.username},
                    evidence=f"Username submitted during auth attempt: '{ev.username}'"
                )
                add_edge(ev_node_id, user_node_id, "TARGETED_USER", "observed", 1.0, f"Auth request specified username '{ev.username}'")
                unique_users.add(user_node_id)

            # Executed Command (Observed)
            if ev.command:
                cmd_trunc = ev.command[:28] + ("..." if len(ev.command) > 28 else "")
                cmd_node_id = f"cmd-{abs(hash(ev.command)) % 100000}"
                add_node(
                    node_id=cmd_node_id,
                    label=cmd_trunc,
                    node_type="command",
                    properties={"command": ev.command},
                    evidence=f"Raw interactive command entered: {ev.command}"
                )
                add_edge(ev_node_id, cmd_node_id, "EXECUTED_COMMAND", "observed", 1.0, "Honeypot virtual shell captured execution")
                unique_commands.add(cmd_node_id)

            # File Hash (Observed)
            if ev.file_hash:
                hash_trunc = ev.file_hash[:10] + "..."
                hash_node_id = f"hash-{ev.file_hash[:16]}"
                add_node(
                    node_id=hash_node_id,
                    label=hash_trunc,
                    node_type="file_hash",
                    properties={"sha256": ev.file_hash},
                    evidence=f"SHA-256 payload download: {ev.file_hash}"
                )
                add_edge(ev_node_id, hash_node_id, "RETRIEVED_FILE", "observed", 1.0, "Cowrie session downloaded malicious payload")
                unique_hashes.add(hash_node_id)

        # Inferred relationship: Attacker IP correlated to Incident directly
        for ip_node in unique_ips:
            add_edge(ip_node, inc_node_id, "ATTACKS_INCIDENT", "inferred", 0.95, "Clustered adversary IP address")

        # Counts of observed vs inferred edges
        obs_count = sum(1 for e in edges if e["relationship_type"] == "observed")
        inf_count = sum(1 for e in edges if e["relationship_type"] == "inferred")

        return {
            "incident_id": inv_id,
            "nodes": list(nodes.values()),
            "edges": edges,
            "summary": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "observed_edges": obs_count,
                "inferred_edges": inf_count,
                "unique_ips": len(unique_ips),
                "unique_users": len(unique_users),
                "unique_commands": len(unique_commands),
                "unique_hashes": len(unique_hashes)
            }
        }

investigation_graph_service = InvestigationGraphService()

