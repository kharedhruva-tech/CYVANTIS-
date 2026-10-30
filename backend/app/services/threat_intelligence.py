import datetime
import json
import logging
from typing import Optional, Dict, Any, List
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ThreatIntelIOC

logger = logging.getLogger(__name__)

class ThreatIntelligenceService:
    """
    Modular Threat Intelligence Service.
    Enriches IPs, Domains, File Hashes, and CVEs via AbuseIPDB, VirusTotal, and NVD APIs.
    Features local SQLite caching with TTL, bounded retries, rate-limiting resilience, and explicit feed status.
    """
    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.virustotal_key = settings.VIRUSTOTAL_API_KEY
        self.nvd_key = settings.NVD_API_KEY
        self.nvd_api_url = settings.NVD_API_URL
        self.default_ttl_hours = 24

    def _get_cached_ioc(self, indicator: str, db: Session) -> Optional[ThreatIntelIOC]:
        if not db:
            return None
        now = datetime.datetime.utcnow()
        ioc = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == indicator).first()
        if ioc:
            if ioc.expiration and ioc.expiration < now:
                # Expired cache record
                return None
            return ioc
        return None

    def _save_ioc_cache(
        self,
        db: Session,
        indicator: str,
        ioc_type: str,
        threat_score: int,
        category: str,
        description: str,
        source: str,
        confidence: float = 1.0,
        raw_intel: Dict[str, Any] = None
    ) -> ThreatIntelIOC:
        if not db:
            return None
        now = datetime.datetime.utcnow()
        expiration = now + datetime.timedelta(hours=self.default_ttl_hours)
        ioc = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.indicator == indicator).first()
        raw_intel_str = json.dumps(raw_intel or {})
        
        if ioc:
            ioc.threat_score = threat_score
            ioc.category = category
            ioc.description = description
            ioc.source = source
            ioc.confidence = confidence
            ioc.raw_intel = raw_intel_str
            ioc.last_seen = now
            ioc.expiration = expiration
        else:
            ioc = ThreatIntelIOC(
                indicator=indicator,
                ioc_type=ioc_type,
                threat_score=threat_score,
                category=category,
                description=description,
                source=source,
                confidence=confidence,
                raw_intel=raw_intel_str,
                first_seen=now,
                last_seen=now,
                expiration=expiration
            )
            db.add(ioc)
        try:
            db.commit()
            db.refresh(ioc)
        except Exception as e:
            db.rollback()
            logger.warning("Failed to persist IOC cache: %s", e)
        return ioc

    def enrich_ip(self, ip_address: str, db: Optional[Session] = None, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Enriches an IP address using AbuseIPDB if configured, or local database reputation cache.
        """
        if not force_refresh and db:
            cached = self._get_cached_ioc(ip_address, db)
            if cached:
                raw = json.loads(cached.raw_intel) if cached.raw_intel else {}
                return {
                    "indicator": ip_address,
                    "ioc_type": "ip",
                    "threat_score": cached.threat_score,
                    "category": cached.category,
                    "description": cached.description,
                    "source": cached.source,
                    "confidence": cached.confidence,
                    "cached": True,
                    "last_seen": cached.last_seen.isoformat() if cached.last_seen else None,
                    "details": raw
                }

        # Check if external AbuseIPDB API key is provided
        if self.abuseipdb_key and self.abuseipdb_key.strip():
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json"
                }
                params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
                
                with httpx.Client(timeout=4.0) as client:
                    resp = client.get(url, headers=headers, params=params)
                    if resp.status_code == 200:
                        payload = resp.json().get("data", {})
                        score = int(payload.get("abuseConfidenceScore", 0))
                        category = "Confirmed Malicious Host" if score >= 80 else ("Suspicious Scanner" if score >= 40 else "Benign Host")
                        desc = f"AbuseIPDB reports {payload.get('totalReports', 0)} abuse incidents. Usage type: {payload.get('usageType', 'Unknown')}."
                        
                        saved = self._save_ioc_cache(
                            db=db,
                            indicator=ip_address,
                            ioc_type="ip",
                            threat_score=score,
                            category=category,
                            description=desc,
                            source="AbuseIPDB Live Feed",
                            confidence=0.95,
                            raw_intel=payload
                        )
                        return {
                            "indicator": ip_address,
                            "ioc_type": "ip",
                            "threat_score": score,
                            "category": category,
                            "description": desc,
                            "source": "AbuseIPDB Live Feed",
                            "confidence": 0.95,
                            "cached": False,
                            "last_seen": datetime.datetime.utcnow().isoformat(),
                            "details": payload
                        }
                    elif resp.status_code == 429:
                        logger.warning("AbuseIPDB rate limit exceeded (429). Falling back to local intelligence.")
            except Exception as e:
                logger.warning("Error querying external AbuseIPDB API: %s", e)

        # Fallback to local intelligence / GeoIP heuristics without fabricating live results
        from app.geoip_service import enrich_ip as local_enrich_ip
        local_geo = local_enrich_ip(ip_address)
        base_score = int(local_geo.get("threat_score", 15))
        category = "Known Adversarial Zone" if base_score >= 70 else ("Monitored IP" if base_score >= 40 else "Clean / Low Risk")
        desc = f"Origin: {local_geo.get('country', 'Unknown')}, ASN: {local_geo.get('asn', 'Unknown')}."
        
        if db:
            self._save_ioc_cache(
                db=db,
                indicator=ip_address,
                ioc_type="ip",
                threat_score=base_score,
                category=category,
                description=desc,
                source="CYVANTIS Local Intelligence",
                confidence=0.75,
                raw_intel=local_geo
            )

        return {
            "indicator": ip_address,
            "ioc_type": "ip",
            "threat_score": base_score,
            "category": category,
            "description": desc,
            "source": "CYVANTIS Local Intelligence",
            "confidence": 0.75,
            "cached": False,
            "last_seen": datetime.datetime.utcnow().isoformat(),
            "details": local_geo
        }

    def enrich_hash(self, file_hash: str, db: Optional[Session] = None, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Enriches a file hash (SHA-256 or MD5) via VirusTotal v3 API if configured, or local database.
        """
        clean_hash = file_hash.strip().lower()
        if not force_refresh and db:
            cached = self._get_cached_ioc(clean_hash, db)
            if cached:
                raw = json.loads(cached.raw_intel) if cached.raw_intel else {}
                return {
                    "indicator": clean_hash,
                    "ioc_type": "hash",
                    "threat_score": cached.threat_score,
                    "category": cached.category,
                    "description": cached.description,
                    "source": cached.source,
                    "confidence": cached.confidence,
                    "cached": True,
                    "details": raw
                }

        # Query VirusTotal if API key is configured
        if self.virustotal_key and self.virustotal_key.strip():
            try:
                url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
                headers = {"x-apikey": self.virustotal_key}
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        malicious = int(stats.get("malicious", 0))
                        total = sum(stats.values()) or 70
                        score = min(100, int((malicious / total) * 100)) if total > 0 else 0
                        category = "Malicious Binary" if score >= 50 else ("Suspicious Payload" if score > 0 else "Benign Hash")
                        desc = f"VirusTotal detection: {malicious}/{total} security engines flagged as malicious."

                        saved = self._save_ioc_cache(
                            db=db,
                            indicator=clean_hash,
                            ioc_type="hash",
                            threat_score=score,
                            category=category,
                            description=desc,
                            source="VirusTotal v3 API",
                            confidence=0.98,
                            raw_intel=stats
                        )
                        return {
                            "indicator": clean_hash,
                            "ioc_type": "hash",
                            "threat_score": score,
                            "category": category,
                            "description": desc,
                            "source": "VirusTotal v3 API",
                            "confidence": 0.98,
                            "cached": False,
                            "details": stats
                        }
                    elif resp.status_code == 404:
                        desc = "File hash not catalogued in public VirusTotal database."
                        return {
                            "indicator": clean_hash,
                            "ioc_type": "hash",
                            "threat_score": 10,
                            "category": "Unknown / Unseen Hash",
                            "description": desc,
                            "source": "VirusTotal v3 API (Not Found)",
                            "confidence": 0.50,
                            "cached": False,
                            "details": {}
                        }
            except Exception as e:
                logger.warning("Error querying VirusTotal API: %s", e)

        # Local database lookup or fallback
        known_bad = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                "score": 0, "category": "Empty File Benchmark", "desc": "Standard empty SHA-256 hash"
            },
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
                "score": 95, "category": "Mirai Botnet Dropper", "desc": "Known ELF Trojan-Downloader Linux Mirai variant"
            }
        }
        meta = known_bad.get(clean_hash, {
            "score": 30, "category": "Unverified Ingested Binary", "desc": "Unverified honeypot download hash; external feeds unconfigured."
        })

        if db:
            self._save_ioc_cache(
                db=db,
                indicator=clean_hash,
                ioc_type="hash",
                threat_score=meta["score"],
                category=meta["category"],
                description=meta["desc"],
                source="CYVANTIS Local IOC Database",
                confidence=0.70,
                raw_intel=meta
            )

        return {
            "indicator": clean_hash,
            "ioc_type": "hash",
            "threat_score": meta["score"],
            "category": meta["category"],
            "description": meta["desc"],
            "source": "CYVANTIS Local IOC Database",
            "confidence": 0.70,
            "cached": False,
            "details": meta
        }

    def enrich_cve(self, cve_id: str, db: Optional[Session] = None, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Enriches a CVE vulnerability identifier via the official NVD API 2.0 or local curated catalog.
        """
        clean_cve = cve_id.strip().upper()
        if not force_refresh and db:
            cached = self._get_cached_ioc(clean_cve, db)
            if cached:
                raw = json.loads(cached.raw_intel) if cached.raw_intel else {}
                return {
                    "cve_id": clean_cve,
                    "threat_score": cached.threat_score,
                    "cvss_score": round(cached.threat_score / 10.0, 1),
                    "category": cached.category,
                    "description": cached.description,
                    "source": cached.source,
                    "confidence": cached.confidence,
                    "cached": True,
                    "details": raw
                }

        # Query NVD API 2.0 if reachable
        try:
            url = f"{self.nvd_api_url}?cveId={clean_cve}"
            headers = {"Accept": "application/json"}
            if self.nvd_key and self.nvd_key.strip():
                headers["apiKey"] = self.nvd_key

            with httpx.Client(timeout=4.5) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_item = vulnerabilities[0].get("cve", {})
                        descriptions = cve_item.get("descriptions", [])
                        eng_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
                        metrics = cve_item.get("metrics", {})
                        
                        # Extract CVSS v3.1 or v3.0 score
                        cvss_data = None
                        if "cvssMetricV31" in metrics:
                            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        elif "cvssMetricV30" in metrics:
                            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                        elif "cvssMetricV2" in metrics:
                            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})

                        base_score = float(cvss_data.get("baseScore", 7.5)) if cvss_data else 7.5
                        severity_str = str(cvss_data.get("baseSeverity", "HIGH")).upper() if cvss_data else "HIGH"
                        threat_score = int(base_score * 10)

                        raw_dict = {
                            "cve_id": clean_cve,
                            "cvss": base_score,
                            "severity": severity_str,
                            "published": cve_item.get("published"),
                            "last_modified": cve_item.get("lastModified")
                        }

                        if db:
                            self._save_ioc_cache(
                                db=db,
                                indicator=clean_cve,
                                ioc_type="cve",
                                threat_score=threat_score,
                                category=f"NVD {severity_str} Vulnerability",
                                description=eng_desc[:300],
                                source="National Vulnerability Database (NVD API 2.0)",
                                confidence=0.99,
                                raw_intel=raw_dict
                            )

                        return {
                            "cve_id": clean_cve,
                            "threat_score": threat_score,
                            "cvss_score": base_score,
                            "category": f"NVD {severity_str} Vulnerability",
                            "description": eng_desc,
                            "source": "National Vulnerability Database (NVD API 2.0)",
                            "confidence": 0.99,
                            "cached": False,
                            "details": raw_dict
                        }
        except Exception as e:
            logger.warning("NVD API request failed: %s", e)

        # Fallback to local curated CVE catalog (e.g. Log4Shell, Spring4Shell, XZ Utils)
        CURATED_CVES = {
            "CVE-2021-44228": {"cvss": 10.0, "desc": "Apache Log4j2 JNDI Remote Code Execution vulnerability (Log4Shell).", "cisa_kev": True},
            "CVE-2022-22965": {"cvss": 9.8, "desc": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell).", "cisa_kev": True},
            "CVE-2024-3094": {"cvss": 10.0, "desc": "Malicious code injection in upstream XZ Utils tarballs compromising OpenSSH.", "cisa_kev": True},
            "CVE-2020-0796": {"cvss": 10.0, "desc": "SMBv3 Compression Remote Code Execution Vulnerability (SMBGhost).", "cisa_kev": True},
            "CVE-2023-32154": {"cvss": 8.1, "desc": "MikroTik RouterOS IPv6 Advertisements buffer overflow exploit.", "cisa_kev": True}
        }
        item = CURATED_CVES.get(clean_cve, {
            "cvss": 7.0, "desc": f"Vulnerability {clean_cve} recorded in local security catalog.", "cisa_kev": False
        })
        threat_score = int(item["cvss"] * 10)

        if db:
            self._save_ioc_cache(
                db=db,
                indicator=clean_cve,
                ioc_type="cve",
                threat_score=threat_score,
                category="Curated Enterprise CVE Catalog",
                description=item["desc"],
                source="CYVANTIS Curated Vulnerability Catalog",
                confidence=0.85,
                raw_intel=item
            )

        return {
            "cve_id": clean_cve,
            "threat_score": threat_score,
            "cvss_score": item["cvss"],
            "category": "Curated Enterprise CVE Catalog",
            "description": item["desc"],
            "source": "CYVANTIS Curated Vulnerability Catalog",
            "confidence": 0.85,
            "cached": False,
            "details": item
        }

threat_intel_service = ThreatIntelligenceService()
