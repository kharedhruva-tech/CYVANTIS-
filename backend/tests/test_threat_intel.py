import pytest
from app.services.threat_intelligence import ThreatIntelligenceService
from conftest import TestingSessionLocal

def test_threat_intel_ip_enrichment():
    db = TestingSessionLocal()
    try:
        service = ThreatIntelligenceService()
        # Test IP lookup
        res = service.enrich_ip("185.220.101.5", db=db, force_refresh=True)
        assert res["indicator"] == "185.220.101.5"
        assert res["ioc_type"] == "ip"
        assert 0 <= res["threat_score"] <= 100
        assert "source" in res
        assert 0.0 <= res["confidence"] <= 1.0

        # Test caching
        cached_res = service.enrich_ip("185.220.101.5", db=db, force_refresh=False)
        assert cached_res["cached"] is True
    finally:
        db.close()

def test_threat_intel_hash_enrichment():
    db = TestingSessionLocal()
    try:
        service = ThreatIntelligenceService()
        known_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = service.enrich_hash(known_hash, db=db)
        assert res["indicator"] == known_hash
        assert res["ioc_type"] == "hash"
        assert res["threat_score"] == 99

        # Test uncatalogued hash
        unseen_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        unseen_res = service.enrich_hash(unseen_hash, db=db, force_refresh=True)
        assert unseen_res["threat_score"] == 30
    finally:
        db.close()

def test_threat_intel_cve_enrichment():
    db = TestingSessionLocal()
    try:
        service = ThreatIntelligenceService()
        res = service.enrich_cve("CVE-2021-44228", db=db)
        assert res["cve_id"] == "CVE-2021-44228"
        assert res["threat_score"] >= 90
        assert res["cvss_score"] == 10.0
        assert "Log4Shell" in res["description"] or "Log4j" in res["description"]
    finally:
        db.close()
