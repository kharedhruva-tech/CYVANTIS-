from typing import Dict, Any, List, Optional
import math

class RiskScoringService:
    """
    Consistent, mathematically bounded, explainable risk prioritization engine.
    Computes inherent and residual risk scores across 5 weighted dimensions:
      1. Detection Severity (Weight: 0.30)
      2. Threat Intelligence Reputation (Weight: 0.25)
      3. Incident Scope & Frequency (Weight: 0.15)
      4. Machine Learning Behavioral Anomaly (Weight: 0.15)
      5. Target Asset Criticality (Weight: 0.15)
    Total Weight = 1.00
    """
    WEIGHT_SEVERITY = 0.30
    WEIGHT_INTEL = 0.25
    WEIGHT_SCOPE = 0.15
    WEIGHT_ANOMALY = 0.15
    WEIGHT_ASSET = 0.15

    SEVERITY_MAP = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 45.0,
        "low": 20.0
    }

    ASSET_TIER_MAP = {
        "Critical Gateway": 95.0,
        "Payment Gateway": 100.0,
        "Authentication Server": 90.0,
        "Core Application": 70.0,
        "Internal Telemetry": 40.0,
        "Demo Sensor": 25.0
    }

    def calculate_risk(
        self,
        severity: str,
        threat_intel_score: Optional[float] = None,
        event_count: int = 1,
        is_anomalous: bool = False,
        anomaly_score: float = 0.0,
        asset_tier: str = "Critical Gateway",
        confidence: float = 0.90
    ) -> Dict[str, Any]:
        """
        Calculates explainable risk score and returns a transparent breakdown of contributing factors.
        """
        # 1. Detection Severity Factor
        sev_clean = (severity or "medium").lower()
        s_sev = self.SEVERITY_MAP.get(sev_clean, 45.0)

        # 2. Threat Intel Reputation Factor
        if threat_intel_score is not None:
            s_intel = max(0.0, min(100.0, float(threat_intel_score)))
            intel_rationale = f"Enriched IOC reputation score ({s_intel:.0f}/100)"
        else:
            s_intel = 20.0
            intel_rationale = "No external threat reputation available (unverified indicator baseline)"

        # 3. Incident Scope & Event Velocity Factor
        # Sublinear scaling for repeated attempts: min(100, 20 + 15 * log2(event_count))
        if event_count <= 1:
            s_scope = 25.0
            scope_rationale = "Single isolated attack event"
        else:
            s_scope = min(100.0, 25.0 + 15.0 * math.log2(event_count))
            scope_rationale = f"Repeated campaign with {event_count} correlated events"

        # 4. Behavioral Anomaly Factor
        if is_anomalous:
            # Isolation forest anomaly score (typically between -0.5 and 0.0) mapped to 60-100
            s_anom = min(100.0, max(60.0, 75.0 + abs(anomaly_score) * 50.0))
            anom_rationale = f"Isolation Forest flagged statistical anomaly (score {anomaly_score:.3f})"
        else:
            s_anom = 15.0
            anom_rationale = "Telemetry conforms to established behavioral baseline"

        # 5. Asset Criticality Factor
        s_asset = self.ASSET_TIER_MAP.get(asset_tier, 70.0)
        asset_rationale = f"Target asset classification: '{asset_tier}'"

        # Compute Inherent Risk Score (Weighted Sum)
        contrib_sev = self.WEIGHT_SEVERITY * s_sev
        contrib_intel = self.WEIGHT_INTEL * s_intel
        contrib_scope = self.WEIGHT_SCOPE * s_scope
        contrib_anom = self.WEIGHT_ANOMALY * s_anom
        contrib_asset = self.WEIGHT_ASSET * s_asset

        inherent_risk = round(contrib_sev + contrib_intel + contrib_scope + contrib_anom + contrib_asset, 1)
        inherent_risk = max(0.0, min(100.0, inherent_risk))

        # Residual Risk factored by confidence
        conf_factor = max(0.5, min(1.0, float(confidence)))
        residual_risk = round(inherent_risk * conf_factor, 1)

        # Priority classification
        if inherent_risk >= 80.0:
            priority = "CRITICAL"
        elif inherent_risk >= 60.0:
            priority = "HIGH"
        elif inherent_risk >= 35.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        factors = [
            {
                "factor": "Detection Severity",
                "weight": self.WEIGHT_SEVERITY,
                "raw_value": s_sev,
                "contribution": round(contrib_sev, 1),
                "rationale": f"Base severity level '{sev_clean.upper()}'"
            },
            {
                "factor": "Threat Intelligence",
                "weight": self.WEIGHT_INTEL,
                "raw_value": s_intel,
                "contribution": round(contrib_intel, 1),
                "rationale": intel_rationale
            },
            {
                "factor": "Incident Scope & Frequency",
                "weight": self.WEIGHT_SCOPE,
                "raw_value": round(s_scope, 1),
                "contribution": round(contrib_scope, 1),
                "rationale": scope_rationale
            },
            {
                "factor": "Machine Learning Anomaly",
                "weight": self.WEIGHT_ANOMALY,
                "raw_value": round(s_anom, 1),
                "contribution": round(contrib_anom, 1),
                "rationale": anom_rationale
            },
            {
                "factor": "Asset Criticality",
                "weight": self.WEIGHT_ASSET,
                "raw_value": s_asset,
                "contribution": round(contrib_asset, 1),
                "rationale": asset_rationale
            }
        ]

        summary = (
            f"Evaluated risk score of {inherent_risk}/100 ({priority}). "
            f"Primary driver: {factors[0]['factor']} ({contrib_sev:.1f} pts) and "
            f"{factors[1]['factor']} ({contrib_intel:.1f} pts). "
            f"Data confidence: {int(conf_factor * 100)}%."
        )

        return {
            "risk_score": inherent_risk,
            "residual_risk": residual_risk,
            "priority": priority,
            "confidence": conf_factor,
            "summary": summary,
            "factors": factors
        }

risk_scoring_service = RiskScoringService()
