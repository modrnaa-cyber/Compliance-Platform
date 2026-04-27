# services/prioritization_service.py
from typing import List, Dict


class PrioritizationService:
    SEVERITY_BASE = {
        "Critical": 90,
        "High": 70,
        "Medium": 45,
        "Low": 20
    }

    CRITICALITY_MULTIPLIER = {
        "critical": 1.35,
        "high": 1.20,
        "medium": 1.00,
        "low": 0.85
    }

    def calculate_priority_score(self, finding: Dict, asset: Dict = None) -> float:
        severity = finding.get("risk_level", "Low")
        base = self.SEVERITY_BASE.get(severity, 20)

        cvss = float(finding.get("cvss", 0.0) or 0.0)
        cvss_bonus = min(cvss * 2.5, 25)

        internet_exposed = bool(finding.get("internet_exposed", False))
        exposure_bonus = 12 if internet_exposed else 0

        exploit_available = bool(finding.get("exploit_available", False))
        exploit_bonus = 15 if exploit_available else 0

        asset_criticality = (
            (asset or {}).get("criticality")
            or finding.get("asset_criticality")
            or "medium"
        ).lower()

        criticality_multiplier = self.CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)

        raw_score = (base + cvss_bonus + exposure_bonus + exploit_bonus) * criticality_multiplier
        return round(min(raw_score, 100), 2)

    def assign_priority_tier(self, priority_score: float) -> str:
        if priority_score >= 90:
            return "P1"
        if priority_score >= 75:
            return "P2"
        if priority_score >= 55:
            return "P3"
        return "P4"

    def enrich_findings(self, findings: List[Dict], asset: Dict = None) -> List[Dict]:
        enriched = []

        for finding in findings:
            finding_copy = dict(finding)
            score = self.calculate_priority_score(finding_copy, asset=asset)
            finding_copy["priority_score"] = score
            finding_copy["priority_tier"] = self.assign_priority_tier(score)
            enriched.append(finding_copy)

        enriched.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        return enriched