# services/remediation_service.py
from typing import List, Dict
from datetime import datetime, timedelta


class RemediationService:
    def suggest_owner(self, finding: Dict, asset: Dict = None) -> str:
        service = (finding.get("service") or "").lower()

        if service in ["http", "https"]:
            return "Web Team"
        if service in ["ssh", "rdp"]:
            return "Infrastructure Team"
        if service in ["dns", "smtp"]:
            return "Network Team"
        if service in ["smb", "netbios"]:
            return "Windows Platform Team"

        if asset and asset.get("owner"):
            return asset["owner"]

        return "Security Operations"

    def recommend_sla_days(self, finding: Dict, asset: Dict = None) -> int:
        priority = finding.get("priority_tier", "P4")
        internet_exposed = bool(finding.get("internet_exposed", False))
        criticality = ((asset or {}).get("criticality") or finding.get("asset_criticality") or "medium").lower()

        if priority == "P1":
            return 3 if internet_exposed or criticality == "critical" else 7
        if priority == "P2":
            return 15 if criticality in ["critical", "high"] else 30
        if priority == "P3":
            return 45
        return 90

    def recommendation_text(self, finding: Dict) -> str:
        service = (finding.get("service") or "").lower()
        title = (finding.get("title") or "").lower()

        if "version disclosure" in title:
            return "Reduce banner exposure, disable version leakage, and harden web server responses."
        if service == "ssh":
            return "Disable weak SSH algorithms, enforce strong ciphers, and restrict administrative access."
        if service in ["http", "https"]:
            return "Patch the affected web component, harden configuration, and validate external exposure."
        if service in ["smb", "netbios"]:
            return "Restrict file-sharing exposure, segment access, and disable legacy protocols where possible."
        if service == "rdp":
            return "Restrict remote access, enforce MFA/VPN controls, and limit exposure to trusted networks."

        return finding.get("remediation") or "Validate exposure, patch the affected service, and apply secure configuration controls."

    def enrich_findings(self, findings: List[Dict], asset: Dict = None) -> List[Dict]:
        enriched = []

        for finding in findings:
            finding_copy = dict(finding)
            sla_days = self.recommend_sla_days(finding_copy, asset=asset)
            due_date = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")

            finding_copy["owner"] = self.suggest_owner(finding_copy, asset=asset)
            finding_copy["sla_days"] = sla_days
            finding_copy["due_date"] = due_date
            finding_copy["remediation"] = self.recommendation_text(finding_copy)

            enriched.append(finding_copy)

        return enriched