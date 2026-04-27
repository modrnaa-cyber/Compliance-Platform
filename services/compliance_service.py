# services/compliance_service.py
from typing import List, Dict


class ComplianceService:
    CONTROL_RULES = [
        {
            "match_services": ["ssh"],
            "match_keywords": ["weak", "cipher", "algorithm", "ssh"],
            "nca_control": "NCA-ECC-01 Access Control and Secure Administration",
            "deduction_override": 10
        },
        {
            "match_services": ["http", "https"],
            "match_keywords": ["version disclosure", "banner", "header", "http"],
            "nca_control": "NCA-ECC-02 Secure Configuration and Hardening",
            "deduction_override": 6
        },
        {
            "match_services": ["smb", "netbios"],
            "match_keywords": ["smb", "netbios", "file sharing"],
            "nca_control": "NCA-ECC-03 Network Segmentation and Service Exposure",
            "deduction_override": 12
        },
        {
            "match_services": ["rdp"],
            "match_keywords": ["rdp", "remote desktop"],
            "nca_control": "NCA-ECC-04 Remote Access Protection",
            "deduction_override": 14
        },
        {
            "match_services": ["dns"],
            "match_keywords": ["zone transfer", "dns"],
            "nca_control": "NCA-ECC-05 Infrastructure Service Protection",
            "deduction_override": 8
        }
    ]

    DEFAULT_CONTROLS = {
        "Critical": ("NCA-GEN-01 Critical Risk Governance Gap", 20),
        "High": ("NCA-GEN-02 High Risk Security Control Gap", 14),
        "Medium": ("NCA-GEN-03 Moderate Security Control Gap", 8),
        "Low": ("NCA-GEN-04 Low Risk Security Hygiene Gap", 4)
    }

    def map_finding_to_control(self, finding: Dict) -> Dict:
        text = " ".join([
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("service", ""))
        ]).lower()

        service = (finding.get("service") or "").lower()

        for rule in self.CONTROL_RULES:
            service_match = service in rule["match_services"]
            keyword_match = any(keyword in text for keyword in rule["match_keywords"])

            if service_match or keyword_match:
                return {
                    "nca_control": rule["nca_control"],
                    "deduction": float(rule["deduction_override"])
                }

        risk_level = finding.get("risk_level", "Low")
        fallback_control, fallback_deduction = self.DEFAULT_CONTROLS.get(risk_level, self.DEFAULT_CONTROLS["Low"])

        return {
            "nca_control": fallback_control,
            "deduction": float(fallback_deduction)
        }

    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        enriched = []

        for finding in findings:
            finding_copy = dict(finding)
            mapping = self.map_finding_to_control(finding_copy)

            finding_copy["nca_control"] = mapping["nca_control"]
            finding_copy["deduction"] = max(float(finding_copy.get("deduction", 0.0)), mapping["deduction"])

            enriched.append(finding_copy)

        return enriched

    def build_compliance_summary(self, findings: List[Dict]) -> Dict:
        total_deduction = round(sum(float(f.get("deduction", 0.0)) for f in findings), 2)
        final_score = max(round(100 - total_deduction, 2), 0)

        severity_summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        control_summary = {}

        for finding in findings:
            severity = finding.get("risk_level", "Low")
            control = finding.get("nca_control", "Unmapped Control")

            if severity in severity_summary:
                severity_summary[severity] += 1

            control_summary[control] = control_summary.get(control, 0) + 1

        if final_score >= 90:
            posture = "Strong"
        elif final_score >= 75:
            posture = "Moderate"
        elif final_score >= 50:
            posture = "Weak"
        else:
            posture = "Critical"

        return {
            "final_score": final_score,
            "total_deduction": total_deduction,
            "severity_summary": severity_summary,
            "control_summary": control_summary,
            "posture": posture
        }