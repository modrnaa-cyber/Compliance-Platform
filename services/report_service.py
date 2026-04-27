# services/report_service.py
from typing import List, Dict


class ReportService:
    def build_executive_summary(self, target: str, findings: List[Dict], compliance_summary: Dict) -> Dict:
        total_findings = len(findings)
        internet_exposed_count = sum(1 for f in findings if f.get("internet_exposed"))
        exploitable_count = sum(1 for f in findings if f.get("exploit_available"))
        top_priority_count = sum(1 for f in findings if f.get("priority_tier") == "P1")

        return {
            "target": target,
            "posture": compliance_summary.get("posture", "Unknown"),
            "total_findings": total_findings,
            "internet_exposed_findings": internet_exposed_count,
            "exploitable_findings": exploitable_count,
            "priority_one_findings": top_priority_count
        }

    def build_dashboard_metrics(self, findings: List[Dict], compliance_summary: Dict) -> Dict:
        return {
            "final_score": compliance_summary.get("final_score", 0),
            "total_deduction": compliance_summary.get("total_deduction", 0),
            "posture": compliance_summary.get("posture", "Unknown"),
            "severity_summary": compliance_summary.get("severity_summary", {}),
            "control_summary": compliance_summary.get("control_summary", {})
        }

    def build_compliance_gaps(self, findings: List[Dict]) -> List[Dict]:
        gaps = []

        for finding in findings:
            gaps.append({
                "title": finding.get("title"),
                "service": finding.get("service"),
                "risk_level": finding.get("risk_level"),
                "priority_tier": finding.get("priority_tier"),
                "priority_score": finding.get("priority_score"),
                "nca_control": finding.get("nca_control"),
                "source": finding.get("source"),
                "deduction": finding.get("deduction"),
                "owner": finding.get("owner"),
                "sla_days": finding.get("sla_days"),
                "due_date": finding.get("due_date"),
                "remediation": finding.get("remediation")
            })

        return gaps

    def build_full_response(self, target: str, findings: List[Dict], compliance_summary: Dict) -> Dict:
        return {
            "status": "success",
            "message": "Enterprise assessment completed successfully",
            "summary": {
                "target": target,
                "total_findings": len(findings)
            },
            "executive_summary": self.build_executive_summary(target, findings, compliance_summary),
            "score": self.build_dashboard_metrics(findings, compliance_summary),
            "compliance_gaps": self.build_compliance_gaps(findings),
            "top_findings": findings[:10]
        }