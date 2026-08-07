# تأكد من استيراد الكلاس بشكل صحيح
from services.nca_controls_service import NCAControlsService

class ComplianceService:
    def build_dashboard(self, target, mode, raw_nmap, merged_findings, nessus_meta=None):
        if nessus_meta is None:
            nessus_meta = {}

        if not isinstance(merged_findings, list):
            merged_findings = []

        severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        source_breakdown = {
            "Internal": 0,
            "OpenVAS": 0,
            "WhatWeb": 0,
            "testssl.sh": 0,
            "Correlated": 0
        }

        total_deduction = 0
        compliance_gaps = []

        # تأكد من أن المعايير تتوافق مع نوع الفحص
        for finding in merged_findings:
            if not isinstance(finding, dict):
                continue

            severity = finding.get("severity", "Low")
            if severity not in severity_breakdown:
                severity = "Low"

            severity_breakdown[severity] += 1
            total_deduction += int(finding.get("deduction", 0))

            sources = finding.get("source", [])
            if not isinstance(sources, list):
                sources = [str(sources)]

            if sources == ["Internal"]:
                source_breakdown["Internal"] += 1
            elif sources == ["OpenVAS"]:
                source_breakdown["OpenVAS"] += 1
            elif sources == ["WhatWeb"]:
                source_breakdown["WhatWeb"] += 1
            elif sources == ["testssl.sh"]:
                source_breakdown["testssl.sh"] += 1
            else:
                source_breakdown["Correlated"] += 1

            asset = finding.get("asset", {})
            if not isinstance(asset, dict):
                asset = {}

            compliance = finding.get("compliance", {})
            if not isinstance(compliance, dict):
                compliance = {}

            related_controls = finding.get("related_controls", [])
            if not isinstance(related_controls, list):
                related_controls = []

            control_ids = []
            primary_control_id = compliance.get("control_id", "1-5")
            control_ids.append(primary_control_id)

            for control in related_controls:
                if isinstance(control, dict):
                    control_id = control.get("control_id")
                    if control_id and control_id not in control_ids:
                        control_ids.append(control_id)

            nca_control_text = ", ".join(control_ids)

            cves = finding.get("cve", [])
            if isinstance(cves, list):
                cve_text = ", ".join(cves) if cves else "No CVE detected"
            else:
                cve_text = str(cves) if cves else "No CVE detected"

            compliance_gaps.append({
                "finding": finding.get("title", "Unknown finding"),
                "service": asset.get("service", "unknown"),
                "risk": severity,
                "cve": cve_text,
                "nca_control": nca_control_text,
                "nca_domain": compliance.get("domain", "NCA ECC 2-2024"),
                "nca_control_name": compliance.get("control_name", "Cybersecurity Risk Management"),
                "source": ", ".join(sources),
                "deduction": int(finding.get("deduction", 0)),
                "remediation": finding.get("remediation", "No remediation provided.")
            })

        final_score = max(0, 100 - total_deduction)

        if final_score >= 85:
            posture = "Good"
            risk_level = "Low"
        elif final_score >= 70:
            posture = "Moderate"
            risk_level = "Medium"
        else:
            posture = "Poor"
            risk_level = "High"

        mode_map = {
            "quick_internal": {
                "label": "Nmap Quick Scan (Top 100 Ports)",
                "engine": "Nmap"
            },
            "standard_internal": {
                "label": "Nmap Standard Scan (Top 1000 Ports)",
                "engine": "Nmap"
            },
            "deep_internal": {
                "label": "Nmap Deep Scan (All Ports)",
                "engine": "Nmap"
            },
            "vulners_quick": {
                "label": "Nmap + Vulners Quick",
                "engine": "Nmap + Vulners"
            },
            "vulners_standard": {
                "label": "Nmap + Vulners Standard",
                "engine": "Nmap + Vulners"
            },
            "vulners_deep": {
                "label": "Nmap + Vulners Deep",
                "engine": "Nmap + Vulners"
            },
            "openvas_basic": {
                "label": "OpenVAS Basic Scan",
                "engine": "OpenVAS"
            },
            "openvas_advanced": {
                "label": "OpenVAS Advanced Scan",
                "engine": "OpenVAS"
            },
            "openvas_web": {
                "label": "OpenVAS Web Application Scan",
                "engine": "OpenVAS"
            },
            "hybrid_quick": {
                "label": "Hybrid Quick (Nmap + OpenVAS)",
                "engine": "Nmap + OpenVAS"
            },
            "hybrid_standard": {
                "label": "Hybrid Standard (Nmap + Vulners + OpenVAS)",
                "engine": "Nmap + Vulners + OpenVAS"
            },
            "hybrid_deep": {
                "label": "Hybrid Deep (Nmap + Vulners + OpenVAS)",
                "engine": "Nmap + Vulners + OpenVAS"
            },
            "web_technology": {
                "label": "Web Technology Detection (WhatWeb)",
                "engine": "WhatWeb"
            },
            "ssl_tls_scan": {
                "label": "SSL/TLS Scan (testssl.sh)",
                "engine": "testssl.sh"
            },
            "full_assessment": {
                "label": "Full Assessment (All Engines)",
                "engine": "Nmap + Vulners + OpenVAS + WhatWeb + testssl.sh"
            }
        }

        mode_info = mode_map.get(mode, {
            "label": mode or "Unknown Mode",
            "engine": "Unknown"
        })

        hosts = raw_nmap.get("hosts", []) if isinstance(raw_nmap, dict) else []
        host_status = hosts[0].get("state", "unknown") if hosts else "unknown"

        nca_service = NCAControlsService()
        nca_coverage = nca_service.build_coverage_matrix(compliance_gaps)

        return {
            "target": target,
            "mode": mode,
            "mode_label": mode_info["label"],
            "scan_engine": mode_info["engine"],
            "host_status": host_status,
            "final_score": final_score,
            "total_deduction": total_deduction,
            "posture": posture,
            "risk_level": risk_level,
            "total_findings": len(compliance_gaps),
            "severity_breakdown": severity_breakdown,
            "source_breakdown": source_breakdown,
            "scan_duration": raw_nmap.get("scan_duration", 0) if isinstance(raw_nmap, dict) else 0,
            "total_open_ports": raw_nmap.get("total_open_ports", 0) if isinstance(raw_nmap, dict) else 0,
            "nessus_meta": nessus_meta,
            "compliance_gaps": compliance_gaps,
            "nca_coverage": nca_coverage
        }