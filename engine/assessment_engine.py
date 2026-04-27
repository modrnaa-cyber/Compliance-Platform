from services.nmap_service import run_nmap_scan
from services.cache_service import load_cached_findings
from services.nessus_service import NessusService
from engine.compliance_matrix import map_finding_to_control
from engine.scoring_engine import calculate_compliance_score
from engine.remediation_engine import get_remediation


def build_assessment(target, scan_profile):
    nmap_result = run_nmap_scan(target, scan_profile)

    if nmap_result.get("error"):
        return {
            "status": "error",
            "target": target,
            "scan_profile": scan_profile,
            "scanner": nmap_result["scanner"],
            "message": nmap_result["error"]
        }

    normalized_findings = []

    for item in nmap_result.get("findings", []):
        title = f"Open port {item['port']}/{item['service']}"
        if item.get("product"):
            title += f" ({item['product']})"
        if item.get("version"):
            title += f" {item['version']}"

        normalized_findings.append({
            "title": title,
            "service": item["service"],
            "state": item["state"],
            "source": "Nmap",
            "port": item["port"],
            "protocol": item.get("protocol", "tcp"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "extrainfo": item.get("extrainfo", ""),
            "description": item.get("description", "")
        })

    cached_findings = load_cached_findings(target)
    for item in cached_findings:
        normalized_findings.append({
            "title": item["title"],
            "service": item["service"],
            "state": "detected",
            "source": item.get("source", "Cache"),
            "port": item.get("port"),
            "protocol": item.get("protocol"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "extrainfo": item.get("extrainfo", ""),
            "description": item.get("description", ""),
            "severity": item.get("severity"),
            "plugin_id": item.get("plugin_id"),
            "solution": item.get("solution", ""),
            "cves": item.get("cves", [])
        })

    nessus_service = NessusService(base_path="nessus")
    nessus_scan = nessus_service.load_scan_file("last_scan.json")

    if nessus_scan.get("status") == "success":
        nessus_findings = nessus_service.extract_findings(nessus_scan.get("data", {}), target)

        for item in nessus_findings:
            normalized_findings.append({
                "title": item["title"],
                "service": item.get("service", "unknown"),
                "state": "detected",
                "source": "Nessus Cache",
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "product": "",
                "version": "",
                "extrainfo": "",
                "description": item.get("description", ""),
                "severity": item.get("severity"),
                "risk_factor": item.get("risk_factor"),
                "cvss": item.get("cvss"),
                "plugin_id": item.get("plugin_id"),
                "solution": item.get("solution", ""),
                "plugin_output": item.get("plugin_output", ""),
                "cves": item.get("cves", []),
                "references": item.get("references", [])
            })

    mapped_findings = []
    for item in normalized_findings:
        control_data = map_finding_to_control(item["service"])
        remediation = (
            item.get("solution")
            or get_remediation(item["service"])
        )

        mapped_findings.append({
            "title": item["title"],
            "service": item["service"],
            "state": item["state"],
            "source": item["source"],
            "port": item.get("port"),
            "protocol": item.get("protocol"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "extrainfo": item.get("extrainfo", ""),
            "description": item.get("description", ""),
            "severity": item.get("severity", control_data["risk_level"]),
            "risk_level": control_data["risk_level"],
            "nca_control": control_data["control_id"],
            "control_name": control_data["control_name"],
            "deduction": control_data["deduction"],
            "remediation": remediation,
            "plugin_id": item.get("plugin_id"),
            "cvss": item.get("cvss"),
            "cves": item.get("cves", []),
            "references": item.get("references", [])
        })

    score_result = calculate_compliance_score(mapped_findings)

    return {
        "status": "success",
        "target": target,
        "scan_profile": scan_profile,
        "scanner": nmap_result["scanner"],
        "summary": {
            "total_findings": len(mapped_findings),
            "nmap_findings": len([f for f in mapped_findings if f["source"] == "Nmap"]),
            "cache_findings": len([f for f in mapped_findings if f["source"] == "Cache"]),
            "nessus_findings": len([f for f in mapped_findings if f["source"] == "Nessus Cache"])
        },
        "score": score_result,
        "executive_summary": {
            "target": target,
            "posture": score_result.get("posture", "Unknown"),
            "total_findings": len(mapped_findings)
        },
        "compliance_gaps": mapped_findings
    }