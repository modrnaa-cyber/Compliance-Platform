# services/normalization_service.py

import hashlib
from typing import List, Dict, Any


class NormalizationService:
    def __init__(self):
        self.severity_map = {
            "info": "Low",
            "informational": "Low",
            "none": "Low",
            "low": "Low",
            "medium": "Medium",
            "moderate": "Medium",
            "high": "High",
            "critical": "Critical",
        }

        self.service_aliases = {
            "www": "http",
            "www-http": "http",
            "http-proxy": "http",
            "ssl/http": "https",
            "https-alt": "https",
            "domain": "dns",
            "microsoft-ds": "smb",
            "netbios-ssn": "netbios",
            "msrpc": "rpc",
            "postgresql": "postgres",
        }

    def normalize_service_name(self, service: str):
        if not service:
            return None
        value = str(service).strip().lower()
        return self.service_aliases.get(value, value)

    def normalize_severity(self, severity: str = None, cvss: float = 0.0):
        if severity:
            normalized = self.severity_map.get(str(severity).strip().lower())
            if normalized:
                return normalized

        cvss = float(cvss or 0.0)

        if cvss >= 9.0:
            return "Critical"
        if cvss >= 7.0:
            return "High"
        if cvss >= 4.0:
            return "Medium"
        return "Low"

    def severity_weight(self, severity: str):
        weights = {
            "Critical": 40.0,
            "High": 25.0,
            "Medium": 12.0,
            "Low": 5.0
        }
        return weights.get(severity, 5.0)

    def build_finding_id(self, host, port, protocol, title, source):
        raw = f"{host}|{port}|{protocol}|{title}|{source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def normalize_nessus_findings(self, raw_findings: List[Dict[str, Any]], asset_id: str) -> List[Dict[str, Any]]:
        normalized = []

        for item in raw_findings:
            host = item.get("host", asset_id)
            port = item.get("port")
            protocol = str(item.get("protocol", "tcp")).lower()
            title = item.get("title", "Unnamed Nessus Finding")
            description = item.get("description", "")
            cvss = float(item.get("cvss", 0.0) or 0.0)
            severity = self.normalize_severity(item.get("severity"), cvss=cvss)
            service = self.normalize_service_name(item.get("service"))
            remediation = item.get("solution", "No remediation provided")

            normalized.append({
                "finding_id": self.build_finding_id(host, port, protocol, title, "nessus"),
                "asset_id": asset_id,
                "title": title,
                "description": description,
                "source": "nessus",
                "plugin_id": item.get("plugin_id"),
                "cves": item.get("cves", []),
                "cvss": cvss,
                "severity": severity,
                "risk_level": severity,
                "protocol": protocol,
                "port": int(port) if port not in [None, ""] else None,
                "service": service,
                "state": "open",
                "evidence": {
                    "plugin_output": item.get("plugin_output", ""),
                    "references": item.get("references", [])
                },
                "remediation": remediation,
                "references": item.get("references", []),
                "exploit_available": False,
                "internet_exposed": False,
                "asset_criticality": "medium",
                "priority_score": 0.0,
                "priority_tier": "P4",
                "nca_control": None,
                "deduction": self.severity_weight(severity),
                "status": "open"
            })

        return normalized

    def normalize_nmap_findings(self, nmap_result: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
        normalized = []
        host = nmap_result.get("target", asset_id)
        ports = nmap_result.get("ports", [])

        for item in ports:
            state = str(item.get("state", "")).lower()
            if state != "open":
                continue

            port = item.get("port")
            protocol = str(item.get("protocol", "tcp")).lower()
            service = self.normalize_service_name(item.get("service"))
            version = item.get("version", "")
            product = item.get("product", "")

            title = f"Exposed service detected: {service or 'unknown'} on port {port}"
            description = f"Network discovery identified an exposed service on {port}/{protocol}. Version: {version}".strip()

            normalized.append({
                "finding_id": self.build_finding_id(host, port, protocol, title, "nmap"),
                "asset_id": asset_id,
                "title": title,
                "description": description,
                "source": "nmap",
                "plugin_id": None,
                "cves": [],
                "cvss": 0.0,
                "severity": "Low",
                "risk_level": "Low",
                "protocol": protocol,
                "port": int(port) if port not in [None, ""] else None,
                "service": service,
                "state": state,
                "evidence": {
                    "version": version,
                    "product": product
                },
                "remediation": "Validate whether the exposed service is required and restrict access where possible.",
                "references": [],
                "exploit_available": False,
                "internet_exposed": False,
                "asset_criticality": "medium",
                "priority_score": 0.0,
                "priority_tier": "P4",
                "nca_control": None,
                "deduction": 2.0,
                "status": "open"
            })

        return normalized