# services/normalization_service.py
import hashlib
from typing import List, Dict


class NormalizationService:
    SEVERITY_MAP = {
        "info": "Low",
        "informational": "Low",
        "low": "Low",
        "medium": "Medium",
        "moderate": "Medium",
        "high": "High",
        "critical": "Critical"
    }

    CVSS_TO_SEVERITY = [
        (9.0, "Critical"),
        (7.0, "High"),
        (4.0, "Medium"),
        (0.1, "Low"),
        (0.0, "Low")
    ]

    SERVICE_ALIASES = {
        "www": "http",
        "www-http": "http",
        "ssl/http": "https",
        "domain": "dns",
        "microsoft-ds": "smb",
        "msrpc": "rpc",
        "netbios-ssn": "netbios",
        "postgresql": "postgres",
        "https-alt": "https"
    }

    def normalize_service_name(self, service: str):
        if not service:
            return None
        value = service.strip().lower()
        return self.SERVICE_ALIASES.get(value, value)

    def normalize_severity(self, severity: str, cvss: float = 0.0):
        if severity:
            normalized = self.SEVERITY_MAP.get(str(severity).strip().lower())
            if normalized:
                return normalized

        for threshold, mapped in self.CVSS_TO_SEVERITY:
            if cvss >= threshold:
                return mapped

        return "Low"

    def severity_weight(self, severity: str):
        mapping = {
            "Critical": 40,
            "High": 25,
            "Medium": 12,
            "Low": 5
        }
        return mapping.get(severity, 0)

    def build_finding_id(self, host, port, protocol, title, source):
        raw = f"{host}|{port}|{protocol}|{title}|{source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def normalize_nessus_findings(self, raw_findings: List[Dict], asset_id: str) -> List[Dict]:
        normalized = []

        for item in raw_findings:
            cvss = float(item.get("cvss", 0.0) or 0.0)
            severity = self.normalize_severity(item.get("severity"), cvss)
            service = self.normalize_service_name(item.get("service"))
            host = item.get("host")
            port = item.get("port")
            protocol = item.get("protocol", "tcp")

            normalized.append({
                "finding_id": self.build_finding_id(host, port, protocol, item.get("title"), "nessus"),
                "asset_id": asset_id,
                "title": item.get("title", "Unnamed Finding"),
                "description": item.get("description", ""),
                "source": "nessus",
                "plugin_id": item.get("plugin_id"),
                "cves": item.get("cves", []),
                "cvss": cvss,
                "severity": severity,
                "risk_level": severity,
                "protocol": protocol,
                "port": port,
                "service": service,
                "state": "open",
                "evidence": {
                    "plugin_output": item.get("plugin_output", ""),
                    "references": item.get("references", [])
                },
                "remediation": item.get("solution", ""),
                "references": item.get("references", []),
                "exploit_available": False,
                "internet_exposed": False,
                "asset_criticality": "medium",
                "priority_score": 0.0,
                "nca_control": None,
                "deduction": float(self.severity_weight(severity)),
                "status": "open"
            })

        return normalized

    def normalize_nmap_findings(self, nmap_result: Dict, asset_id: str) -> List[Dict]:
        normalized = []
        host = nmap_result.get("target")
        ports = nmap_result.get("ports", [])

        for item in ports:
            if str(item.get("state", "")).lower() != "open":
                continue

            port = item.get("port")
            protocol = item.get("protocol", "tcp")
            service = self.normalize_service_name(item.get("service"))
            version = item.get("version", "")

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
                "port": port,
                "service": service,
                "state": item.get("state", "open"),
                "evidence": {
                    "version": version,
                    "product": item.get("product", "")
                },
                "remediation": "Validate whether the exposed service is required and restrict access where possible.",
                "references": [],
                "exploit_available": False,
                "internet_exposed": False,
                "asset_criticality": "medium",
                "priority_score": 0.0,
                "nca_control": None,
                "deduction": 2.0,
                "status": "open"
            })

        return normalized