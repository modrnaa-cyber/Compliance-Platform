# services/nessus_service.py
import json
import os
from typing import List, Dict, Any


class NessusService:
    def __init__(self, base_path="data/nessus"):
        self.base_path = base_path

    def _safe_get(self, obj: Dict, key: str, default=None):
        value = obj.get(key, default)
        return value if value not in [None, ""] else default

    def load_scan_file(self, filename: str = "last_scan.json") -> Dict[str, Any]:
        file_path = os.path.join(self.base_path, filename)

        if not os.path.exists(file_path):
            return {
                "status": "error",
                "message": f"Nessus scan file not found: {file_path}",
                "data": {}
            }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)

            return {
                "status": "success",
                "message": "Nessus scan loaded successfully",
                "data": raw
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to parse Nessus scan file: {str(e)}",
                "data": {}
            }

    def extract_findings(self, scan_data: Dict[str, Any], target: str = None) -> List[Dict]:
        findings = []

        raw_findings = scan_data.get("findings", [])
        scan_target = scan_data.get("scan_target")

        for item in raw_findings:
            host = self._safe_get(item, "host", scan_target or target)
            port = self._safe_get(item, "port")
            protocol = self._safe_get(item, "protocol", "tcp")
            service = self._safe_get(item, "service")
            severity = self._safe_get(item, "severity", "Low")
            risk_factor = self._safe_get(item, "risk_factor", severity)
            cvss = self._safe_get(item, "cvss", 0.0)
            plugin_id = str(self._safe_get(item, "plugin_id", ""))
            plugin_name = self._safe_get(item, "plugin_name", "Unnamed Nessus Finding")
            solution = self._safe_get(item, "solution", "No remediation provided")
            cve = item.get("cve", []) or []
            description = self._safe_get(item, "description", "")
            plugin_output = self._safe_get(item, "plugin_output", "")
            references = item.get("references", []) or []

            findings.append({
                "host": host,
                "port": int(port) if port not in [None, ""] else None,
                "protocol": protocol,
                "service": service,
                "severity": severity,
                "risk_factor": risk_factor,
                "cvss": float(cvss) if cvss not in [None, ""] else 0.0,
                "plugin_id": plugin_id,
                "title": plugin_name,
                "description": description,
                "plugin_output": plugin_output,
                "solution": solution,
                "cves": cve,
                "references": references,
                "source": "nessus"
            })

        return findings