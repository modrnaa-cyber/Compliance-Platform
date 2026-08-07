class OpenVASService:
    def launch_and_fetch_scan(self, target, service_type=None, progress_callback=None):
        if progress_callback:
            progress_callback({
                "progress": 55,
                "stage": "Running OpenVAS",
                "message": "OpenVAS deep validation started"
            })

        mock_findings = []

        if service_type == "deep_internal":
            mock_findings = [
                {
                    "title": "TLS Weak Cipher Suite Detected",
                    "description": "The remote service supports weak TLS cipher suites.",
                    "severity": "Medium",
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "cvss": 5.9,
                    "cve": ["CVE-2023-44487"],
                    "plugin_id": "openvas-1001",
                    "remediation": "Disable weak TLS cipher suites and enforce modern TLS configuration."
                },
                {
                    "title": "Outdated Web Server Detected",
                    "description": "The detected web server version is outdated and may expose known vulnerabilities.",
                    "severity": "High",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "cvss": 8.1,
                    "cve": ["CVE-2024-12345"],
                    "plugin_id": "openvas-1002",
                    "remediation": "Upgrade the web server to the latest secure version and apply vendor patches."
                }
            ]

        return {
            "nessus_meta": {
                "connected": True,
                "used": service_type == "deep_internal",
                "scan_id": "openvas-local-simulated",
                "scan_name": "OpenVAS Deep Validation",
                "status": "Completed",
                "creation_date": None,
                "last_modification_date": None,
                "message": "OpenVAS deep validation completed successfully."
            },
            "vulnerabilities": mock_findings
        }