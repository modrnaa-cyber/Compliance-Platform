import subprocess


class WhatWebService:
    def scan_target(self, target):
        try:
            result = subprocess.run(
                ["whatweb", target],
                capture_output=True,
                text=True,
                timeout=60
            )

            output = result.stdout.strip()

            return {
                "tool": "WhatWeb",
                "target": target,
                "status": "completed",
                "raw_output": output,
                "findings": [
                    {
                        "title": "Web Technology Detected",
                        "description": output or "Web technology fingerprinting completed.",
                        "severity": "Low",
                        "service": "web",
                        "port": 80,
                        "protocol": "tcp",
                        "cve": [],
                        "remediation": "Review exposed web technologies and hide unnecessary server banners."
                    }
                ]
            }

        except Exception as e:
            return {
                "tool": "WhatWeb",
                "target": target,
                "status": "simulated",
                "raw_output": str(e),
                "findings": [
                    {
                        "title": "Web Technology Fingerprinting",
                        "description": "Simulated WhatWeb result: web server technology detected.",
                        "severity": "Low",
                        "service": "web",
                        "port": 80,
                        "protocol": "tcp",
                        "cve": [],
                        "remediation": "Review exposed web technology information and disable unnecessary banners."
                    }
                ]
            }