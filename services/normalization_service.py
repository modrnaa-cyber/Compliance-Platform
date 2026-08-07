class NormalizationService:
    NCA_CONTROLS = {
        "1-1": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-1",
            "control_name": "Cybersecurity Strategy"
        },
        "1-2": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-2",
            "control_name": "Cybersecurity Management"
        },
        "1-3": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-3",
            "control_name": "Cybersecurity Policies and Procedures"
        },
        "1-4": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-4",
            "control_name": "Cybersecurity Roles and Responsibilities"
        },
        "1-5": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-5",
            "control_name": "Cybersecurity Risk Management"
        },
        "1-6": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-6",
            "control_name": "Cybersecurity in Information Technology Project Management"
        },
        "1-7": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-7",
            "control_name": "Cybersecurity Awareness and Training"
        },
        "1-8": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-8",
            "control_name": "Cybersecurity Regulatory Compliance"
        },
        "1-9": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-9",
            "control_name": "Cybersecurity Periodical Review and Audit"
        },
        "1-10": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-10",
            "control_name": "Cybersecurity in Human Resources"
        },
        "1-11": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Governance",
            "control_id": "1-11",
            "control_name": "Cybersecurity in Asset Management"
        },

        "2-1": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-1",
            "control_name": "Identity and Access Management"
        },
        "2-2": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-2",
            "control_name": "Privileged Access Management"
        },
        "2-3": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-3",
            "control_name": "Information System and Processing Facilities Protection"
        },
        "2-4": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-4",
            "control_name": "Email Protection"
        },
        "2-5": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-5",
            "control_name": "Network Security Management"
        },
        "2-6": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-6",
            "control_name": "Mobile Devices Security"
        },
        "2-7": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-7",
            "control_name": "Data and Information Protection"
        },
        "2-8": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-8",
            "control_name": "Cryptography"
        },
        "2-9": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-9",
            "control_name": "Backup and Recovery"
        },
        "2-10": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-10",
            "control_name": "Vulnerability Management"
        },
        "2-11": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-11",
            "control_name": "Penetration Testing"
        },
        "2-12": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-12",
            "control_name": "Cybersecurity Event Logs and Monitoring"
        },
        "2-13": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-13",
            "control_name": "Cybersecurity Incident and Threat Management"
        },
        "2-14": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-14",
            "control_name": "Physical Security"
        },
        "2-15": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Defense",
            "control_id": "2-15",
            "control_name": "Web Application Security"
        },

        "3-1": {
            "framework": "NCA ECC 2-2024",
            "domain": "Cybersecurity Resilience",
            "control_id": "3-1",
            "control_name": "Cybersecurity Resilience Aspects of Business Continuity Management"
        },

        "4-1": {
            "framework": "NCA ECC 2-2024",
            "domain": "Third-Party and Cloud Computing Cybersecurity",
            "control_id": "4-1",
            "control_name": "Third-Party Cybersecurity"
        },
        "4-2": {
            "framework": "NCA ECC 2-2024",
            "domain": "Third-Party and Cloud Computing Cybersecurity",
            "control_id": "4-2",
            "control_name": "Cloud Computing and Hosting Cybersecurity"
        }
    }

    def from_nmap(self, raw_nmap):
        findings = []

        for host in raw_nmap.get("hosts", []):
            ip = host.get("ip")
            hostname = host.get("hostname")

            for port_item in host.get("ports", []):
                if port_item.get("state") != "open":
                    continue

                port = port_item.get("port")
                protocol = port_item.get("protocol")
                service = port_item.get("service", "unknown")
                cves = port_item.get("cves", [])

                if not isinstance(cves, list):
                    cves = []

                severity = self._severity_from_nmap(service, port, cves)
                compliance = self._map_controls(service, port, cves)

                findings.append({
                    "fingerprint": f"{ip}|{port}|{service}|nmap",
                    "source": ["Internal"],
                    "asset": {
                        "ip": ip,
                        "hostname": hostname,
                        "port": port,
                        "protocol": protocol,
                        "service": service
                    },
                    "title": f"Open port {port}/{service}",
                    "description": f"Open port {port}/{service} detected by internal scanner.",
                    "severity": severity,
                    "cvss": self._cvss_from_severity(severity),
                    "cve": cves,
                    "plugin_id": None,
                    "compliance": compliance["primary"],
                    "related_controls": compliance["related"],
                    "deduction": self._deduction(severity),
                    "remediation": self._remediation(service, cves)
                })

        return findings

    def from_openvas(self, raw_openvas, target):
        return self._from_generic_tool(raw_openvas.get("vulnerabilities", []), target, "OpenVAS")

    def from_whatweb(self, raw_whatweb, target):
        return self._from_generic_tool(raw_whatweb.get("findings", []), target, "WhatWeb")

    def from_testssl(self, raw_testssl, target):
        return self._from_generic_tool(raw_testssl.get("findings", []), target, "testssl.sh")

    def _from_generic_tool(self, items, target, source_name):
        findings = []

        for item in items:
            severity = item.get("severity", "Low")
            port = item.get("port")
            protocol = item.get("protocol", "tcp")
            service = item.get("service", "unknown")
            cves = item.get("cve", [])

            if not isinstance(cves, list):
                cves = []

            compliance = self._map_controls(service, port, cves)

            findings.append({
                "fingerprint": f"{target}|{port}|{service}|{source_name.lower()}",
                "source": [source_name],
                "asset": {
                    "ip": target,
                    "hostname": target,
                    "port": port,
                    "protocol": protocol,
                    "service": service
                },
                "title": item.get("title", f"{source_name} Finding"),
                "description": item.get("description", f"{source_name} finding detected."),
                "severity": severity,
                "cvss": item.get("cvss", self._cvss_from_severity(severity)),
                "cve": cves,
                "plugin_id": item.get("plugin_id"),
                "compliance": compliance["primary"],
                "related_controls": compliance["related"],
                "deduction": self._deduction(severity),
                "remediation": item.get("remediation", self._remediation(service, cves))
            })

        return findings

    def _control(self, control_id):
        return self.NCA_CONTROLS.get(control_id, self.NCA_CONTROLS["1-5"])

    def _map_controls(self, service, port=None, cves=None):
        service = str(service).lower()
        cves = cves or []

        related_ids = []

        if cves:
            related_ids.append("2-10")

        if "http" in service or service == "web":
            if port == 80:
                primary_id = "2-15"
                related_ids.extend(["2-5", "2-8"])
            elif port == 443 or "https" in service:
                primary_id = "2-8"
                related_ids.extend(["2-15", "2-5"])
            else:
                primary_id = "2-15"
                related_ids.extend(["2-5"])
        elif "https" in service or "ssl" in service or "tls" in service:
            primary_id = "2-8"
            related_ids.extend(["2-5", "2-15"])
        elif "ssh" in service:
            primary_id = "2-2"
            related_ids.extend(["2-1", "2-5"])
        elif "ftp" in service or "telnet" in service:
            primary_id = "2-1"
            related_ids.extend(["2-2", "2-5"])
        elif "domain" in service or "dns" in service:
            primary_id = "2-5"
            related_ids.extend(["2-3"])
        elif "smtp" in service or "mail" in service:
            primary_id = "2-4"
            related_ids.extend(["2-5"])
        elif "mysql" in service or "mssql" in service or "postgres" in service or "oracle" in service or "database" in service:
            primary_id = "2-7"
            related_ids.extend(["2-1", "2-5"])
        elif "rdp" in service or port == 3389:
            primary_id = "2-2"
            related_ids.extend(["2-1", "2-5"])
        elif "smb" in service or "netbios" in service or port in [139, 445]:
            primary_id = "2-5"
            related_ids.extend(["2-3", "2-7"])
        elif "upnp" in service:
            primary_id = "2-5"
            related_ids.extend(["2-3"])
        elif "tcpwrapped" in service or "unknown" in service:
            primary_id = "2-3"
            related_ids.extend(["1-5", "2-5"])
        else:
            primary_id = "1-5"
            related_ids.extend(["1-11", "2-5"])

        unique_related = []
        for control_id in related_ids:
            if control_id != primary_id and control_id not in unique_related:
                unique_related.append(control_id)

        return {
            "primary": self._control(primary_id),
            "related": [self._control(control_id) for control_id in unique_related]
        }

    def _severity_from_nmap(self, service, port, cves):
        service = str(service).lower()

        if cves:
            return "High"

        if port in [21, 23, 445, 3389]:
            return "High"

        if port in [80, 139, 110, 143, 443]:
            return "Medium"

        if "unknown" in service or "tcpwrapped" in service:
            return "Low"

        return "Low"

    def _cvss_from_severity(self, severity):
        return {
            "Critical": 9.5,
            "High": 8.0,
            "Medium": 5.5,
            "Low": 2.5
        }.get(severity, 2.5)

    def _deduction(self, severity):
        return {
            "Critical": 15,
            "High": 10,
            "Medium": 5,
            "Low": 2
        }.get(severity, 2)

    def _remediation(self, service, cves=None):
        service = str(service).lower()
        cves = cves or []

        if cves:
            return "Review detected CVEs, validate exposure, apply vendor patches, and track remediation under vulnerability management."

        if "https" in service or "ssl" in service or "tls" in service:
            return "Enforce TLS 1.2 or TLS 1.3, disable weak ciphers, and review certificate configuration."

        if "http" in service or "web" in service:
            return "Redirect HTTP to HTTPS, enforce TLS, harden web headers, and disable unnecessary web technology disclosure."

        if "ssh" in service:
            return "Restrict SSH exposure, enforce key-based authentication, disable password login where possible, and limit administrative source IPs."

        if "ftp" in service or "telnet" in service:
            return "Disable insecure remote access protocols or replace them with secure alternatives such as SSH or SFTP."

        if "domain" in service or "dns" in service:
            return "Restrict DNS exposure, disable open recursion, and review DNS service hardening."

        if "upnp" in service:
            return "Disable UPnP on exposed interfaces unless explicitly required and approved."

        if "tcpwrapped" in service or "unknown" in service:
            return "Identify the exposed service, validate business need, and restrict access using firewall rules."

        return "Review the service configuration, validate business need, and align exposure with security policy."