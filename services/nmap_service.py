import time
import re
import nmap


class NmapService:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def _arguments_by_mode(self, mode):
        profiles = {
            "quick_internal": "-Pn -T4 --top-ports 100 -sV --script vulners",
            "standard_internal": "-Pn -T4 --top-ports 1000 -sV -O --script vulners",
            "deep_internal": "-Pn -T4 -p- -sV -O --script vulners"
        }

        return profiles.get(mode, profiles["standard_internal"])

    def _extract_cves(self, script_output):
        if not script_output:
            return []

        matches = re.findall(r"CVE-\d{4}-\d{4,7}", script_output)

        unique_cves = []
        for cve in matches:
            if cve not in unique_cves:
                unique_cves.append(cve)

        return unique_cves

    def scan_target(self, target, mode="standard_internal"):
        arguments = self._arguments_by_mode(mode)

        started_at = time.time()

        self.scanner.scan(
            hosts=target,
            arguments=arguments
        )

        ended_at = time.time()

        hosts = []
        total_open_ports = 0

        for host in self.scanner.all_hosts():
            host_record = {
                "ip": host,
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "ports": []
            }

            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()

                for port in sorted(ports):
                    port_info = self.scanner[host][proto][port]
                    state = port_info.get("state", "unknown")

                    if state == "open":
                        total_open_ports += 1

                    scripts = port_info.get("script", {})
                    vulners_output = scripts.get("vulners", "")

                    cves = self._extract_cves(vulners_output)

                    host_record["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "cves": cves
                    })

            hosts.append(host_record)

        duration = round(ended_at - started_at, 2)

        return {
            "target": target,
            "mode": mode,
            "arguments": arguments,
            "hosts": hosts,
            "scan_duration": duration,
            "total_open_ports": total_open_ports
        }