import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def get_nmap_command(scan_profile, target, xml_output_path):
    if scan_profile == "quick":
        return ["nmap", "-Pn", "-F", "-sV", "-oX", xml_output_path, target]

    if scan_profile == "standard":
        return ["nmap", "-Pn", "--top-ports", "1000", "-sV", "-oX", xml_output_path, target]

    if scan_profile == "deep":
        return ["nmap", "-Pn", "-p-", "-sV", "-T4", "-oX", xml_output_path, target]

    return ["nmap", "-Pn", "--top-ports", "1000", "-sV", "-oX", xml_output_path, target]


def parse_nmap_xml(xml_path):
    findings = []
    host_summary = {
        "addresses": [],
        "hostnames": [],
        "status": "unknown"
    }

    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host in root.findall("host"):
        status_tag = host.find("status")
        if status_tag is not None:
            host_summary["status"] = status_tag.get("state", "unknown")

        for address in host.findall("address"):
            addr = address.get("addr")
            if addr:
                host_summary["addresses"].append(addr)

        hostnames_tag = host.find("hostnames")
        if hostnames_tag is not None:
            for hostname in hostnames_tag.findall("hostname"):
                name = hostname.get("name")
                if name:
                    host_summary["hostnames"].append(name)

        ports_tag = host.find("ports")
        if ports_tag is not None:
            for port in ports_tag.findall("port"):
                state = port.find("state")
                service = port.find("service")

                if state is not None and state.get("state") == "open":
                    findings.append({
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol", "tcp"),
                        "service": service.get("name", "unknown") if service is not None else "unknown",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "extrainfo": service.get("extrainfo", "") if service is not None else "",
                        "state": state.get("state", "unknown")
                    })

    return findings, host_summary


def run_nmap_scan(target, scan_profile):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as temp_file:
        xml_output_path = temp_file.name

    command = get_nmap_command(scan_profile, target, xml_output_path)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            return {
                "target": target,
                "scan_profile": scan_profile,
                "port_scope": scan_profile,
                "scanner": "nmap-real",
                "findings": [],
                "host_summary": {},
                "error": result.stderr.strip() or "Nmap scan failed"
            }

        findings, host_summary = parse_nmap_xml(xml_output_path)

        return {
            "target": target,
            "scan_profile": scan_profile,
            "port_scope": scan_profile,
            "scanner": "nmap-real",
            "host_summary": host_summary,
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "scan_profile": scan_profile,
            "port_scope": scan_profile,
            "scanner": "nmap-real",
            "findings": [],
            "host_summary": {},
            "error": "Nmap scan timed out"
        }

    except FileNotFoundError:
        return {
            "target": target,
            "scan_profile": scan_profile,
            "port_scope": scan_profile,
            "scanner": "nmap-real",
            "findings": [],
            "host_summary": {},
            "error": "Nmap is not installed or not available in PATH"
        }

    finally:
        if os.path.exists(xml_output_path):
            os.remove(xml_output_path)