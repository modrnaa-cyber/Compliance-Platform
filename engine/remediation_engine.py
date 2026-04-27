def get_remediation(service_name):
    remediation_map = {
        "ftp": "Disable FTP if not required, or replace it with SFTP/FTPS and enforce encrypted transfer.",
        "http": "Redirect HTTP to HTTPS, enforce TLS, and disable insecure plaintext web access.",
        "telnet": "Disable Telnet immediately and replace it with SSH for secure administrative access.",
        "rdp": "Restrict RDP exposure, enforce MFA, limit source IPs, and harden remote access settings.",
        "ssh": "Restrict SSH access to authorized administrators only, enforce key-based authentication, and disable weak configurations."
    }

    return remediation_map.get(
        service_name.lower(),
        "Review the service configuration, validate business need, and apply hardening according to organizational security policy."
    )