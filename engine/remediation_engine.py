def get_remediation(service_name):
    remediation_map = {
        "ftp": "Disable FTP if not required, or replace it with SFTP/FTPS and enforce encrypted transfer.",
        "http": "Redirect HTTP to HTTPS, enforce TLS, and disable insecure plaintext web access.",
        "telnet": "Disable Telnet immediately and replace it with SSH for secure administrative access.",
        "rdp": "Restrict RDP exposure, enforce MFA, limit source IPs, and harden remote access settings.",
        "ssh": "Restrict SSH access to authorized administrators only, enforce key-based authentication, and disable weak configurations.",
        "https": "Verify TLS version and cipher strength. Disable TLS 1.0/1.1 and weak cipher suites.",
        "smtp": "Enforce SMTP authentication and TLS encryption for mail relay.",
        "dns": "Restrict DNS zone transfers, enable DNSSEC, and harden resolver configuration.",
        "smb": "Restrict SMB exposure to internal networks, disable SMBv1, and enforce signing.",
        "netbios": "Disable NetBIOS over TCP/IP if not required for legacy applications.",
        "mysql": "Restrict MySQL to internal access only, enforce authentication, and disable remote root login.",
        "postgres": "Restrict PostgreSQL to internal access, enforce pg_hba.conf rules and SSL connections.",
        "vnc": "Disable VNC or tunnel through encrypted VPN. Enforce strong authentication.",
        "snmp": "Disable SNMPv1/v2 community strings, enforce SNMPv3 with authentication and encryption."
    }

    return remediation_map.get(
        service_name.lower(),
        "Review the service configuration, validate business need, and apply hardening according to organizational security policy."
    )
