def map_finding_to_control(service_name):
    matrix = {
        "ftp": {
            "nca_control": "CS-1.3.1 - Secure Protocols",
            "risk_level": "High",
            "deduction": 10
        },
        "http": {
            "nca_control": "CS-1.3.1 - Secure Protocols",
            "risk_level": "High",
            "deduction": 10
        },
        "telnet": {
            "nca_control": "CS-1.3.1 - Secure Protocols",
            "risk_level": "Critical",
            "deduction": 15
        },
        "rdp": {
            "nca_control": "CS-2.2.2 - Secure Remote Access",
            "risk_level": "High",
            "deduction": 10
        },
        "ssh": {
            "nca_control": "CS-2.2.1 - Administrative Access Control",
            "risk_level": "Medium",
            "deduction": 5
        }
    }

    default_mapping = {
        "nca_control": "CS-0.0.0 - General Security Review",
        "risk_level": "Low",
        "deduction": 2
    }

    return matrix.get(service_name.lower(), default_mapping)