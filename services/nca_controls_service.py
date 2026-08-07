class NCAControlsService:
    def get_all_controls(self):
        return [
            {
                "control_id": "1-1",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Strategy",
                "assessment_type": "Manual",
                "description": "Requires review of cybersecurity strategy documentation, approval, execution, and periodic review."
            },
            {
                "control_id": "1-2",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Management",
                "assessment_type": "Manual",
                "description": "Requires review of cybersecurity governance structure, management support, and program oversight."
            },
            {
                "control_id": "1-3",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Policies and Procedures",
                "assessment_type": "Manual",
                "description": "Requires review of documented cybersecurity policies, procedures, approval, communication, and periodic updates."
            },
            {
                "control_id": "1-4",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Roles and Responsibilities",
                "assessment_type": "Manual",
                "description": "Requires review of assigned cybersecurity roles, responsibilities, segregation of duties, and accountability."
            },
            {
                "control_id": "1-5",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Risk Management",
                "assessment_type": "Hybrid",
                "description": "Can use technical findings as risk inputs, but requires manual risk assessment and risk treatment review."
            },
            {
                "control_id": "1-6",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity in Information and Technology Project Management",
                "assessment_type": "Manual",
                "description": "Requires review of cybersecurity integration in IT project lifecycle and change management."
            },
            {
                "control_id": "1-7",
                "domain": "Cybersecurity Governance",
                "control_name": "Compliance with Cybersecurity Standards, Laws and Regulations",
                "assessment_type": "Manual",
                "description": "Requires review of applicable cybersecurity regulatory requirements and compliance evidence."
            },
            {
                "control_id": "1-8",
                "domain": "Cybersecurity Governance",
                "control_name": "Periodical Cybersecurity Review and Audit",
                "assessment_type": "Manual",
                "description": "Requires review of audit plans, assessment results, and periodic review records."
            },
            {
                "control_id": "1-9",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity in Human Resources",
                "assessment_type": "Manual",
                "description": "Requires review of HR-related cybersecurity requirements before, during, and after employment."
            },
            {
                "control_id": "1-10",
                "domain": "Cybersecurity Governance",
                "control_name": "Cybersecurity Awareness and Training Program",
                "assessment_type": "Manual",
                "description": "Requires review of cybersecurity awareness and training program evidence."
            },
            {
                "control_id": "2-1",
                "domain": "Cybersecurity Defense",
                "control_name": "Asset Management",
                "assessment_type": "Hybrid",
                "description": "Can be partially assessed using asset discovery, but requires asset inventory validation."
            },
            {
                "control_id": "2-2",
                "domain": "Cybersecurity Defense",
                "control_name": "Identity and Access Management",
                "assessment_type": "Hybrid",
                "description": "Technical scans can detect exposed administrative services, but full IAM review is manual."
            },
            {
                "control_id": "2-3",
                "domain": "Cybersecurity Defense",
                "control_name": "Information Systems and Information Processing Facilities Protection",
                "assessment_type": "Hybrid",
                "description": "Technical scans can identify exposed systems and services; physical and configuration evidence may require manual review."
            },
            {
                "control_id": "2-4",
                "domain": "Cybersecurity Defense",
                "control_name": "Email Protection",
                "assessment_type": "Hybrid",
                "description": "Can be partially assessed when email services are detected, but requires mail security configuration review."
            },
            {
                "control_id": "2-5",
                "domain": "Cybersecurity Defense",
                "control_name": "Network Security Management",
                "assessment_type": "Technical",
                "description": "Can be assessed using open ports, exposed services, network protocols, and service exposure findings."
            },
            {
                "control_id": "2-6",
                "domain": "Cybersecurity Defense",
                "control_name": "Mobile Devices Security",
                "assessment_type": "Manual",
                "description": "Requires review of mobile device management, mobile access, and endpoint policy evidence."
            },
            {
                "control_id": "2-7",
                "domain": "Cybersecurity Defense",
                "control_name": "Data and Information Protection",
                "assessment_type": "Hybrid",
                "description": "Technical scans may identify exposed databases or plaintext services, but full data classification review is manual."
            },
            {
                "control_id": "2-8",
                "domain": "Cybersecurity Defense",
                "control_name": "Cryptography",
                "assessment_type": "Technical",
                "description": "Can be assessed using SSL/TLS checks, HTTPS configuration, certificates, weak cipher detection, and encryption posture."
            },
            {
                "control_id": "2-9",
                "domain": "Cybersecurity Defense",
                "control_name": "Backup and Recovery Management",
                "assessment_type": "Manual",
                "description": "Requires review of backup policies, recovery tests, retention, and restoration evidence."
            },
            {
                "control_id": "2-10",
                "domain": "Cybersecurity Defense",
                "control_name": "Vulnerability Management",
                "assessment_type": "Technical",
                "description": "Can be assessed using CVEs, vulnerability scan results, OpenVAS findings, and patching recommendations."
            },
            {
                "control_id": "2-11",
                "domain": "Cybersecurity Defense",
                "control_name": "Penetration Testing",
                "assessment_type": "Hybrid",
                "description": "Technical findings support penetration testing scope, but formal penetration testing evidence is manual."
            },
            {
                "control_id": "2-12",
                "domain": "Cybersecurity Defense",
                "control_name": "Cybersecurity Event Logs and Monitoring Management",
                "assessment_type": "Manual",
                "description": "Requires review of log collection, retention, monitoring, SIEM, and alerting evidence."
            },
            {
                "control_id": "2-13",
                "domain": "Cybersecurity Defense",
                "control_name": "Cybersecurity Incident and Threat Management",
                "assessment_type": "Manual",
                "description": "Requires review of incident response processes, threat handling, escalation, and records."
            },
            {
                "control_id": "2-14",
                "domain": "Cybersecurity Defense",
                "control_name": "Physical Security",
                "assessment_type": "Manual",
                "description": "Requires physical security review and cannot be assessed through network scanning alone."
            },
            {
                "control_id": "2-15",
                "domain": "Cybersecurity Defense",
                "control_name": "Web Application Security",
                "assessment_type": "Technical",
                "description": "Can be assessed using web technology detection, exposed web services, TLS posture, and web-related findings."
            },
            {
                "control_id": "3-1",
                "domain": "Cybersecurity Resilience",
                "control_name": "Cybersecurity Resilience Aspects of Business Continuity Management",
                "assessment_type": "Manual",
                "description": "Requires review of business continuity, disaster recovery, and cybersecurity resilience evidence."
            },
            {
                "control_id": "4-1",
                "domain": "Third-Party and Cloud Computing Cybersecurity",
                "control_name": "Third-Party Cybersecurity",
                "assessment_type": "Manual",
                "description": "Requires review of third-party cybersecurity requirements, contracts, SLAs, and supplier risk management."
            },
            {
                "control_id": "4-2",
                "domain": "Third-Party and Cloud Computing Cybersecurity",
                "control_name": "Cloud Computing and Hosting Cybersecurity",
                "assessment_type": "Hybrid",
                "description": "Can be partially assessed if cloud-hosted exposure is detected, but full cloud governance review is manual."
            }
        ]

    def build_coverage_matrix(self, compliance_gaps):
        controls = self.get_all_controls()
        controls_by_id = {control["control_id"]: control for control in controls}

        mapped_control_ids = []

        for gap in compliance_gaps:
            raw_controls = gap.get("nca_control", "")

            for control_id in str(raw_controls).split(","):
                control_id = control_id.strip()

                if control_id and control_id not in mapped_control_ids:
                    mapped_control_ids.append(control_id)

        coverage = []

        for control_id in mapped_control_ids:
            control = controls_by_id.get(control_id)

            if not control:
                continue

            coverage.append({
                "control_id": control["control_id"],
                "domain": control["domain"],
                "control_name": control["control_name"],
                "assessment_type": control["assessment_type"],
                "status": "Mapped Finding",
                "description": control["description"]
            })

        return coverage