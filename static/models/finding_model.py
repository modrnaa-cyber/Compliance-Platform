# models/finding_model.py
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    title: str
    description: str = ""
    source: str = "unknown"
    plugin_id: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    cvss: float = 0.0
    severity: str = "Low"
    risk_level: str = "Low"
    protocol: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    state: Optional[str] = None
    evidence: Dict = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    internet_exposed: bool = False
    asset_criticality: str = "medium"
    priority_score: float = 0.0
    nca_control: Optional[str] = None
    deduction: float = 0.0
    status: str = "open"

    def to_dict(self):
        return asdict(self)