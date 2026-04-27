# models/asset_model.py
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict


@dataclass
class Asset:
    asset_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    operating_system: Optional[str] = None
    environment: str = "unknown"
    business_unit: str = "unknown"
    owner: str = "unassigned"
    asset_type: str = "server"
    internet_exposed: bool = False
    criticality: str = "medium"
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)