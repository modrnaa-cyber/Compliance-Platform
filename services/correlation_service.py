# services/correlation_service.py

from typing import List, Dict, Optional


class CorrelationService:
    def correlate(self, nmap_findings: List[Dict], nessus_findings: List[Dict]) -> List[Dict]:
        correlated = []
        consumed_nmap = set()

        for nessus_item in nessus_findings:
            match_index = self._find_matching_nmap_index(nessus_item, nmap_findings)

            if match_index is not None:
                nmap_item = nmap_findings[match_index]
                consumed_nmap.add(match_index)
                merged = self._merge_findings(nmap_item, nessus_item)
                correlated.append(merged)
            else:
                correlated.append(nessus_item)

        for index, nmap_item in enumerate(nmap_findings):
            if index not in consumed_nmap:
                correlated.append(nmap_item)

        return correlated

    def _find_matching_nmap_index(self, nessus_finding: Dict, nmap_findings: List[Dict]) -> Optional[int]:
        nessus_port = nessus_finding.get("port")
        nessus_protocol = (nessus_finding.get("protocol") or "").lower()
        nessus_service = (nessus_finding.get("service") or "").lower()

        for index, nmap_item in enumerate(nmap_findings):
            nmap_port = nmap_item.get("port")
            nmap_protocol = (nmap_item.get("protocol") or "").lower()
            nmap_service = (nmap_item.get("service") or "").lower()

            same_port = nmap_port == nessus_port
            same_protocol = nmap_protocol == nessus_protocol
            same_service = nmap_service == nessus_service

            if same_port and same_protocol:
                return index

            if same_port and same_service:
                return index

        return None

    def _merge_findings(self, nmap_item: Dict, nessus_item: Dict) -> Dict:
        merged = dict(nessus_item)

        merged["description"] = self._merge_text(
            nmap_item.get("description", ""),
            nessus_item.get("description", "")
        )

        merged["evidence"] = {
            "nmap": nmap_item.get("evidence", {}),
            "nessus": nessus_item.get("evidence", {})
        }

        if not merged.get("service"):
            merged["service"] = nmap_item.get("service")

        if not merged.get("state"):
            merged["state"] = nmap_item.get("state", "open")

        merged["internet_exposed"] = bool(
            nmap_item.get("internet_exposed", False) or
            nessus_item.get("internet_exposed", False)
        )

        merged["asset_criticality"] = (
            nessus_item.get("asset_criticality") or
            nmap_item.get("asset_criticality") or
            "medium"
        )

        merged["references"] = list(set(
            (nmap_item.get("references") or []) +
            (nessus_item.get("references") or [])
        ))

        return merged

    def _merge_text(self, text1: str, text2: str) -> str:
        text1 = (text1 or "").strip()
        text2 = (text2 or "").strip()

        if text1 and text2 and text1 != text2:
            return f"{text1}\n{text2}"

        return text1 or text2