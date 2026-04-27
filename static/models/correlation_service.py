# services/correlation_service.py
from typing import List, Dict


class CorrelationService:
    def correlate(self, nmap_findings: List[Dict], nessus_findings: List[Dict]) -> List[Dict]:
        correlated = []
        consumed_nmap = set()

        for nf in nessus_findings:
            matched_index = self._find_matching_nmap_index(nf, nmap_findings)

            if matched_index is not None:
                nmap_item = nmap_findings[matched_index]
                consumed_nmap.add(matched_index)

                merged = self._merge_findings(nmap_item, nf)
                correlated.append(merged)
            else:
                correlated.append(nf)

        for idx, nmap_item in enumerate(nmap_findings):
            if idx not in consumed_nmap:
                correlated.append(nmap_item)

        return correlated

    def _find_matching_nmap_index(self, nessus_finding: Dict, nmap_findings: List[Dict]):
        for idx, nmap_item in enumerate(nmap_findings):
            same_port = nmap_item.get("port") == nessus_finding.get("port")
            same_protocol = (nmap_item.get("protocol") or "").lower() == (nessus_finding.get("protocol") or "").lower()
            same_service = (nmap_item.get("service") or "").lower() == (nessus_finding.get("service") or "").lower()

            if same_port and same_protocol:
                return idx

            if same_port and same_service:
                return idx

        return None

    def _merge_findings(self, nmap_item: Dict, nessus_item: Dict):
        merged = dict(nessus_item)

        merged["evidence"] = {
            "nmap": nmap_item.get("evidence", {}),
            "nessus": nessus_item.get("evidence", {})
        }

        merged["description"] = self._merge_text(
            nmap_item.get("description", ""),
            nessus_item.get("description", "")
        )

        if not merged.get("service"):
            merged["service"] = nmap_item.get("service")

        if not merged.get("state"):
            merged["state"] = nmap_item.get("state", "open")

        merged["internet_exposed"] = nmap_item.get("internet_exposed", False) or nessus_item.get("internet_exposed", False)
        merged["asset_criticality"] = nessus_item.get("asset_criticality") or nmap_item.get("asset_criticality", "medium")

        merged["references"] = list(set((nmap_item.get("references") or []) + (nessus_item.get("references") or [])))

        return merged

    def _merge_text(self, text1: str, text2: str):
        text1 = (text1 or "").strip()
        text2 = (text2 or "").strip()

        if text1 and text2 and text1 != text2:
            return f"{text1}\n{text2}"
        return text1 or text2