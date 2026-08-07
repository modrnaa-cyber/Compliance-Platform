class CorrelationService:
    def merge_findings(self, internal_findings, nessus_findings):
        merged = {}

        for finding in internal_findings + nessus_findings:
            key = self._dedup_key(finding)

            if key not in merged:
                merged[key] = finding
                continue

            existing = merged[key]
            existing["source"] = sorted(list(set(existing["source"] + finding["source"])))
            existing["deduction"] = max(existing["deduction"], finding["deduction"])
            existing["severity"] = self._higher_severity(existing["severity"], finding["severity"])

            existing_cve = set(existing.get("cve", []))
            new_cve = set(finding.get("cve", []))
            existing["cve"] = sorted(list(existing_cve.union(new_cve)))

            if not existing.get("plugin_id") and finding.get("plugin_id"):
                existing["plugin_id"] = finding["plugin_id"]

        return list(merged.values())

    def _dedup_key(self, finding):
        asset = finding.get("asset", {})
        ip = asset.get("ip")
        port = asset.get("port")
        service = str(asset.get("service", "")).lower()
        return f"{ip}|{port}|{service}"

    def _higher_severity(self, a, b):
        order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return a if order.get(a, 1) >= order.get(b, 1) else b