import json
import os

_controls_cache = None


def _load_controls():
    global _controls_cache
    if _controls_cache is not None:
        return _controls_cache

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    controls_path = os.path.join(base_dir, "data", "compliance_controls.json")

    try:
        with open(controls_path, "r", encoding="utf-8") as f:
            _controls_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _controls_cache = {
            "deduction_model": {"Critical": 15, "High": 10, "Medium": 5, "Low": 2},
            "service_rules": [],
            "default_rule": {
                "control_id": "NCA-GEN-01",
                "control_name": "General Security Review",
                "risk_level": "Low",
                "deduction": 2,
                "remediation": "Review service configuration and validate business need."
            }
        }

    return _controls_cache


def map_finding_to_control(service_name):
    controls = _load_controls()
    service_key = str(service_name).strip().lower()

    for rule in controls.get("service_rules", []):
        if rule["service"].lower() == service_key:
            return {
                "control_id": rule["control_id"],
                "control_name": rule["control_name"],
                "risk_level": rule["risk_level"],
                "deduction": rule["deduction"],
                "remediation": rule["remediation"]
            }

    default = controls.get("default_rule", {})
    return {
        "control_id": default.get("control_id", "NCA-GEN-01"),
        "control_name": default.get("control_name", "General Security Review"),
        "risk_level": default.get("risk_level", "Low"),
        "deduction": default.get("deduction", 2),
        "remediation": default.get("remediation", "Review service configuration and validate business need.")
    }


def get_deduction_for_severity(severity):
    controls = _load_controls()
    model = controls.get("deduction_model", {})
    return model.get(severity, 2)
