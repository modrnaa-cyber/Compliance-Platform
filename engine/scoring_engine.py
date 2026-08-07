from datetime import datetime


def get_posture_label(score):
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Moderate Risk"
    if score >= 25:
        return "High Risk"
    return "Critical Risk"


def calculate_compliance_score(mapped_findings):
    baseline_score = 100
    total_deduction = sum(item["deduction"] for item in mapped_findings)
    final_score = max(0, baseline_score - total_deduction)

    severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in mapped_findings:
        risk = item.get("risk_level", "Low")
        if risk in severity_summary:
            severity_summary[risk] += 1

    return {
        "baseline_score": baseline_score,
        "total_deduction": total_deduction,
        "final_score": final_score,
        "posture": get_posture_label(final_score),
        "severity_summary": severity_summary,
        "assessed_at": datetime.now().isoformat()
    }
