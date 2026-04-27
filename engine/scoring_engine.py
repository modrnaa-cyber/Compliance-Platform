def calculate_compliance_score(mapped_findings):
    baseline_score = 100
    total_deduction = sum(item["deduction"] for item in mapped_findings)
    final_score = baseline_score - total_deduction

    if final_score < 0:
        final_score = 0

    severity_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for item in mapped_findings:
        risk = item["risk_level"]
        if risk in severity_summary:
            severity_summary[risk] += 1

    return {
        "baseline_score": baseline_score,
        "total_deduction": total_deduction,
        "final_score": final_score,
        "severity_summary": severity_summary
    }