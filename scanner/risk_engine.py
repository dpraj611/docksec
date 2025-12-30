def calculate_risk(findings):
    """
    Assigns risk scores and produces summary.
    """

    severity_scores = {
        "CRITICAL": 9,
        "HIGH": 7,
        "MEDIUM": 5,
        "LOW": 3
    }

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    total_score = 0

    for f in findings:
        sev = f["severity"]
        score = severity_scores.get(sev, 0)
        f["risk_score"] = score

        if sev in summary:
            summary[sev] += 1

        total_score += score

    overall_risk = "LOW"
    if summary["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif summary["HIGH"] > 0:
        overall_risk = "HIGH"
    elif summary["MEDIUM"] > 0:
        overall_risk = "MEDIUM"

    return {
        "summary": summary,
        "total_score": total_score,
        "overall_risk": overall_risk,
        "findings": findings
    }
