def calculate_risk(findings):
    """
    Calculates risk summary and exposure score.
    """

    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    total_exposure = 0

    for f in findings:
        sev = f.get("severity", "LOW")
        weight = severity_weights.get(sev, 0)

        f["risk_score"] = weight
        summary[sev] += 1
        total_exposure += weight

    # --- Deployment gate (conservative) ---
    if summary["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif summary["HIGH"] >= 10:
        overall_risk = "CRITICAL"
    elif summary["HIGH"] > 0:
        overall_risk = "HIGH"
    elif summary["MEDIUM"] >= 20:
        overall_risk = "HIGH"
    elif summary["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    return {
        "summary": summary,
        "overall_risk": overall_risk,
        "total_exposure_score": total_exposure,
        "findings": findings
    }
