def analyze_risk(raw):

    if raw.get("execution", {}).get("status") != "success":
        return {
            "risk_score": 0,
            "vulnerable": False,
            "issues": [],
            "error": "execution_failed"
        }

    data = raw.get("data", {})

    # Handle both formats
    issues = data.get("issues") or raw.get("issues") or []

    score = 0
    for issue in issues:
        upper_issue = issue.upper()
        if upper_issue.startswith("CRITICAL"):
            score += 4
        elif upper_issue.startswith("HIGH"):
            score += 3
        elif upper_issue.startswith("MEDIUM") or upper_issue.startswith("WARN"):
            score += 2
        elif upper_issue.startswith("LOW"):
            score += 1
        elif upper_issue.startswith("INFO"):
            score += 0

    return {
        "risk_score": min(score, 10),
        "vulnerable": score > 0,
        "issues": issues
    }
