from backend.risk_engine import analyze_risk

data = {
    "execution": {"status": "success"},
    "data": {
        "status": "ok",
        "issues": ["INFO: /some/non/existent/path does not exist"]
    }
}
print(analyze_risk(data))
