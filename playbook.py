import json
from datetime import datetime, timezone

def decide_action(entry):
    """
    This is the 'playbook' logic: given a severity, decide what a SOC
    would do. In a real SOAR tool this step would call a firewall API,
    an EDR API, or an identity provider API. Here we log the decision.
    """
    severity = entry["severity"]
    ioc_type = entry["type"]
    value = entry["value"]

    if severity == "critical":
        if ioc_type == "ip":
            action = f"BLOCK IP {value} at perimeter firewall"
        else:
            action = f"QUARANTINE file with hash {value} on all endpoints"
        auto_approved = True
    elif severity == "high":
        action = f"FLAG {ioc_type} {value} for analyst review within 1 hour"
        auto_approved = False
    elif severity == "medium":
        action = f"ADD {ioc_type} {value} to watchlist, monitor for 7 days"
        auto_approved = True
    elif severity == "low":
        action = f"LOG {ioc_type} {value}, no action required"
        auto_approved = True
    else:
        action = f"No action, {value} is clean"
        auto_approved = True

    return {
        "indicator": value,
        "type": ioc_type,
        "severity": severity,
        "risk_score": entry["risk_score"],
        "action_decided": action,
        "auto_approved": auto_approved,
        "status": "SIMULATED - not executed against real infrastructure",
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }

if __name__ == "__main__":
    with open("results/enriched_findings.json") as f:
        findings = json.load(f)

    decisions = [decide_action(e) for e in findings]

    with open("results/response_actions.json", "w") as f:
        json.dump(decisions, f, indent=2)

    print(f"{len(decisions)} response decisions made:\n")
    for d in decisions:
        flag = "AUTO" if d["auto_approved"] else "NEEDS REVIEW"
        print(f"  [{d['severity'].upper():8}] [{flag:12}] {d['action_decided']}")
