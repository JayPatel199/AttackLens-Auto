import os, json, requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")
WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")

EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "clean": "✅", "unknown": "⚪"}

def send_slack_alert(decision):
    emoji = EMOJI.get(decision["severity"], "⚪")
    flag = "Auto-approved" if decision["auto_approved"] else "Needs analyst review"
    text = (
        f"{emoji} *{decision['severity'].upper()}* — {decision['type']} `{decision['indicator']}`\n"
        f"*Risk score:* {decision['risk_score']}\n"
        f"*Action:* {decision['action_decided']}\n"
        f"*Status:* {flag} ({decision['status']})"
    )
    r = requests.post(WEBHOOK, json={"text": text}, timeout=10)
    return r.status_code

if __name__ == "__main__":
    with open("results/response_actions.json") as f:
        decisions = json.load(f)

    # Only alert on things worth a human seeing: medium severity and above
    alertable = [d for d in decisions if d["severity"] in ("critical", "high", "medium")]

    if not alertable:
        print("Nothing above medium severity, no alerts sent.")
    for d in alertable:
        status = send_slack_alert(d)
        print(f"Sent alert for {d['indicator']} (Slack response: {status})")
