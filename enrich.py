import os, time, json, csv
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests

load_dotenv(dotenv_path=".env")
VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

os.makedirs("results", exist_ok=True)

def check_ip_abuseipdb(ip):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                          params={"ipAddress": ip, "maxAgeInDays": 90},
                          headers={"Key": ABUSE_KEY, "Accept": "application/json"}, timeout=15)
        if r.status_code == 200:
            d = r.json()["data"]
            return {"abuse_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode"), "isp": d.get("isp"),
                    "total_reports": d.get("totalReports", 0), "is_tor": d.get("isTor", False)}
        return {"error": f"AbuseIPDB status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_ip_virustotal(ip):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                          headers={"x-apikey": VT_KEY}, timeout=15)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)}
        return {"error": f"VirusTotal status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_hash_virustotal(file_hash):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                          headers={"x-apikey": VT_KEY}, timeout=15)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "type_description": attrs.get("type_description"),
                    "names": attrs.get("names", [])[:3]}
        elif r.status_code == 404:
            return {"not_found": True}
        return {"error": f"VirusTotal status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def score_and_label(vt, abuse=None):
    malicious = vt.get("malicious", 0) if vt else 0
    suspicious = vt.get("suspicious", 0) if vt else 0
    abuse_score = abuse.get("abuse_score", 0) if abuse else 0

    score = (malicious * 10) + (suspicious * 5) + abuse_score
    if score >= 50:
        return score, "critical"
    elif score >= 20:
        return score, "high"
    elif score >= 5:
        return score, "medium"
    elif score > 0:
        return score, "low"
    return score, "clean"

results = []
with open("indicators.csv") as f:
    reader = csv.DictReader(f)
    rows = list(reader)

for row in rows:
    ioc_type, value, note = row["type"], row["value"], row.get("note", "")
    print(f"Checking {ioc_type}: {value} ...")
    entry = {"type": ioc_type, "value": value, "note": note,
              "checked_at": datetime.now(timezone.utc).isoformat()}

    if ioc_type == "ip":
        vt = check_ip_virustotal(value)
        abuse = check_ip_abuseipdb(value)
        entry["virustotal"] = vt
        entry["abuseipdb"] = abuse
        score, label = score_and_label(vt, abuse)
    elif ioc_type == "hash":
        vt = check_hash_virustotal(value)
        entry["virustotal"] = vt
        score, label = score_and_label(vt)
    else:
        entry["error"] = "Unknown indicator type"
        score, label = 0, "unknown"

    entry["risk_score"] = score
    entry["severity"] = label
    results.append(entry)
    print(f"  -> severity: {label} (score {score})")
    time.sleep(16)  # VirusTotal free tier allows 4 requests/minute

with open("results/enriched_findings.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\nDone. {len(results)} indicators checked. Saved to results/enriched_findings.json")
