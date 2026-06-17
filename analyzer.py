from collections import Counter
from typing import List, Dict


SUSPICIOUS_KEYWORDS = [
    "FAILED_LOGIN",
    "privilege_escalation",
    "suspicious_file_access",
    "malware",
    "unauthorized",
    "bruteforce",
]


def analyze_logs(logs: List[str]) -> Dict:
    suspicious_events = []
    ip_counter = Counter()
    risk_score = 0

    for line in logs:
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in line.lower():
                suspicious_events.append(line)
                risk_score += 20

        if "ip=" in line:
            ip = line.split("ip=")[-1].split()[0]
            ip_counter[ip] += 1

    repeated_ips = {
        ip: count for ip, count in ip_counter.items() if count >= 3
    }

    if repeated_ips:
        risk_score += 25

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        severity = "High"
    elif risk_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "severity": severity,
        "risk_score": risk_score,
        "suspicious_events": suspicious_events,
        "repeated_ips": repeated_ips,
        "summary": generate_summary(severity, suspicious_events, repeated_ips),
        "recommendations": generate_recommendations(severity, repeated_ips),
    }


def generate_summary(severity, suspicious_events, repeated_ips):
    if not suspicious_events:
        return "No major suspicious activity was detected in the uploaded logs."

    return (
        f"The system detected {len(suspicious_events)} suspicious security events. "
        f"Repeated activity was found from IP addresses: {list(repeated_ips.keys())}. "
        f"The incident severity is classified as {severity}."
    )


def generate_recommendations(severity, repeated_ips):
    recommendations = []

    if repeated_ips:
        recommendations.append("Block or rate-limit repeated suspicious IP addresses.")
        recommendations.append("Review authentication logs for brute-force login attempts.")

    if severity == "High":
        recommendations.append("Immediately rotate affected credentials.")
        recommendations.append("Review privileged account activity.")
        recommendations.append("Run endpoint malware and integrity checks.")
    elif severity == "Medium":
        recommendations.append("Monitor affected users and IP addresses.")
        recommendations.append("Enable stricter alerting for repeated failed logins.")
    else:
        recommendations.append("Continue normal monitoring.")

    return recommendations