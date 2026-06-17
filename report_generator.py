from datetime import datetime


def generate_incident_report(filename, total_logs, analysis):
    report = {
        "report_title": "Agentic Security Copilot Incident Report",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source_file": filename,
        "total_logs_analyzed": total_logs,
        "severity": analysis["severity"],
        "risk_score": analysis["risk_score"],
        "executive_summary": analysis["summary"],
        "detected_events": analysis["suspicious_events"],
        "repeated_ips": analysis["repeated_ips"],
        "recommended_actions": analysis["recommendations"],
        "incident_classification": classify_incident(analysis),
    }

    return report


def classify_incident(analysis):
    events = " ".join(analysis["suspicious_events"]).lower()

    classifications = []

    if "failed_login" in events:
        classifications.append("Brute Force Authentication Attempt")

    if "privilege_escalation" in events:
        classifications.append("Privilege Escalation Attempt")

    if "suspicious_file_access" in events:
        classifications.append("Sensitive File Access")

    if not classifications:
        classifications.append("General Security Anomaly")

    return classifications