class ThreatIntelligenceAgent:
    """
    Agent 2:
    Takes detected log findings and enriches them with basic threat intelligence.
    This is a simple local threat intelligence system for beginner-friendly implementation.
    """

    def run(self, log_analysis: dict):
        threat_matches = []

        analysis_text = str(log_analysis).lower()

        if "failed_login" in analysis_text:
            threat_matches.append({
                "indicator": "FAILED_LOGIN",
                "threat_type": "Brute Force Attempt",
                "description": "Multiple failed login attempts may indicate password guessing or credential stuffing.",
                "mitre_attack_mapping": "T1110 - Brute Force"
            })

        if "privilege_escalation" in analysis_text:
            threat_matches.append({
                "indicator": "privilege_escalation",
                "threat_type": "Privilege Escalation",
                "description": "A user or process may be attempting to gain higher-level permissions.",
                "mitre_attack_mapping": "T1068 - Exploitation for Privilege Escalation"
            })

        if "suspicious_file_access" in analysis_text:
            threat_matches.append({
                "indicator": "suspicious_file_access",
                "threat_type": "Sensitive File Access",
                "description": "Access to sensitive files may indicate reconnaissance or data theft activity.",
                "mitre_attack_mapping": "T1005 - Data from Local System"
            })

        real_threat_count = len(threat_matches)

        if not threat_matches:
            threat_matches.append({
                "indicator": "none",
                "threat_type": "No Known Threat Match",
                "description": "No suspicious indicator matched the local threat intelligence rules.",
                "mitre_attack_mapping": "N/A"
            })

        return {
            "agent_name": "Threat Intelligence Agent",
            "task": "Enrich detected findings with threat intelligence",
            "status": "completed",
            "output": {
                "threat_matches": threat_matches,
                "threat_count": real_threat_count
            }
        }