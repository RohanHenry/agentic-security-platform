class RiskAssessmentAgent:
    """
    Agent 3:
    Combines log analysis and threat intelligence to calculate final risk.
    """

    def run(self, log_analysis: dict, threat_intelligence: dict):
        risk_score = 0
        risk_level = "Low"
        reasons = []

        analysis_text = str(log_analysis).lower()

        if "failed_login" in analysis_text:
            risk_score += 25
            reasons.append("Failed login activity detected")

        if "privilege_escalation" in analysis_text:
            risk_score += 40
            reasons.append("Privilege escalation activity detected")

        if "suspicious_file_access" in analysis_text:
            risk_score += 35
            reasons.append("Suspicious file access detected")

        threat_count = threat_intelligence.get("output", {}).get("threat_count", 0)

        if threat_count >= 2:
            risk_score += 10
            reasons.append("Multiple threat intelligence matches found")

        if risk_score >= 75:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        recommendations = self.generate_recommendations(risk_level, analysis_text)

        return {
            "agent_name": "Risk Assessment Agent",
            "task": "Calculate overall incident risk",
            "status": "completed",
            "output": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_reasons": reasons,
                "recommendations": recommendations
            }
        }

    def generate_recommendations(self, risk_level: str, analysis_text: str):
        recommendations = []

        if "failed_login" in analysis_text:
            recommendations.append("Review authentication logs and check for brute-force attempts.")
            recommendations.append("Temporarily lock accounts with repeated failed login attempts.")

        if "privilege_escalation" in analysis_text:
            recommendations.append("Investigate the user or process involved in privilege escalation.")
            recommendations.append("Review admin role assignments and permission changes.")

        if "suspicious_file_access" in analysis_text:
            recommendations.append("Check whether sensitive files were accessed without authorization.")
            recommendations.append("Review file access permissions and audit logs.")

        if risk_level in ["High", "Critical"]:
            recommendations.append("Escalate this incident to the security operations team.")
            recommendations.append("Preserve logs and evidence for further investigation.")

        if not recommendations:
            recommendations.append("Continue monitoring. No immediate action required.")

        return recommendations