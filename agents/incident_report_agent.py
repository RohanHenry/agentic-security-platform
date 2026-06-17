from datetime import datetime


class IncidentReportAgent:
    """
    Agent 4:
    Creates a final human-readable incident investigation report.
    """

    def run(self, log_analysis: dict, threat_intelligence: dict, risk_assessment: dict):
        report = {
            "report_title": "Multi-Agent Threat Investigation Report",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": self.create_summary(risk_assessment),
            "log_analysis": log_analysis,
            "threat_intelligence": threat_intelligence,
            "risk_assessment": risk_assessment,
            "final_status": self.get_final_status(risk_assessment)
        }

        return {
            "agent_name": "Incident Report Agent",
            "task": "Generate final incident investigation report",
            "status": "completed",
            "output": report
        }

    def create_summary(self, risk_assessment: dict):
        output = risk_assessment.get("output", {})
        risk_level = output.get("risk_level", "Unknown")
        risk_score = output.get("risk_score", 0)

        return (
            f"The multi-agent investigation completed successfully. "
            f"The incident was assessed as {risk_level} risk with a score of {risk_score}."
        )

    def get_final_status(self, risk_assessment: dict):
        risk_level = risk_assessment.get("output", {}).get("risk_level", "Low")

        if risk_level in ["Critical", "High"]:
            return "Escalation Required"
        elif risk_level == "Medium":
            return "Needs Review"
        else:
            return "Monitoring Only"