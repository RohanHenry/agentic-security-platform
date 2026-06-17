from agents.log_analyzer_agent import LogAnalyzerAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.risk_assessment_agent import RiskAssessmentAgent
from agents.incident_report_agent import IncidentReportAgent


class MultiAgentThreatInvestigationSystem:
    """
    Simple multi-agent orchestration system.

    Flow:
    1. Log Analyzer Agent analyzes raw logs.
    2. Threat Intelligence Agent enriches findings.
    3. Risk Assessment Agent calculates risk.
    4. Incident Report Agent creates final report.
    """

    def __init__(self):
        self.log_analyzer_agent = LogAnalyzerAgent()
        self.threat_intelligence_agent = ThreatIntelligenceAgent()
        self.risk_assessment_agent = RiskAssessmentAgent()
        self.incident_report_agent = IncidentReportAgent()

    def investigate(self, log_text: str):
        investigation_steps = []

        log_analysis = self.log_analyzer_agent.run(log_text)
        investigation_steps.append(log_analysis)

        threat_intelligence = self.threat_intelligence_agent.run(log_analysis)
        investigation_steps.append(threat_intelligence)

        risk_assessment = self.risk_assessment_agent.run(
            log_analysis,
            threat_intelligence
        )
        investigation_steps.append(risk_assessment)

        incident_report = self.incident_report_agent.run(
            log_analysis,
            threat_intelligence,
            risk_assessment
        )
        investigation_steps.append(incident_report)

        return {
            "project": "Multi-Agent Threat Investigation System",
            "architecture": "Sequential Multi-Agent Orchestration",
            "total_agents": 4,
            "status": "investigation_completed",
            "agent_flow": [
                "Log Analyzer Agent",
                "Threat Intelligence Agent",
                "Risk Assessment Agent",
                "Incident Report Agent"
            ],
            "investigation_steps": investigation_steps,
            "final_report": incident_report["output"]
        }