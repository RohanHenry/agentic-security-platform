from analyzer import analyze_logs


class LogAnalyzerAgent:
    """
    Agent 1:
    Reads raw security logs and detects suspicious activity.
    It reuses the existing analyzer.py logic from Project 1.
    """

    def run(self, log_text: str):
        analysis_result = analyze_logs(log_text)

        return {
            "agent_name": "Log Analyzer Agent",
            "task": "Analyze raw security logs and detect suspicious events",
            "status": "completed",
            "output": analysis_result
        }