from fastapi import FastAPI, UploadFile, File
from analyzer import analyze_logs
from database import conn, cursor
from report_generator import generate_incident_report
from agents.orchestrator import MultiAgentThreatInvestigationSystem

app = FastAPI(
    title="Agentic Security Copilot",
    description="AI-powered security log analysis and incident reporting system",
    version="1.0.0"
)

multi_agent_system = MultiAgentThreatInvestigationSystem()

@app.get("/")
def home():
    return {
        "message": "Agentic Security Copilot API is running",
        "endpoints": ["/analyze", "/dashboard", "/health"]
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/dashboard")
def dashboard():
    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
    """)

    total_incidents = cursor.fetchone()[0]

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM incidents
        GROUP BY severity
    """)

    severity_breakdown = cursor.fetchall()

    return {
        "total_incidents": total_incidents,
        "severity_breakdown": severity_breakdown
    }


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    content = await file.read()
    logs = content.decode("utf-8").splitlines()

    result = analyze_logs(logs)
    report = generate_incident_report(file.filename, len(logs), result)

    cursor.execute(
        """
        INSERT INTO incidents
        (severity, risk_score, summary)
        VALUES (?, ?, ?)
        """,
        (
            result["severity"],
            result["risk_score"],
            result["summary"]
        )
    )

    conn.commit()

    return {
        "filename": file.filename,
        "total_logs": len(logs),
        "analysis": result,
        "incident_report": report
    }
@app.post("/multi-agent-investigate")
async def multi_agent_investigate(file: UploadFile = File(...)):
    contents = await file.read()
    log_text = contents.decode("utf-8")

    investigation_result = multi_agent_system.investigate(log_text)

    return investigation_result