"""REST API routes for the MedSecure web dashboard."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from medsecure.web.state import pipeline_state

router = APIRouter(tags=["dashboard"])


@router.get("/summary")
async def get_summary() -> dict:
    """Get overall pipeline summary with metrics."""
    pipeline_state.initialize()
    return pipeline_state.get_pipeline_summary()


@router.get("/findings")
async def get_findings(
    status: str | None = None,
    severity: str | None = None,
    cwe: str | None = None,
) -> dict:
    """Get all findings, optionally filtered."""
    pipeline_state.initialize()
    groups = pipeline_state.get_findings_by_status()

    # Flatten all findings
    all_findings = []
    for group_findings in groups.values():
        all_findings.extend(group_findings)

    # Apply filters
    if status:
        all_findings = [f for f in all_findings if f["status"] == status]
    if severity:
        all_findings = [f for f in all_findings if f["severity"] == severity]
    if cwe:
        all_findings = [f for f in all_findings if f["cwe_id"] == cwe]

    return {
        "findings": all_findings,
        "total": len(all_findings),
        "groups": {k: len(v) for k, v in groups.items()},
    }


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict:
    """Get a single finding by ID."""
    pipeline_state.initialize()
    for f in pipeline_state.findings:
        if f.finding_id == finding_id:
            session = next(
                (s for s in pipeline_state.sessions if s.session_id == f.session_id),
                None,
            )
            return {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "cwe_id": f.cwe_id,
                "severity": f.severity.value,
                "message": f.message,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "code_snippet": f.code_snippet,
                "recommendation": f.recommendation,
                "status": f.status.value,
                "session_id": f.session_id,
                "pr_url": f.pr_url,
                "priority_label": f.priority_label,
                "session": {
                    "session_id": session.session_id,
                    "session_url": session.session_url,
                    "status": session.status,
                    "pr_url": session.pr_url,
                } if session else None,
            }
    raise HTTPException(status_code=404, detail="Finding not found")


@router.get("/sessions")
async def get_sessions() -> dict:
    """Get all Devin remediation sessions."""
    pipeline_state.initialize()
    return {
        "sessions": pipeline_state.get_sessions_data(),
        "total": len(pipeline_state.sessions),
    }


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> dict:
    """Get a single session by ID."""
    pipeline_state.initialize()
    for s in pipeline_state.sessions:
        if s.session_id == session_id:
            session_findings = [
                {
                    "finding_id": f.finding_id,
                    "rule_name": f.rule_name,
                    "cwe_id": f.cwe_id,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                }
                for f in pipeline_state.findings
                if f.finding_id in s.finding_ids
            ]
            return {
                "session_id": s.session_id,
                "session_url": s.session_url,
                "status": s.status,
                "status_detail": s.status_detail,
                "pr_url": s.pr_url,
                "pr_state": s.pr_state,
                "finding_count": len(s.finding_ids),
                "findings": session_findings,
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat(),
                "structured_output": s.structured_output,
            }
    raise HTTPException(status_code=404, detail="Session not found")


@router.get("/pipeline")
async def get_pipeline() -> dict:
    """Get pipeline execution log and phase info."""
    pipeline_state.initialize()
    return {
        "phase": pipeline_state.pipeline_phase,
        "log": pipeline_state.pipeline_log,
    }


@router.post("/pipeline/run")
async def run_pipeline() -> dict:
    """Re-run the demo pipeline."""
    pipeline_state._initialized = False
    pipeline_state.findings = []
    pipeline_state.sessions = []
    pipeline_state.scan_summary = None
    pipeline_state.report = None
    pipeline_state.pipeline_log = []
    pipeline_state.initialize()
    return {"status": "ok", "phase": pipeline_state.pipeline_phase}
