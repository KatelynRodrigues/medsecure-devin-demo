"""REST API routes for the MedSecure interactive web dashboard.

Provides endpoints for the full remediation workflow:
  CodeQL findings -> Triage -> Fix -> PR Review -> Merge -> Rescan
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from medsecure.web.state import pipeline_state

router = APIRouter(tags=["dashboard"])


class CommentBody(BaseModel):
    """Request body for PR comments."""

    comment: str


# ------------------------------------------------------------------
# Data endpoints
# ------------------------------------------------------------------

@router.get("/summary")
async def get_summary() -> dict:
    """Get overall dashboard metrics."""
    pipeline_state.initialize()
    return pipeline_state.get_summary()


@router.get("/findings")
async def get_findings(
    state: str | None = None,
    severity: str | None = None,
    cwe: str | None = None,
) -> dict:
    """Get all findings, optionally filtered."""
    pipeline_state.initialize()
    all_findings = pipeline_state.get_all_findings()

    if state:
        all_findings = [
            f for f in all_findings if f["workflow_state"] == state
        ]
    if severity:
        all_findings = [
            f for f in all_findings if f["severity"] == severity
        ]
    if cwe:
        all_findings = [f for f in all_findings if f["cwe_id"] == cwe]

    return {"findings": all_findings, "total": len(all_findings)}


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict:
    """Get a single finding by ID."""
    pipeline_state.initialize()
    wf = pipeline_state.findings.get(finding_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Finding not found")
    return wf.to_dict()


@router.get("/prs")
async def get_prs() -> dict:
    """Get all findings with PRs ready for review."""
    pipeline_state.initialize()
    prs = pipeline_state.get_prs_for_review()
    return {"prs": prs, "total": len(prs)}


@router.get("/notifications")
async def get_notifications(unread_only: bool = False) -> dict:
    """Get notifications."""
    pipeline_state.initialize()
    notifs = pipeline_state.get_notifications(unread_only=unread_only)
    return {"notifications": notifs, "total": len(notifs)}


@router.get("/activity")
async def get_activity() -> dict:
    """Get activity log."""
    pipeline_state.initialize()
    return {
        "log": list(reversed(pipeline_state.activity_log)),
        "total": len(pipeline_state.activity_log),
    }


# ------------------------------------------------------------------
# Action endpoints (user-triggered workflow steps)
# ------------------------------------------------------------------

@router.post("/findings/{finding_id}/triage")
async def triage_finding(finding_id: str) -> dict:
    """Trigger Devin triage agent for a finding."""
    pipeline_state.initialize()
    result = pipeline_state.triage_finding(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/triage-all")
async def triage_all() -> dict:
    """Triage all detected findings at once."""
    pipeline_state.initialize()
    results = pipeline_state.triage_all()
    return {"triaged": len(results), "findings": results}


@router.post("/findings/{finding_id}/fix")
async def fix_finding(finding_id: str) -> dict:
    """Approve Devin to create a fix PR for this finding."""
    pipeline_state.initialize()
    result = pipeline_state.fix_finding(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/{finding_id}/comment")
async def comment_on_pr(finding_id: str, body: CommentBody) -> dict:
    """Post a comment on a finding's PR (Devin will respond)."""
    pipeline_state.initialize()
    result = pipeline_state.comment_on_pr(finding_id, body.comment)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/{finding_id}/approve")
async def approve_pr(finding_id: str) -> dict:
    """Approve a PR for merge."""
    pipeline_state.initialize()
    result = pipeline_state.approve_pr(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/{finding_id}/merge")
async def merge_pr(finding_id: str) -> dict:
    """Merge a PR."""
    pipeline_state.initialize()
    result = pipeline_state.merge_pr(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/{finding_id}/rescan")
async def rescan_finding(finding_id: str) -> dict:
    """Run a verification rescan after merge."""
    pipeline_state.initialize()
    result = pipeline_state.rescan_finding(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/findings/{finding_id}/retry")
async def retry_finding(finding_id: str) -> dict:
    """Reset a failed finding to try again."""
    pipeline_state.initialize()
    result = pipeline_state.retry_finding(finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str) -> dict:
    """Mark a notification as read."""
    pipeline_state.mark_notification_read(notif_id)
    return {"status": "ok"}


@router.post("/notifications/read-all")
async def mark_all_read() -> dict:
    """Mark all notifications as read."""
    pipeline_state.mark_all_notifications_read()
    return {"status": "ok"}


@router.post("/reset")
async def reset_pipeline() -> dict:
    """Reset the entire pipeline state."""
    pipeline_state.findings = {}
    pipeline_state.activity_log = []
    pipeline_state.notifications = []
    pipeline_state._initialized = False
    pipeline_state.initialize()
    return {"status": "ok", "total_findings": len(pipeline_state.findings)}
