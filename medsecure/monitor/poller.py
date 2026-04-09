"""Session status poller with state persistence.

Coordinates between the session manager and state store to
track remediation progress and update finding statuses.
"""

from __future__ import annotations

import logging

from medsecure.models import FindingStatus, RemediationSession, SecurityFinding
from medsecure.monitor.state_store import StateStore

logger = logging.getLogger(__name__)

# Map Devin session status to finding status
_SESSION_TO_FINDING: dict[str, FindingStatus] = {
    "running": FindingStatus.RUNNING,
    "exit": FindingStatus.COMPLETED,
    "error": FindingStatus.FAILED,
    "suspended": FindingStatus.NEEDS_REVIEW,
}


def sync_session_results(
    sessions: list[RemediationSession],
    findings: list[SecurityFinding],
    store: StateStore,
) -> None:
    """Synchronize session results back to findings and persist state.

    After sessions complete, this function:
    1. Updates finding statuses based on session outcomes
    2. Attaches PR URLs to findings
    3. Persists everything to the state store

    Args:
        sessions: Completed/updated remediation sessions.
        findings: The original findings that were dispatched.
        store: State store for persistence.
    """
    # Build a lookup from finding_id to finding
    finding_map = {f.finding_id: f for f in findings}

    for session in sessions:
        new_finding_status = _SESSION_TO_FINDING.get(session.status, FindingStatus.RUNNING)

        for finding_id in session.finding_ids:
            finding = finding_map.get(finding_id)
            if finding is None:
                continue

            finding.status = new_finding_status
            finding.session_id = session.session_id

            if session.pr_url:
                finding.pr_url = session.pr_url

            # Persist finding update
            store.update_finding_status(
                finding_id,
                new_finding_status,
                session_id=session.session_id,
                pr_url=session.pr_url,
            )

        # Persist session
        store.save_session(session)

    logger.info(
        "Synced %d sessions -> %d findings updated",
        len(sessions),
        sum(len(s.finding_ids) for s in sessions),
    )


def get_remediation_stats(findings: list[SecurityFinding]) -> dict[str, int]:
    """Calculate remediation statistics from findings.

    Args:
        findings: List of all tracked findings.

    Returns:
        Dictionary with counts by status.
    """
    stats: dict[str, int] = {
        "total": len(findings),
        "pending": 0,
        "dispatched": 0,
        "running": 0,
        "completed": 0,
        "failed": 0,
        "needs_review": 0,
    }

    for finding in findings:
        status_key = finding.status.value
        if status_key in stats:
            stats[status_key] += 1

    return stats
