"""Interactive pipeline state for the web dashboard.

Manages the full remediation workflow:
  CodeQL scan -> Triage -> Fix -> PR Review -> Merge -> Rescan

Each step requires user action to advance, simulating the real
Devin API workflow with mock data.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import UTC, datetime
from pathlib import Path

from medsecure.ingester.prioritizer import prioritize
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.models import FindingStatus, SecurityFinding, Severity
from medsecure.scanner.mock_scanner import generate_sarif

logger = logging.getLogger(__name__)


class FindingWorkflow:
    """Tracks a single finding through the interactive workflow."""

    def __init__(self, finding: SecurityFinding) -> None:
        self.finding = finding
        self.workflow_state: str = "detected"
        self.triage_session_id: str | None = None
        self.triage_result: dict | None = None
        self.fix_session_id: str | None = None
        self.fix_session_url: str | None = None
        self.pr_url: str | None = None
        self.pr_number: int | None = None
        self.pr_comments: list[dict] = []
        self.pr_title: str | None = None
        self.rescan_result: str | None = None
        self.notifications: list[dict] = []
        self.updated_at: datetime = datetime.now(UTC)

    def to_dict(self) -> dict:
        """Serialize to dictionary for API responses."""
        return {
            "finding_id": self.finding.finding_id,
            "rule_id": self.finding.rule_id,
            "rule_name": self.finding.rule_name,
            "cwe_id": self.finding.cwe_id,
            "severity": self.finding.severity.value,
            "message": self.finding.message,
            "file_path": self.finding.file_path,
            "start_line": self.finding.start_line,
            "end_line": self.finding.end_line,
            "code_snippet": self.finding.code_snippet,
            "recommendation": self.finding.recommendation,
            "priority_label": self.finding.priority_label,
            "workflow_state": self.workflow_state,
            "triage_session_id": self.triage_session_id,
            "triage_result": self.triage_result,
            "fix_session_id": self.fix_session_id,
            "fix_session_url": self.fix_session_url,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "pr_comments": self.pr_comments,
            "pr_title": self.pr_title,
            "rescan_result": self.rescan_result,
            "notifications": self.notifications,
            "updated_at": self.updated_at.isoformat(),
        }


class InteractivePipelineState:
    """Holds the interactive pipeline state for the web UI.

    Unlike the batch pipeline, this state advances step-by-step
    as the user triggers actions from the UI.
    """

    def __init__(self) -> None:
        self.findings: dict[str, FindingWorkflow] = {}
        self.activity_log: list[dict] = []
        self.notifications: list[dict] = []
        self._initialized = False

    def _log(
        self, event: str, message: str, finding_id: str | None = None,
    ) -> None:
        """Append an entry to the activity log."""
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            "message": message,
            "finding_id": finding_id,
        }
        self.activity_log.append(entry)

    def _notify(
        self,
        title: str,
        message: str,
        level: str = "info",
        finding_id: str | None = None,
    ) -> None:
        """Create a notification for the UI."""
        notif = {
            "id": uuid.uuid4().hex[:8],
            "timestamp": datetime.now(UTC).isoformat(),
            "title": title,
            "message": message,
            "level": level,
            "read": False,
            "finding_id": finding_id,
        }
        self.notifications.append(notif)
        if finding_id and finding_id in self.findings:
            self.findings[finding_id].notifications.append(notif)

    # ------------------------------------------------------------------
    # Step 1: Run CodeQL scan (auto on first load)
    # ------------------------------------------------------------------
    def initialize(self) -> None:
        """Run the mock CodeQL scan and populate findings."""
        if self._initialized:
            return

        out = Path("output")
        out.mkdir(parents=True, exist_ok=True)

        self._log("scan_start", "Starting CodeQL security scan...")
        sarif = generate_sarif(out / "web_scan.sarif")
        raw_findings = parse_sarif(sarif)
        prioritized = prioritize(raw_findings)

        for f in prioritized:
            wf = FindingWorkflow(f)
            self.findings[f.finding_id] = wf

        file_count = len({f.file_path for f in prioritized})
        self._log(
            "scan_complete",
            f"CodeQL scan complete: {len(prioritized)} vulnerabilities detected",
        )
        self._notify(
            "CodeQL Scan Complete",
            f"Found {len(prioritized)} security vulnerabilities across "
            f"{file_count} files. Review findings and trigger triage.",
            level="warning",
        )
        self._initialized = True

    # ------------------------------------------------------------------
    # Step 2: Triage a finding
    # ------------------------------------------------------------------
    def triage_finding(self, finding_id: str) -> dict:
        """Simulate Devin triage agent analysing a finding."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}

        wf.workflow_state = "triaging"
        wf.updated_at = datetime.now(UTC)
        session_id = f"devin-triage-{uuid.uuid4().hex[:12]}"
        wf.triage_session_id = session_id

        self._log(
            "triage_start",
            f"Devin triage agent started for {wf.finding.rule_name} "
            f"({wf.finding.cwe_id})",
            finding_id,
        )

        impact_map: dict[Severity, str] = {
            Severity.CRITICAL: "Critical - immediate exploitation risk, HIPAA violation",
            Severity.HIGH: "High - exploitable with moderate effort, data exposure risk",
            Severity.MEDIUM: "Medium - requires specific conditions to exploit",
            Severity.LOW: "Low - minimal direct security impact",
        }
        exploitability = random.choice(["High", "Medium", "Low"])
        data_exposure = random.choice([
            "PHI/PII data at risk",
            "Internal system data at risk",
            "Configuration data at risk",
            "No sensitive data directly exposed",
        ])

        wf.triage_result = {
            "session_id": session_id,
            "impact_assessment": impact_map[wf.finding.severity],
            "exploitability": exploitability,
            "data_exposure": data_exposure,
            "affected_component": wf.finding.file_path.split("/")[-1],
            "root_cause": wf.finding.message,
            "recommended_fix": wf.finding.recommendation,
            "estimated_effort": random.choice(["Low", "Medium", "High"]),
            "hipaa_relevance": (
                "Direct HIPAA impact - patient data handling"
                if wf.finding.severity in (Severity.CRITICAL, Severity.HIGH)
                else "Indirect - defense-in-depth measure"
            ),
        }

        wf.workflow_state = "triaged"
        wf.updated_at = datetime.now(UTC)

        fname = wf.finding.file_path.split("/")[-1]
        self._log(
            "triage_complete",
            f"Triage complete for {wf.finding.rule_name}: "
            f"exploitability={exploitability}",
            finding_id,
        )
        self._notify(
            "Triage Complete",
            f"{wf.finding.rule_name} ({wf.finding.cwe_id}) in "
            f"{fname} has been triaged. Ready for fix.",
            level="info",
            finding_id=finding_id,
        )
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Step 3: Fix a finding (creates a PR)
    # ------------------------------------------------------------------
    def fix_finding(self, finding_id: str) -> dict:
        """Simulate Devin creating a fix session and producing a PR."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}

        wf.workflow_state = "fixing"
        wf.updated_at = datetime.now(UTC)
        session_id = f"devin-fix-{uuid.uuid4().hex[:12]}"
        wf.fix_session_id = session_id
        wf.fix_session_url = f"https://app.devin.ai/sessions/{session_id}"

        self._log(
            "fix_start",
            f"Devin fix agent started for {wf.finding.rule_name}",
            finding_id,
        )

        pr_number = random.randint(10, 200)
        filename = wf.finding.file_path.split("/")[-1].replace(".py", "")
        wf.pr_number = pr_number
        wf.pr_url = (
            "https://github.com/KatelynRodrigues/medsecure-devin-demo"
            f"/pull/{pr_number}"
        )
        wf.pr_title = (
            f"fix(security): remediate {wf.finding.cwe_id} in {filename}"
        )

        wf.workflow_state = "in_pr"
        wf.updated_at = datetime.now(UTC)

        self._log(
            "pr_created",
            f"PR #{pr_number} created: {wf.pr_title}",
            finding_id,
        )
        self._notify(
            "PR Ready for Review",
            f"Devin created PR #{pr_number}: {wf.pr_title}. "
            "Review the changes and leave comments or approve.",
            level="success",
            finding_id=finding_id,
        )
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Step 4: Comment on PR
    # ------------------------------------------------------------------
    def comment_on_pr(self, finding_id: str, comment: str) -> dict:
        """Simulate a PR comment exchange with Devin."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}

        wf.pr_comments.append({
            "author": "you",
            "body": comment,
            "timestamp": datetime.now(UTC).isoformat(),
        })
        wf.workflow_state = "pr_commented"
        wf.updated_at = datetime.now(UTC)

        self._log(
            "pr_comment",
            f"Comment on PR #{wf.pr_number}: {comment[:80]}",
            finding_id,
        )

        responses = [
            "Good catch! I have updated the fix to address your feedback. "
            f"The {wf.finding.cwe_id} remediation now includes "
            "additional input validation.",
            "Thanks for the review. I have pushed a new commit with the "
            "requested changes. All tests still pass.",
            f"I have revised the approach for the {wf.finding.rule_name} "
            "fix based on your comments. The new implementation follows "
            "the pattern you suggested.",
            "Updated! I have also added an extra test case to cover the "
            "edge case you mentioned. Ready for re-review.",
        ]

        devin_response = random.choice(responses)
        wf.pr_comments.append({
            "author": "devin",
            "body": devin_response,
            "timestamp": datetime.now(UTC).isoformat(),
        })
        wf.workflow_state = "in_pr"
        wf.updated_at = datetime.now(UTC)

        self._notify(
            "Devin Responded",
            f"Devin replied on PR #{wf.pr_number}: "
            f"{devin_response[:80]}...",
            level="info",
            finding_id=finding_id,
        )
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Step 5: Approve PR
    # ------------------------------------------------------------------
    def approve_pr(self, finding_id: str) -> dict:
        """Mark a PR as approved and ready to merge."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}
        wf.workflow_state = "pr_approved"
        wf.updated_at = datetime.now(UTC)
        self._log("pr_approved", f"PR #{wf.pr_number} approved", finding_id)
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Step 6: Merge PR
    # ------------------------------------------------------------------
    def merge_pr(self, finding_id: str) -> dict:
        """Simulate merging a PR."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}

        wf.workflow_state = "merged"
        wf.updated_at = datetime.now(UTC)
        self._log("merge_complete", f"PR #{wf.pr_number} merged to main", finding_id)
        self._notify(
            "PR Merged",
            f"PR #{wf.pr_number} ({wf.pr_title}) merged. "
            "Triggering verification scan...",
            level="success",
            finding_id=finding_id,
        )
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Step 7: Rescan to verify fix
    # ------------------------------------------------------------------
    def rescan_finding(self, finding_id: str) -> dict:
        """Simulate a targeted rescan to verify the fix."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}

        wf.workflow_state = "rescanning"
        wf.updated_at = datetime.now(UTC)
        self._log(
            "rescan_start",
            f"Running targeted CodeQL rescan for {wf.finding.cwe_id} "
            f"in {wf.finding.file_path}...",
            finding_id,
        )

        fixed = random.random() < 0.9
        fname = wf.finding.file_path.split("/")[-1]
        if fixed:
            wf.workflow_state = "verified"
            wf.rescan_result = "clean"
            wf.finding.status = FindingStatus.COMPLETED
            level = "success"
            msg = f"Verification PASSED: {wf.finding.cwe_id} in {fname} remediated."
        else:
            wf.workflow_state = "failed"
            wf.rescan_result = "still_present"
            wf.finding.status = FindingStatus.NEEDS_REVIEW
            level = "error"
            msg = f"Verification FAILED: {wf.finding.cwe_id} in {fname} still present."

        wf.updated_at = datetime.now(UTC)
        self._log("rescan_complete", msg, finding_id)
        self._notify("Rescan Result", msg, level=level, finding_id=finding_id)
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Retry a failed finding
    # ------------------------------------------------------------------
    def retry_finding(self, finding_id: str) -> dict:
        """Reset a failed finding so it can be re-fixed."""
        wf = self.findings.get(finding_id)
        if not wf:
            return {"error": "Finding not found"}
        wf.workflow_state = "triaged"
        wf.fix_session_id = None
        wf.fix_session_url = None
        wf.pr_url = None
        wf.pr_number = None
        wf.pr_comments = []
        wf.pr_title = None
        wf.rescan_result = None
        wf.finding.status = FindingStatus.PENDING
        wf.updated_at = datetime.now(UTC)
        self._log("retry", f"Reset for retry: {wf.finding.rule_name}", finding_id)
        return wf.to_dict()

    # ------------------------------------------------------------------
    # Bulk triage
    # ------------------------------------------------------------------
    def triage_all(self) -> list[dict]:
        """Triage all detected findings at once."""
        results = []
        for fid, wf in self.findings.items():
            if wf.workflow_state == "detected":
                results.append(self.triage_finding(fid))
        return results

    # ------------------------------------------------------------------
    # Data access helpers
    # ------------------------------------------------------------------
    def get_summary(self) -> dict:
        """Get overall metrics."""
        states: dict[str, int] = {}
        severity_counts = {s.value: 0 for s in Severity}
        for wf in self.findings.values():
            states[wf.workflow_state] = states.get(wf.workflow_state, 0) + 1
            severity_counts[wf.finding.severity.value] += 1

        total = len(self.findings)
        verified = states.get("verified", 0)
        in_pr = states.get("in_pr", 0) + states.get("pr_commented", 0)

        return {
            "total_findings": total,
            "verified": verified,
            "in_pr": in_pr,
            "pr_approved": states.get("pr_approved", 0),
            "merged": states.get("merged", 0),
            "failed": states.get("failed", 0),
            "detected": states.get("detected", 0),
            "triaged": states.get("triaged", 0),
            "fixing": states.get("fixing", 0),
            "rescanning": states.get("rescanning", 0),
            "remediation_rate": (
                round((verified / total) * 100, 1) if total > 0 else 0
            ),
            "severity_counts": severity_counts,
            "state_counts": states,
            "unread_notifications": sum(
                1 for n in self.notifications if not n["read"]
            ),
        }

    def get_all_findings(self) -> list[dict]:
        """Get all findings as dicts."""
        return [wf.to_dict() for wf in self.findings.values()]

    def get_prs_for_review(self) -> list[dict]:
        """Get findings that have PRs ready for review."""
        return [
            wf.to_dict()
            for wf in self.findings.values()
            if wf.workflow_state in ("in_pr", "pr_commented", "pr_approved")
        ]

    def get_notifications(self, unread_only: bool = False) -> list[dict]:
        """Get notifications, newest first."""
        notifs = self.notifications
        if unread_only:
            notifs = [n for n in notifs if not n["read"]]
        return list(reversed(notifs))

    def mark_notification_read(self, notif_id: str) -> None:
        """Mark a notification as read."""
        for n in self.notifications:
            if n["id"] == notif_id:
                n["read"] = True
                break

    def mark_all_notifications_read(self) -> None:
        """Mark all notifications as read."""
        for n in self.notifications:
            n["read"] = True


# Singleton
pipeline_state = InteractivePipelineState()
