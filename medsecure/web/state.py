"""In-memory pipeline state for the web dashboard.

Manages the pipeline execution state that the web UI reads from.
Runs the demo pipeline on startup to populate data.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from medsecure.config import PipelineConfig
from medsecure.ingester.prioritizer import group_by_file, prioritize
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.models import (
    FindingStatus,
    RemediationReport,
    RemediationSession,
    ScanSummary,
    SecurityFinding,
    Severity,
)
from medsecure.monitor.poller import sync_session_results
from medsecure.monitor.state_store import StateStore
from medsecure.orchestrator.session_manager import SessionManager
from medsecure.reports.generator import build_report, build_scan_summary
from medsecure.scanner.mock_scanner import generate_sarif

logger = logging.getLogger(__name__)


class PipelineState:
    """Holds the current state of the pipeline for the web UI."""

    def __init__(self) -> None:
        self.findings: list[SecurityFinding] = []
        self.sessions: list[RemediationSession] = []
        self.scan_summary: ScanSummary | None = None
        self.report: RemediationReport | None = None
        self.pipeline_phase: str = "idle"
        self.pipeline_log: list[dict] = []
        self._initialized = False

    def _log_event(self, phase: str, message: str) -> None:
        self.pipeline_log.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "phase": phase,
            "message": message,
        })

    def initialize(self, output_dir: Path | None = None) -> None:
        """Run the demo pipeline to populate state."""
        if self._initialized:
            return

        out = output_dir or Path("output")
        out.mkdir(parents=True, exist_ok=True)
        config = PipelineConfig(
            demo_mode=True,
            output_dir=out,
            db_path=out / "web_state.db",
        )

        # Phase 1: Identification
        self.pipeline_phase = "identification"
        self._log_event("identification", "Starting CodeQL scan simulation...")
        sarif = generate_sarif(out / "web_scan.sarif")
        result_count = len(sarif["runs"][0]["results"])
        self._log_event(
            "identification",
            f"Scan complete: {result_count} potential vulnerabilities detected",
        )

        # Phase 2: Triage / Prioritization
        self.pipeline_phase = "triage"
        self._log_event("triage", "Parsing SARIF and classifying findings...")
        findings = parse_sarif(sarif)
        self.findings = prioritize(findings)
        self.scan_summary = build_scan_summary(self.findings)
        self._log_event(
            "triage",
            f"Prioritized {len(self.findings)} findings "
            f"({self.scan_summary.critical} critical, "
            f"{self.scan_summary.high} high, "
            f"{self.scan_summary.medium} medium, "
            f"{self.scan_summary.low} low)",
        )

        # Phase 3: Dispatch / Mitigation
        self.pipeline_phase = "mitigation"
        self._log_event("mitigation", "Creating Devin sessions for remediation...")
        batches = group_by_file(self.findings)
        with SessionManager(config) as manager:
            self.sessions = manager.dispatch_findings(batches)
            self._log_event(
                "mitigation",
                f"Dispatched {len(self.sessions)} Devin sessions",
            )

            # Phase 4: Remediation
            self.pipeline_phase = "remediation"
            self._log_event("remediation", "Monitoring sessions for completion...")
            self.sessions = manager.wait_for_completion(
                self.sessions, timeout_seconds=30,
            )

        # Sync results
        with StateStore(config.db_path) as store:
            sync_session_results(self.sessions, self.findings, store)
            store.save_findings(self.findings)
            store.save_sessions(self.sessions)

        # Build report
        self.report = build_report(
            self.scan_summary, self.findings, self.sessions,
        )

        self.pipeline_phase = "complete"
        self._log_event(
            "complete",
            f"Pipeline complete: {self.report.remediation_rate:.0f}% remediation rate",
        )
        self._initialized = True

    def get_findings_by_status(self) -> dict[str, list[dict]]:
        """Group findings by their current status for the portal view."""
        groups: dict[str, list[dict]] = {
            "triaged": [],
            "in_progress": [],
            "in_pr": [],
            "completed": [],
            "failed": [],
        }

        for f in self.findings:
            entry = {
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
            }

            if f.status == FindingStatus.PENDING:
                groups["triaged"].append(entry)
            elif f.status in (FindingStatus.DISPATCHED, FindingStatus.RUNNING):
                # Check if session has a PR
                session = next(
                    (s for s in self.sessions if s.session_id == f.session_id),
                    None,
                )
                if session and session.pr_url:
                    groups["in_pr"].append(entry)
                else:
                    groups["in_progress"].append(entry)
            elif f.status == FindingStatus.COMPLETED:
                groups["completed"].append(entry)
            elif f.status in (FindingStatus.FAILED, FindingStatus.NEEDS_REVIEW):
                groups["failed"].append(entry)

        return groups

    def get_severity_counts(self) -> dict[str, int]:
        """Get finding counts by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def get_status_counts(self) -> dict[str, int]:
        """Get finding counts by status."""
        counts = {s.value: 0 for s in FindingStatus}
        for f in self.findings:
            counts[f.status.value] += 1
        return counts

    def get_sessions_data(self) -> list[dict]:
        """Get session data for the UI."""
        result = []
        for s in self.sessions:
            session_findings = [
                f for f in self.findings if f.finding_id in s.finding_ids
            ]
            cwes = sorted({f.cwe_id for f in session_findings})
            severities = sorted({f.severity.value for f in session_findings})

            result.append({
                "session_id": s.session_id,
                "session_url": s.session_url,
                "status": s.status,
                "status_detail": s.status_detail,
                "pr_url": s.pr_url,
                "pr_state": s.pr_state,
                "finding_count": len(s.finding_ids),
                "finding_ids": s.finding_ids,
                "cwes": cwes,
                "severities": severities,
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat(),
                "structured_output": s.structured_output,
            })
        return result

    def get_pipeline_summary(self) -> dict:
        """Get overall pipeline summary for the dashboard."""
        report = self.report
        return {
            "phase": self.pipeline_phase,
            "total_findings": report.total_findings if report else 0,
            "remediated": report.remediated if report else 0,
            "in_progress": report.in_progress if report else 0,
            "failed": report.failed if report else 0,
            "pending": report.pending if report else 0,
            "remediation_rate": (
                report.remediation_rate if report else 0.0
            ),
            "total_sessions": len(self.sessions),
            "severity_counts": self.get_severity_counts(),
            "status_counts": self.get_status_counts(),
            "scan_id": (
                self.scan_summary.scan_id if self.scan_summary else None
            ),
        }


# Singleton state
pipeline_state = PipelineState()
