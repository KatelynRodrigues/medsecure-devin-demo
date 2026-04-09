"""Generate compliance reports from pipeline state.

Produces both JSON and HTML reports suitable for audit review.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from medsecure.models import (
    FindingStatus,
    RemediationReport,
    RemediationSession,
    ScanSummary,
    SecurityFinding,
    Severity,
)


def build_report(
    scan_summary: ScanSummary,
    findings: list[SecurityFinding],
    sessions: list[RemediationSession],
) -> RemediationReport:
    """Build a remediation report from current pipeline state.

    Args:
        scan_summary: Summary of the original scan.
        findings: All tracked findings.
        sessions: All remediation sessions.

    Returns:
        A complete RemediationReport.
    """
    remediated = sum(1 for f in findings if f.status == FindingStatus.COMPLETED)
    in_progress = sum(
        1 for f in findings if f.status in (FindingStatus.DISPATCHED, FindingStatus.RUNNING)
    )
    failed = sum(
        1 for f in findings if f.status in (FindingStatus.FAILED, FindingStatus.NEEDS_REVIEW)
    )
    pending = sum(1 for f in findings if f.status == FindingStatus.PENDING)

    # Calculate mean time to remediation for completed findings
    mttr_hours: float | None = None
    resolved_times: list[float] = []
    for f in findings:
        if f.status == FindingStatus.COMPLETED and f.resolved_at:
            delta = (f.resolved_at - f.created_at).total_seconds() / 3600
            resolved_times.append(delta)
    if resolved_times:
        mttr_hours = sum(resolved_times) / len(resolved_times)

    return RemediationReport(
        report_id=f"report-{uuid.uuid4().hex[:12]}",
        scan_summary=scan_summary,
        sessions=sessions,
        total_findings=len(findings),
        remediated=remediated,
        in_progress=in_progress,
        failed=failed,
        pending=pending,
        mean_time_to_remediation_hours=mttr_hours,
    )


def export_json(report: RemediationReport, output_path: Path) -> Path:
    """Export the report as JSON for GRC tool integration.

    Args:
        report: The remediation report.
        output_path: Path to write the JSON file.

    Returns:
        The path to the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(report.model_dump_json())
    output_path.write_text(json.dumps(data, indent=2, default=str))
    return output_path


def build_scan_summary(findings: list[SecurityFinding], scan_id: str | None = None) -> ScanSummary:
    """Build a ScanSummary from a list of findings.

    Args:
        findings: Parsed and prioritized findings.
        scan_id: Optional scan identifier.

    Returns:
        A ScanSummary with severity counts.
    """
    return ScanSummary(
        scan_id=scan_id or f"scan-{uuid.uuid4().hex[:12]}",
        total_findings=len(findings),
        critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low=sum(1 for f in findings if f.severity == Severity.LOW),
        findings=findings,
    )
