"""Generate an HTML compliance dashboard from a RemediationReport.

Uses Jinja2 to render a self-contained HTML file with inline CSS
that can be opened in any browser — no external dependencies.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from medsecure.models import RemediationReport

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_dashboard(report: RemediationReport, output_path: Path) -> Path:
    """Render the compliance dashboard as an HTML file.

    Args:
        report: The remediation report data.
        output_path: Where to write the HTML file.

    Returns:
        The path to the generated HTML file.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("dashboard.html")

    # Prepare template context
    findings_by_severity: dict[str, list[dict]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for finding in report.scan_summary.findings:
        findings_by_severity[finding.severity.value].append(
            {
                "id": finding.finding_id,
                "rule": finding.rule_name,
                "cwe": finding.cwe_id,
                "file": finding.file_path,
                "line": finding.start_line,
                "status": finding.status.value,
                "pr_url": finding.pr_url,
                "session_id": finding.session_id,
                "message": finding.message,
                "priority": finding.priority_label,
            }
        )

    sessions_data = [
        {
            "id": s.session_id,
            "url": s.session_url,
            "status": s.status,
            "detail": s.status_detail or "",
            "pr_url": s.pr_url or "",
            "pr_state": s.pr_state or "",
            "findings_count": len(s.finding_ids),
            "confidence": (s.structured_output or {}).get("fix_confidence", "N/A"),
            "needs_review": (s.structured_output or {}).get("requires_manual_review", False),
        }
        for s in report.sessions
    ]

    context = {
        "report": report,
        "findings_by_severity": findings_by_severity,
        "sessions": sessions_data,
        "remediation_rate": report.remediation_rate,
        "mttr": report.mean_time_to_remediation_hours,
    }

    html = template.render(**context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)

    return output_path
