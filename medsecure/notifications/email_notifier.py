"""Email notification integration (mock).

Generates formatted email content for security and engineering teams.
In production, this would integrate with an SMTP server or email API
like SendGrid. For the demo, we generate HTML email content and log it.
"""

from __future__ import annotations

import logging
from pathlib import Path

from medsecure.models import RemediationReport, ScanSummary

logger = logging.getLogger(__name__)


def _severity_color(severity: str) -> str:
    """Map severity to an HTML color."""
    return {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#6b7280",
    }.get(severity, "#6b7280")


class EmailNotifier:
    """Generate and send email notifications.

    In demo mode, writes HTML email content to files.
    """

    def __init__(
        self,
        security_recipients: list[str] | None = None,
        engineering_recipients: list[str] | None = None,
        demo_mode: bool = True,
        output_dir: Path | None = None,
    ) -> None:
        self.security_recipients = security_recipients or ["security-team@medsecure.example.com"]
        self.engineering_recipients = engineering_recipients or [
            "eng-leads@medsecure.example.com"
        ]
        self.demo_mode = demo_mode
        self.output_dir = output_dir or Path("output/emails")

    def send_scan_digest(self, summary: ScanSummary) -> str:
        """Generate and send a scan digest email to the security team.

        Returns:
            The generated HTML content.
        """
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1e293b; color: white;
                        padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0;">MedSecure Security Scan Report</h1>
                <p style="margin: 5px 0 0 0; opacity: 0.8;">
                    {summary.scan_time.strftime('%B %d, %Y at %H:%M UTC')}
                </p>
            </div>
            <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
                <h2>Scan Summary</h2>
                <p><strong>Scan ID:</strong> {summary.scan_id}</p>
                <p><strong>Total Findings:</strong> {summary.total_findings}</p>
                <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                    <tr>
                        <td style="padding: 8px;
                            background: {_severity_color('critical')};
                            color: white; text-align: center;
                            border-radius: 4px;">
                            <strong>{summary.critical}</strong><br>Critical
                        </td>
                        <td style="padding: 8px;
                            background: {_severity_color('high')};
                            color: white; text-align: center;
                            border-radius: 4px;">
                            <strong>{summary.high}</strong><br>High
                        </td>
                        <td style="padding: 8px;
                            background: {_severity_color('medium')};
                            color: white; text-align: center;
                            border-radius: 4px;">
                            <strong>{summary.medium}</strong><br>Medium
                        </td>
                        <td style="padding: 8px;
                            background: {_severity_color('low')};
                            color: white; text-align: center;
                            border-radius: 4px;">
                            <strong>{summary.low}</strong><br>Low
                        </td>
                    </tr>
                </table>
                <hr>
                <p>
                    <strong>Automated remediation has been initiated.</strong>
                    Devin AI sessions are being created to fix each finding.
                    You will receive PR review requests as fixes are ready.
                </p>
                <p style="color: #6b7280; font-size: 12px;">
                    This is an automated message from the MedSecure Security Automation Pipeline.
                </p>
            </div>
        </body>
        </html>
        """

        self._deliver(
            recipients=self.security_recipients,
            subject=f"[MedSecure] CodeQL Scan: {summary.total_findings} findings detected",
            html=html,
            filename="scan_digest.html",
        )
        return html

    def send_compliance_report(self, report: RemediationReport) -> str:
        """Generate and send a compliance summary email.

        Returns:
            The generated HTML content.
        """
        rate = report.remediation_rate
        rate_color = "#16a34a" if rate >= 80 else "#ca8a04" if rate >= 50 else "#dc2626"

        pr_rows = ""
        for session in report.sessions:
            if session.pr_url:
                status_badge = {
                    "open": '<span style="color: #16a34a;">Open</span>',
                    "merged": '<span style="color: #7c3aed;">Merged</span>',
                    "closed": '<span style="color: #dc2626;">Closed</span>',
                }.get(session.pr_state or "", session.pr_state or "N/A")

                pr_rows += f"""
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 8px;">
                        <a href="{session.pr_url}">
                            {session.session_id[:20]}...</a></td>
                    <td style="padding: 8px;">{len(session.finding_ids)} findings</td>
                    <td style="padding: 8px;">{status_badge}</td>
                </tr>
                """

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 700px; margin: 0 auto;">
            <div style="background: #1e293b; color: white;
                        padding: 20px; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0;">Compliance Remediation Report</h1>
                <p style="margin: 5px 0 0 0; opacity: 0.8;">
                    Generated {report.generated_at.strftime('%B %d, %Y at %H:%M UTC')}
                </p>
            </div>
            <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
                <div style="text-align: center; margin: 20px 0;">
                    <div style="font-size: 48px; font-weight: bold; color: {rate_color};">
                        {rate:.0f}%
                    </div>
                    <div style="color: #6b7280;">Remediation Rate</div>
                </div>
                <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
                    <tr>
                        <td style="padding: 12px; text-align: center;">
                            <div style="font-size: 24px;
                                font-weight: bold;">
                                {report.total_findings}</div>
                            <div style="color: #6b7280;">Total</div>
                        </td>
                        <td style="padding: 12px; text-align: center;">
                            <div style="font-size: 24px;
                                font-weight: bold;
                                color: #16a34a;">
                                {report.remediated}</div>
                            <div style="color: #6b7280;">Fixed</div>
                        </td>
                        <td style="padding: 12px; text-align: center;">
                            <div style="font-size: 24px;
                                font-weight: bold;
                                color: #2563eb;">
                                {report.in_progress}</div>
                            <div style="color: #6b7280;">In Progress</div>
                        </td>
                        <td style="padding: 12px; text-align: center;">
                            <div style="font-size: 24px;
                                font-weight: bold;
                                color: #dc2626;">
                                {report.failed}</div>
                            <div style="color: #6b7280;">Failed</div>
                        </td>
                    </tr>
                </table>
                <h3>Pull Requests</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr style="background: #f1f5f9;">
                        <th style="padding: 8px; text-align: left;">Session</th>
                        <th style="padding: 8px; text-align: left;">Scope</th>
                        <th style="padding: 8px; text-align: left;">Status</th>
                    </tr>
                    {pr_rows}
                </table>
                <hr>
                <p style="color: #6b7280; font-size: 12px;">
                    MedSecure Automated Security Remediation Pipeline | HIPAA Compliance
                </p>
            </div>
        </body>
        </html>
        """

        self._deliver(
            recipients=self.security_recipients + self.engineering_recipients,
            subject=f"[MedSecure] Compliance Report: {rate:.0f}% remediation rate",
            html=html,
            filename="compliance_report_email.html",
        )
        return html

    def _deliver(
        self,
        recipients: list[str],
        subject: str,
        html: str,
        filename: str,
    ) -> None:
        """Deliver email or write to file in demo mode."""
        if self.demo_mode:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            out_path = self.output_dir / filename
            out_path.write_text(html)
            logger.info(
                "[EMAIL MOCK] To: %s | Subject: %s | Saved: %s",
                ", ".join(recipients),
                subject,
                out_path,
            )
        else:
            # In production: integrate with SendGrid, SES, or SMTP
            logger.info(
                "Would send email to %s: %s",
                ", ".join(recipients),
                subject,
            )
