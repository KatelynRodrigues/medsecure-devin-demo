"""Slack notification integration (real + mock).

Sends structured notifications to Slack channels for:
- Scan completion summaries
- Session dispatch notifications
- PR creation alerts
- Failure/escalation alerts
- Weekly compliance digests
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx

from medsecure.models import RemediationSession, ScanSummary, SecurityFinding

logger = logging.getLogger(__name__)


def _format_scan_summary_blocks(summary: ScanSummary) -> list[dict]:
    """Build Slack Block Kit blocks for a scan summary."""
    severity_line = (
        f":red_circle: *Critical:* {summary.critical}  "
        f":orange_circle: *High:* {summary.high}  "
        f":large_yellow_circle: *Medium:* {summary.medium}  "
        f":white_circle: *Low:* {summary.low}"
    )

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"CodeQL Scan Complete — {summary.total_findings} Findings",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Scan ID:* `{summary.scan_id}`\n"
                    f"*Time:* {summary.scan_time.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                    f"{severity_line}"
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    ":robot_face: *Automated remediation is starting.* "
                    "Devin sessions will be created for each finding batch. "
                    "You'll receive updates as PRs are created."
                ),
            },
        },
        {"type": "divider"},
    ]


def _format_session_created_blocks(
    session: RemediationSession,
    findings: list[SecurityFinding],
) -> list[dict]:
    """Build Slack blocks for a session creation notification."""
    finding_lines = "\n".join(
        f"  - `{f.cwe_id}` {f.rule_name} in `{f.file_path}:{f.start_line}` ({f.severity.value})"
        for f in findings
    )

    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f":wrench: *Devin session started for security remediation*\n\n"
                    f"*Session:* <{session.session_url}|{session.session_id}>\n"
                    f"*Findings being fixed:*\n{finding_lines}"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Session"},
                    "url": session.session_url,
                    "style": "primary",
                }
            ],
        },
        {"type": "divider"},
    ]


def _format_pr_created_blocks(session: RemediationSession) -> list[dict]:
    """Build Slack blocks for a PR creation notification."""
    pr_url = session.pr_url or "N/A"
    confidence = "N/A"
    if session.structured_output:
        confidence = session.structured_output.get("fix_confidence", "N/A")

    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f":white_check_mark: *PR Created for Security Fix*\n\n"
                    f"*PR:* <{pr_url}|View Pull Request>\n"
                    f"*Session:* <{session.session_url}|{session.session_id}>\n"
                    f"*Fix confidence:* {confidence}\n"
                    f"*Findings fixed:* {len(session.finding_ids)}\n\n"
                    f":eyes: *Engineering team: please review this PR.*"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review PR"},
                    "url": pr_url,
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Session"},
                    "url": session.session_url,
                },
            ],
        },
        {"type": "divider"},
    ]


def _format_failure_blocks(session: RemediationSession) -> list[dict]:
    """Build Slack blocks for a session failure/escalation."""
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f":warning: *Security Fix Session Failed — Manual Action Needed*\n\n"
                    f"*Session:* <{session.session_url}|{session.session_id}>\n"
                    f"*Status:* {session.status} ({session.status_detail or 'unknown'})\n"
                    f"*Affected findings:* {len(session.finding_ids)}\n\n"
                    f"This session could not complete automatically. "
                    f"Please review the session and manually fix the findings, "
                    f"or re-trigger the automation."
                ),
            },
        },
        {"type": "divider"},
    ]


class SlackNotifier:
    """Send Slack notifications via webhook.

    In demo mode, logs payloads to console and a file instead of
    sending real HTTP requests.
    """

    def __init__(
        self,
        webhook_url: str = "",
        channel: str = "#security-alerts",
        demo_mode: bool = True,
        log_path: Path | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self.channel = channel
        self.demo_mode = demo_mode
        self.log_path = log_path or Path("output/notifications.log")
        self._notifications: list[dict] = []

    def notify_scan_complete(self, summary: ScanSummary) -> None:
        """Send notification that a scan completed."""
        blocks = _format_scan_summary_blocks(summary)
        self._send(
            text=f"CodeQL scan complete: {summary.total_findings} findings",
            blocks=blocks,
            event_type="scan_complete",
        )

    def notify_session_created(
        self,
        session: RemediationSession,
        findings: list[SecurityFinding],
    ) -> None:
        """Send notification that a Devin session was created."""
        blocks = _format_session_created_blocks(session, findings)
        self._send(
            text=f"Devin session {session.session_id} started for {len(findings)} findings",
            blocks=blocks,
            event_type="session_created",
        )

    def notify_pr_created(self, session: RemediationSession) -> None:
        """Send notification that a PR was created."""
        blocks = _format_pr_created_blocks(session)
        self._send(
            text=f"PR created: {session.pr_url}",
            blocks=blocks,
            event_type="pr_created",
        )

    def notify_failure(self, session: RemediationSession) -> None:
        """Send escalation notification for a failed session."""
        blocks = _format_failure_blocks(session)
        self._send(
            text=f"ESCALATION: Session {session.session_id} failed",
            blocks=blocks,
            event_type="session_failed",
        )

    def get_notification_log(self) -> list[dict]:
        """Return all notifications sent in this run."""
        return list(self._notifications)

    def _send(self, text: str, blocks: list[dict], event_type: str) -> None:
        """Send a Slack webhook payload or log it in demo mode."""
        payload = {
            "channel": self.channel,
            "text": text,
            "blocks": blocks,
        }

        notification_record = {
            "event_type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "channel": self.channel,
            "text": text,
            "payload": payload,
        }
        self._notifications.append(notification_record)

        if self.demo_mode:
            logger.info("[SLACK MOCK] %s -> %s", event_type, text)
            self._log_to_file(notification_record)
        else:
            self._send_webhook(payload)

    def _send_webhook(self, payload: dict) -> None:
        """Send payload to the real Slack webhook URL."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured; skipping notification")
            return

        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=10.0)
            resp.raise_for_status()
            logger.info("Slack notification sent successfully")
        except Exception:
            logger.exception("Failed to send Slack notification")

    def _log_to_file(self, record: dict) -> None:
        """Append notification record to a log file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record, indent=2) + "\n---\n")
