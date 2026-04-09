"""Manage the lifecycle of Devin remediation sessions.

Handles batching findings, creating sessions with concurrency limits,
and tracking session state through completion.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from medsecure.config import PipelineConfig
from medsecure.models import FindingStatus, RemediationSession, SecurityFinding
from medsecure.orchestrator.devin_client import DevinClient
from medsecure.orchestrator.mock_client import MockDevinClient
from medsecure.orchestrator.prompt_builder import (
    build_prompt_for_findings,
    build_structured_output_schema,
)

logger = logging.getLogger(__name__)

# Terminal session statuses
_TERMINAL_STATUSES = {"exit", "error", "suspended"}


class SessionManager:
    """Manages Devin sessions for security finding remediation.

    Handles the full lifecycle: batching findings by file, creating
    sessions with concurrency limits, polling for completion, and
    collecting results.
    """

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._client: DevinClient | MockDevinClient
        if config.demo_mode:
            self._client = MockDevinClient()
        else:
            self._client = DevinClient(config.devin)
        self._active_sessions: dict[str, RemediationSession] = {}

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SessionManager:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def dispatch_findings(
        self,
        finding_batches: dict[str, list[SecurityFinding]],
    ) -> list[RemediationSession]:
        """Create Devin sessions for batched findings.

        Respects concurrency limits — if we have more batches than the
        max concurrent sessions, we process in waves.

        Args:
            finding_batches: Findings grouped by file path.

        Returns:
            List of created RemediationSession objects.
        """
        sessions: list[RemediationSession] = []
        max_concurrent = self.config.devin.max_concurrent_sessions
        batches = list(finding_batches.items())

        for i in range(0, len(batches), max_concurrent):
            wave = batches[i : i + max_concurrent]
            logger.info(
                "Dispatching wave %d/%d (%d batches)",
                (i // max_concurrent) + 1,
                (len(batches) + max_concurrent - 1) // max_concurrent,
                len(wave),
            )

            for _file_path, findings in wave:
                session = self._create_session_for_findings(findings)
                sessions.append(session)

                # Mark findings as dispatched
                for finding in findings:
                    finding.status = FindingStatus.DISPATCHED
                    finding.session_id = session.session_id

        return sessions

    def _create_session_for_findings(
        self,
        findings: list[SecurityFinding],
    ) -> RemediationSession:
        """Create a single Devin session for a batch of findings."""
        # Build tags from findings
        cwe_ids = sorted({f.cwe_id.lower() for f in findings})
        severities = sorted({f.severity.value for f in findings})
        tags = (
            ["security-fix", "medsecure-automation"]
            + [f"cwe-{cwe}" for cwe in cwe_ids]
            + [f"priority-{findings[0].priority_label}"]
        )

        # Build the prompt
        prompt = build_prompt_for_findings(findings, self.config.target_repo)
        schema = build_structured_output_schema()

        # Create the session
        response = self._client.create_session(
            prompt=prompt,
            repos=[self.config.target_repo],
            tags=tags,
            structured_output_schema=schema,
            max_acu_limit=self.config.devin.max_acu_per_session,
            idempotent=True,
        )

        session = RemediationSession(
            session_id=response["session_id"],
            session_url=response["url"],
            finding_ids=[f.finding_id for f in findings],
            status=response.get("status", "running"),
        )

        self._active_sessions[session.session_id] = session

        logger.info(
            "Created session %s for %d findings (severities: %s, CWEs: %s)",
            session.session_id,
            len(findings),
            severities,
            cwe_ids,
        )

        return session

    def poll_sessions(self) -> list[RemediationSession]:
        """Poll all active sessions and update their status.

        Returns:
            List of all tracked sessions (active + completed).
        """
        completed_ids: list[str] = []

        for session_id, session in self._active_sessions.items():
            try:
                response = self._client.get_session(session_id)
                status = response.get("status", "unknown")
                session.status = status
                session.status_detail = response.get("status_detail")
                session.updated_at = datetime.now(UTC)

                # Collect PR information
                prs = response.get("pull_requests", [])
                if prs:
                    session.pr_url = prs[0].get("pr_url")
                    session.pr_state = prs[0].get("pr_state")

                # Collect structured output
                structured = response.get("structured_output")
                if structured:
                    session.structured_output = structured

                if status in _TERMINAL_STATUSES:
                    completed_ids.append(session_id)
                    logger.info(
                        "Session %s completed: status=%s, pr=%s",
                        session_id,
                        status,
                        session.pr_url,
                    )

            except Exception:
                logger.exception("Error polling session %s", session_id)

        # Move completed sessions out of active tracking
        for sid in completed_ids:
            del self._active_sessions[sid]

        return list(self._active_sessions.values())

    def wait_for_completion(
        self,
        sessions: list[RemediationSession],
        *,
        timeout_seconds: int = 600,
    ) -> list[RemediationSession]:
        """Wait for all sessions to reach a terminal state.

        Args:
            sessions: Sessions to wait for.
            timeout_seconds: Maximum time to wait.

        Returns:
            Updated session list with final statuses.
        """
        # Re-register sessions for polling
        for session in sessions:
            if session.status not in _TERMINAL_STATUSES:
                self._active_sessions[session.session_id] = session

        start = time.monotonic()
        poll_interval = self.config.devin.poll_interval_seconds

        # In demo mode, use a short interval
        if self.config.demo_mode:
            poll_interval = 1

        while self._active_sessions:
            elapsed = time.monotonic() - start
            if elapsed > timeout_seconds:
                logger.warning(
                    "Timeout waiting for %d sessions after %ds",
                    len(self._active_sessions),
                    timeout_seconds,
                )
                break

            still_active = self.poll_sessions()
            if not still_active:
                break

            logger.info(
                "%d sessions still active, polling in %ds...",
                len(still_active),
                poll_interval,
            )
            time.sleep(poll_interval)

        return sessions

    def get_all_sessions(self) -> list[RemediationSession]:
        """Return all tracked sessions."""
        return list(self._active_sessions.values())
