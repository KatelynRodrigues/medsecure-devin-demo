"""Mock Devin API client for demo mode.

Simulates the full session lifecycle with realistic delays,
state transitions, and generated PR URLs — no real API calls needed.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# Simulated session states
_SESSION_LIFECYCLE = ["running", "running", "running", "exit"]


class MockDevinClient:
    """Mock implementation of the Devin API client.

    Simulates session creation, polling, and completion with
    realistic-looking responses. Each session progresses through
    a simulated lifecycle on each poll.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        self._poll_counts: dict[str, int] = {}

    def close(self) -> None:
        pass

    def __enter__(self) -> MockDevinClient:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def create_session(
        self,
        prompt: str,
        *,
        repos: list[str] | None = None,
        tags: list[str] | None = None,
        playbook_id: str | None = None,
        structured_output_schema: dict | None = None,
        max_acu_limit: int | None = None,
        idempotent: bool = False,
    ) -> dict:
        """Simulate creating a Devin session."""
        session_id = f"devin-mock-{uuid.uuid4().hex[:12]}"
        now = int(datetime.now(UTC).timestamp())

        # Extract finding info from tags for realistic PR titles
        cwe_tags = [t for t in (tags or []) if t.startswith("cwe-")]
        cwe_label = cwe_tags[0] if cwe_tags else "security"

        session = {
            "session_id": session_id,
            "url": f"https://app.devin.ai/sessions/{session_id}",
            "status": "running",
            "status_detail": "working",
            "tags": tags or [],
            "org_id": "org-mock-medsecure",
            "created_at": now,
            "updated_at": now,
            "acus_consumed": 0.0,
            "pull_requests": [],
            "structured_output": None,
            "_prompt": prompt,
            "_cwe_label": cwe_label,
            "_structured_schema": structured_output_schema,
        }

        self._sessions[session_id] = session
        self._poll_counts[session_id] = 0

        logger.info("[MOCK] Created session %s with tags %s", session_id, tags)
        return {k: v for k, v in session.items() if not k.startswith("_")}

    def get_session(self, session_id: str) -> dict:
        """Simulate polling a session's status.

        Each call advances the session through its lifecycle.
        After a few polls, the session completes with a mock PR.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return {"error": "Session not found", "session_id": session_id}

        poll_count = self._poll_counts.get(session_id, 0)
        self._poll_counts[session_id] = poll_count + 1

        # Advance through lifecycle
        status = (
            _SESSION_LIFECYCLE[poll_count]
            if poll_count < len(_SESSION_LIFECYCLE)
            else "exit"
        )

        session["status"] = status
        session["updated_at"] = int(datetime.now(UTC).timestamp())
        session["acus_consumed"] = round(random.uniform(1.5, 8.0), 2)

        if status == "exit":
            session["status_detail"] = "finished"

            # Generate mock PR
            pr_number = random.randint(10, 200)
            cwe_label = session.get("_cwe_label", "security")
            session["pull_requests"] = [
                {
                    "pr_url": (
                        f"https://github.com/KatelynRodrigues/medsecure-devin-demo"
                        f"/pull/{pr_number}"
                    ),
                    "pr_state": "open",
                }
            ]

            # Generate mock structured output
            schema = session.get("_structured_schema")
            if schema:
                session["structured_output"] = {
                    "findings_fixed": [
                        f"finding-{uuid.uuid4().hex[:8]}"
                        for _ in range(random.randint(1, 3))
                    ],
                    "fix_confidence": random.choice(["high", "high", "medium"]),
                    "files_modified": [f"medsecure/scanner/vulnerable_code/{cwe_label}_fix.py"],
                    "requires_manual_review": random.choice([False, False, True]),
                    "tests_added": True,
                    "notes": f"Fixed {cwe_label.upper()} vulnerability with recommended pattern.",
                }
        else:
            session["status_detail"] = "working"

        logger.info(
            "[MOCK] Session %s poll #%d -> status=%s",
            session_id,
            poll_count,
            status,
        )
        return {k: v for k, v in session.items() if not k.startswith("_")}

    def list_sessions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        tags: list[str] | None = None,
    ) -> dict:
        """List all mock sessions."""
        items = list(self._sessions.values())
        if tags:
            items = [
                s for s in items if any(t in s.get("tags", []) for t in tags)
            ]
        cleaned = [{k: v for k, v in s.items() if not k.startswith("_")} for s in items]
        return {"items": cleaned[offset : offset + limit], "total": len(cleaned)}

    def send_message(self, session_id: str, message: str) -> dict:
        """Simulate sending a message to a session."""
        logger.info("[MOCK] Sent message to %s: %s", session_id, message[:80])
        return {"status": "ok"}

    def get_messages(self, session_id: str) -> dict:
        """Return mock messages for a session."""
        return {
            "items": [
                {
                    "role": "devin",
                    "content": "I've analyzed the vulnerability and I'm working on a fix.",
                    "timestamp": int(datetime.now(UTC).timestamp()),
                }
            ]
        }

    def terminate_session(self, session_id: str) -> dict:
        """Simulate terminating a session."""
        session = self._sessions.get(session_id)
        if session:
            session["status"] = "suspended"
            session["status_detail"] = "user_request"
        return {"status": "ok"}

    def update_tags(self, session_id: str, tags: list[str]) -> dict:
        """Simulate updating session tags."""
        session = self._sessions.get(session_id)
        if session:
            session["tags"] = tags
        return {"status": "ok"}
