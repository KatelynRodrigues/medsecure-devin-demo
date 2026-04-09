"""Devin API v3 client for creating and managing remediation sessions.

Wraps the Devin REST API with typed methods for session lifecycle management.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

import httpx

from medsecure.config import DevinAPIConfig

logger = logging.getLogger(__name__)


class DevinAPIError(Exception):
    """Raised when a Devin API call fails."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Devin API error {status_code}: {detail}")


class DevinClient:
    """Client for the Devin v3 API.

    Handles session creation, polling, messaging, and termination.
    """

    def __init__(self, config: DevinAPIConfig) -> None:
        self.config = config
        self._base = f"{config.base_url}/organizations/{config.org_id}"
        self._client = httpx.Client(
            headers=config.headers,
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> DevinClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make an authenticated API request."""
        url = f"{self._base}{path}"
        resp = self._client.request(method, url, **kwargs)
        if resp.status_code >= 400:
            detail = resp.text
            with contextlib.suppress(Exception):
                detail = resp.json().get("detail", resp.text)
            raise DevinAPIError(resp.status_code, str(detail))
        return resp.json()

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
        """Create a new Devin session.

        Args:
            prompt: The task prompt for Devin.
            repos: List of repository names to make available.
            tags: Tags to attach to the session.
            playbook_id: Optional playbook ID to use.
            structured_output_schema: JSON Schema for structured output.
            max_acu_limit: Maximum ACU limit for the session.
            idempotent: If True, avoid creating duplicate sessions.

        Returns:
            Session response dictionary with session_id, url, status.
        """
        payload: dict[str, Any] = {"prompt": prompt}
        if repos:
            payload["repos"] = repos
        if tags:
            payload["tags"] = tags
        if playbook_id:
            payload["playbook_id"] = playbook_id
        if structured_output_schema:
            payload["structured_output_schema"] = structured_output_schema
        if max_acu_limit:
            payload["max_acu_limit"] = max_acu_limit
        if idempotent:
            payload["idempotent"] = True

        logger.info("Creating Devin session with tags=%s", tags)
        return self._request("POST", "/sessions", json=payload)

    def get_session(self, session_id: str) -> dict:
        """Get current status and details of a session.

        Args:
            session_id: The Devin session ID.

        Returns:
            Session details including status, PRs, structured output.
        """
        return self._request("GET", f"/sessions/{session_id}")

    def list_sessions(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        tags: list[str] | None = None,
    ) -> dict:
        """List sessions, optionally filtered by tags.

        Args:
            limit: Maximum number of sessions to return.
            offset: Pagination offset.
            tags: Filter by these tags.

        Returns:
            Dictionary with 'items' list and pagination info.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if tags:
            params["tags"] = ",".join(tags)
        return self._request("GET", "/sessions", params=params)

    def send_message(self, session_id: str, message: str) -> dict:
        """Send a follow-up message to a running session.

        Args:
            session_id: The Devin session ID.
            message: The message to send.

        Returns:
            Response dictionary.
        """
        return self._request(
            "POST",
            f"/sessions/{session_id}/messages",
            json={"message": message},
        )

    def get_messages(self, session_id: str) -> dict:
        """Get all messages/events for a session.

        Args:
            session_id: The Devin session ID.

        Returns:
            Dictionary with message items.
        """
        return self._request("GET", f"/sessions/{session_id}/messages")

    def terminate_session(self, session_id: str) -> dict:
        """Terminate a running session.

        Args:
            session_id: The Devin session ID.

        Returns:
            Response dictionary.
        """
        return self._request("POST", f"/sessions/{session_id}/terminate")

    def update_tags(self, session_id: str, tags: list[str]) -> dict:
        """Update tags on a session.

        Args:
            session_id: The Devin session ID.
            tags: New set of tags.

        Returns:
            Response dictionary.
        """
        return self._request(
            "PUT",
            f"/sessions/{session_id}/tags",
            json={"tags": tags},
        )
