"""SQLite-backed state store for tracking findings and sessions.

Persists pipeline state across runs so the automation can resume
after interruptions and produce historical compliance reports.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from medsecure.models import (
    FindingStatus,
    RemediationSession,
    SecurityFinding,
    Severity,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    code_snippet TEXT DEFAULT '',
    recommendation TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    session_id TEXT,
    pr_url TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    session_url TEXT NOT NULL,
    finding_ids TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    status_detail TEXT,
    pr_url TEXT,
    pr_state TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    structured_output TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id TEXT PRIMARY KEY,
    scan_time TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    sarif_path TEXT
);
"""


class StateStore:
    """SQLite-backed persistence for pipeline state."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── Findings ──────────────────────────────────────────────────

    def save_finding(self, finding: SecurityFinding) -> None:
        """Insert or update a finding."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO findings
                (finding_id, rule_id, rule_name, cwe_id, severity, message,
                 file_path, start_line, end_line, code_snippet, recommendation,
                 status, session_id, pr_url, created_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.rule_id,
                finding.rule_name,
                finding.cwe_id,
                finding.severity.value,
                finding.message,
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.code_snippet,
                finding.recommendation,
                finding.status.value,
                finding.session_id,
                finding.pr_url,
                finding.created_at.isoformat(),
                finding.resolved_at.isoformat() if finding.resolved_at else None,
            ),
        )
        self._conn.commit()

    def save_findings(self, findings: list[SecurityFinding]) -> None:
        """Batch save findings."""
        for finding in findings:
            self.save_finding(finding)

    def get_finding(self, finding_id: str) -> SecurityFinding | None:
        """Retrieve a finding by ID."""
        row = self._conn.execute(
            "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_finding(row)

    def get_all_findings(self) -> list[SecurityFinding]:
        """Retrieve all findings."""
        rows = self._conn.execute("SELECT * FROM findings ORDER BY severity, file_path").fetchall()
        return [self._row_to_finding(row) for row in rows]

    def update_finding_status(
        self,
        finding_id: str,
        status: FindingStatus,
        *,
        session_id: str | None = None,
        pr_url: str | None = None,
    ) -> None:
        """Update the status of a finding."""
        updates = ["status = ?"]
        params: list[str | None] = [status.value]

        if session_id is not None:
            updates.append("session_id = ?")
            params.append(session_id)

        if pr_url is not None:
            updates.append("pr_url = ?")
            params.append(pr_url)

        if status == FindingStatus.COMPLETED:
            updates.append("resolved_at = ?")
            params.append(datetime.now(UTC).isoformat())

        params.append(finding_id)
        self._conn.execute(
            f"UPDATE findings SET {', '.join(updates)} WHERE finding_id = ?",
            params,
        )
        self._conn.commit()

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> SecurityFinding:
        resolved = row["resolved_at"]
        return SecurityFinding(
            finding_id=row["finding_id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            cwe_id=row["cwe_id"],
            severity=Severity(row["severity"]),
            message=row["message"],
            file_path=row["file_path"],
            start_line=row["start_line"],
            end_line=row["end_line"],
            code_snippet=row["code_snippet"],
            recommendation=row["recommendation"],
            status=FindingStatus(row["status"]),
            session_id=row["session_id"],
            pr_url=row["pr_url"],
            created_at=datetime.fromisoformat(row["created_at"]),
            resolved_at=datetime.fromisoformat(resolved) if resolved else None,
        )

    # ── Sessions ──────────────────────────────────────────────────

    def save_session(self, session: RemediationSession) -> None:
        """Insert or update a remediation session."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO sessions
                (session_id, session_url, finding_ids, status, status_detail,
                 pr_url, pr_state, created_at, updated_at, structured_output)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.session_url,
                json.dumps(session.finding_ids),
                session.status,
                session.status_detail,
                session.pr_url,
                session.pr_state,
                session.created_at.isoformat(),
                session.updated_at.isoformat(),
                json.dumps(session.structured_output) if session.structured_output else None,
            ),
        )
        self._conn.commit()

    def save_sessions(self, sessions: list[RemediationSession]) -> None:
        """Batch save sessions."""
        for session in sessions:
            self.save_session(session)

    def get_all_sessions(self) -> list[RemediationSession]:
        """Retrieve all sessions."""
        rows = self._conn.execute("SELECT * FROM sessions ORDER BY created_at").fetchall()
        return [self._row_to_session(row) for row in rows]

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> RemediationSession:
        structured = row["structured_output"]
        return RemediationSession(
            session_id=row["session_id"],
            session_url=row["session_url"],
            finding_ids=json.loads(row["finding_ids"]),
            status=row["status"],
            status_detail=row["status_detail"],
            pr_url=row["pr_url"],
            pr_state=row["pr_state"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            structured_output=json.loads(structured) if structured else None,
        )

    # ── Scan Runs ─────────────────────────────────────────────────

    def save_scan_run(
        self,
        scan_id: str,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        sarif_path: str | None = None,
    ) -> None:
        """Record a scan run."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO scan_runs
                (scan_id, scan_time, total_findings, critical, high, medium, low, sarif_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                datetime.now(UTC).isoformat(),
                total,
                critical,
                high,
                medium,
                low,
                sarif_path,
            ),
        )
        self._conn.commit()
