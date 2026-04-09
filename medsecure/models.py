"""Data models for MedSecure security automation."""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Severity(enum.StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(enum.StrEnum):
    """Lifecycle status of a security finding."""

    PENDING = "pending"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class SecurityFinding(BaseModel):
    """A single security finding from a CodeQL scan."""

    finding_id: str
    rule_id: str
    rule_name: str
    cwe_id: str
    severity: Severity
    message: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str = ""
    recommendation: str = ""
    status: FindingStatus = FindingStatus.PENDING
    session_id: str | None = None
    pr_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None

    @property
    def priority_label(self) -> str:
        priority_map = {
            Severity.CRITICAL: "P0",
            Severity.HIGH: "P1",
            Severity.MEDIUM: "P2",
            Severity.LOW: "P3",
        }
        return priority_map[self.severity]


class RemediationSession(BaseModel):
    """Tracks a Devin session created to fix findings."""

    session_id: str
    session_url: str
    finding_ids: list[str]
    status: str = "running"
    status_detail: str | None = None
    pr_url: str | None = None
    pr_state: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    structured_output: dict | None = None


class ScanSummary(BaseModel):
    """Summary of a scan run."""

    scan_id: str
    scan_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings: list[SecurityFinding] = Field(default_factory=list)


class RemediationReport(BaseModel):
    """Compliance report for audit purposes."""

    report_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scan_summary: ScanSummary
    sessions: list[RemediationSession] = Field(default_factory=list)
    total_findings: int = 0
    remediated: int = 0
    in_progress: int = 0
    failed: int = 0
    pending: int = 0
    mean_time_to_remediation_hours: float | None = None

    @property
    def remediation_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return (self.remediated / self.total_findings) * 100
