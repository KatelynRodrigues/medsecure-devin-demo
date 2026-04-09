"""Configuration management for MedSecure automation."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class DevinAPIConfig(BaseModel):
    """Configuration for the Devin API client."""

    api_key: str = Field(default="")
    org_id: str = Field(default="")
    base_url: str = Field(default="https://api.devin.ai/v3")
    max_concurrent_sessions: int = Field(default=5)
    poll_interval_seconds: int = Field(default=30)
    max_acu_per_session: int = Field(default=10)

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


class NotificationConfig(BaseModel):
    """Configuration for notification channels."""

    slack_webhook_url: str = Field(default="")
    slack_channel: str = Field(default="#security-alerts")
    email_recipients_security: list[str] = Field(
        default_factory=lambda: ["security-team@medsecure.example.com"]
    )
    email_recipients_engineering: list[str] = Field(
        default_factory=lambda: ["eng-leads@medsecure.example.com"]
    )


class PipelineConfig(BaseModel):
    """Top-level pipeline configuration."""

    devin: DevinAPIConfig = Field(default_factory=DevinAPIConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    target_repo: str = Field(default="KatelynRodrigues/medsecure-devin-demo")
    output_dir: Path = Field(default=Path("output"))
    demo_mode: bool = Field(default=True)
    db_path: Path = Field(default=Path("output/medsecure_state.db"))

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """Load configuration from environment variables."""
        return cls(
            devin=DevinAPIConfig(
                api_key=os.environ.get("DEVIN_API_KEY", ""),
                org_id=os.environ.get("DEVIN_ORG_ID", ""),
                base_url=os.environ.get("DEVIN_API_BASE_URL", "https://api.devin.ai/v3"),
            ),
            notifications=NotificationConfig(
                slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            ),
            target_repo=os.environ.get(
                "MEDSECURE_TARGET_REPO", "KatelynRodrigues/medsecure-devin-demo"
            ),
            demo_mode=os.environ.get("MEDSECURE_DEMO_MODE", "true").lower() == "true",
        )
