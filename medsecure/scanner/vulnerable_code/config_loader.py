"""Configuration loader with intentional security vulnerabilities.

WARNING: This file contains INTENTIONAL vulnerabilities for demonstration
purposes. Do NOT use this code in production.
"""

from __future__ import annotations

import os

# VULNERABILITY: CWE-798 Hardcoded Credentials
# Database and API credentials hardcoded in source code.
DB_HOST = "db.medsecure.internal"
DB_PORT = 5432
DB_NAME = "medsecure_prod"
DB_USER = "medsecure_admin"
DB_PASSWORD = "MedSecure_Prod_2024!"
API_SECRET = "sk-prod-a1b2c3d4e5f6"

# HIPAA audit log encryption key (should be in a secrets manager)
AUDIT_LOG_KEY = "aes-256-gcm-key-do-not-share-12345"


def get_database_url() -> str:
    """Build database connection URL.

    Uses hardcoded credentials instead of environment variables.
    """
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


def get_api_secret() -> str:
    """Return the API secret for signing requests.

    Hardcoded instead of using a secrets manager.
    """
    return API_SECRET


def get_config() -> dict:
    """Load application configuration.

    Mixes hardcoded secrets with environment variables.
    """
    return {
        "database_url": get_database_url(),
        "api_secret": get_api_secret(),
        "audit_key": AUDIT_LOG_KEY,
        "environment": os.environ.get("APP_ENV", "production"),
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
        "log_level": os.environ.get("LOG_LEVEL", "INFO"),
    }
