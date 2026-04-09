"""External API client with intentional security vulnerabilities.

WARNING: This file contains INTENTIONAL vulnerabilities for demonstration
purposes. Do NOT use this code in production.
"""

from __future__ import annotations

import requests  # type: ignore[import-untyped]

# VULNERABILITY: CWE-798 Hardcoded Credentials
# API keys hardcoded in source code.
PATIENT_API_KEY = "pk_live_MedSecure_HIPAA_9x8y7z"
INTERNAL_SERVICE_TOKEN = "svc_medsecure_internal_prod"

API_BASE_URL = "https://api.medsecure.example.com/v1"


def get_patient_record(patient_id: str) -> dict:
    """Fetch a patient record from the external API."""
    headers = {
        "Authorization": f"Bearer {PATIENT_API_KEY}",
        "X-Service-Token": INTERNAL_SERVICE_TOKEN,
    }
    response = requests.get(
        f"{API_BASE_URL}/patients/{patient_id}",
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def fetch_external_data(url: str) -> dict:
    """Fetch data from an external URL.

    VULNERABILITY: CWE-918 Server-Side Request Forgery (SSRF)
    User-controlled URL passed directly to HTTP request without validation.
    """
    response = requests.get(url)
    return response.json()


def render_error_page(error_message: str) -> str:
    """Render an error message as HTML.

    VULNERABILITY: CWE-79 Cross-Site Scripting (Reflected XSS)
    User-controlled input included in HTML without escaping.
    """
    return f"<div class='alert alert-danger'>{error_message}</div>"


def submit_lab_results(patient_id: str, results: dict) -> dict:
    """Submit lab results to the external API."""
    headers = {
        "Authorization": f"Bearer {PATIENT_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        f"{API_BASE_URL}/patients/{patient_id}/labs",
        headers=headers,
        json=results,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()
