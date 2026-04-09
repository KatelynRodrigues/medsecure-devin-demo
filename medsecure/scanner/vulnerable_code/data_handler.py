"""Data handling service with intentional security vulnerabilities.

WARNING: This file contains INTENTIONAL vulnerabilities for demonstration
purposes. Do NOT use this code in production.
"""

from __future__ import annotations

import pickle
import sqlite3
from typing import Any

from lxml import etree  # type: ignore[import-untyped]

# Database connection (simplified for demo)
_db_path = ":memory:"


def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(_db_path)


def search_patients(search_term: str) -> list[dict]:
    """Search for patients by name.

    VULNERABILITY: CWE-89 SQL Injection
    User input is concatenated into SQL query string.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM patients WHERE name LIKE '%" + search_term + "%'")
    rows = cursor.fetchall()
    conn.close()
    return [
        {"id": row[0], "name": row[1], "dob": row[2], "mrn": row[3]}
        for row in rows
    ]


def get_report(report_name: str) -> str:
    """Retrieve a medical report by filename.

    VULNERABILITY: CWE-22 Path Traversal
    User-controlled file path used without validation.
    """
    with open(f"/var/reports/{report_name}") as f:
        return f.read()


def load_session(session_data: bytes) -> dict:
    """Load session data from serialized bytes.

    VULNERABILITY: CWE-502 Deserialization of Untrusted Data
    pickle.loads() called on untrusted data allows arbitrary code execution.
    """
    return pickle.loads(session_data)  # noqa: S301


def parse_medical_record(xml_data: str) -> dict[str, Any]:
    """Parse a medical record from XML.

    VULNERABILITY: CWE-611 XML External Entity (XXE) Injection
    XML parsing with external entity processing enabled.
    """
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_data.encode(), parser)
    return {
        "patient_id": root.findtext("patient_id", ""),
        "name": root.findtext("name", ""),
        "diagnosis": root.findtext("diagnosis", ""),
    }
