"""Mock CodeQL scanner that generates realistic SARIF output.

Produces findings across multiple CWE categories with realistic
file paths, line numbers, code snippets, and severity levels.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Vulnerability definitions
# ---------------------------------------------------------------------------

VULNERABILITY_DEFINITIONS: list[dict] = [
    {
        "rule_id": "py/sql-injection",
        "rule_name": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "file": "medsecure/scanner/vulnerable_code/auth_service.py",
        "start_line": 23,
        "end_line": 25,
        "message": (
            "This SQL query depends on a user-provided value. "
            "User-controlled data is concatenated into the SQL string "
            "without sanitization, enabling SQL injection."
        ),
        "snippet": (
            'query = f"SELECT * FROM users WHERE username = \'{username}\' '
            'AND password = \'{password}\'"'
        ),
        "recommendation": (
            "Use parameterized queries or an ORM to prevent SQL injection. "
            "Replace string concatenation with query parameters."
        ),
    },
    {
        "rule_id": "py/sql-injection",
        "rule_name": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "file": "medsecure/scanner/vulnerable_code/data_handler.py",
        "start_line": 45,
        "end_line": 47,
        "message": (
            "This SQL query uses string formatting with user input in a "
            "patient records search, allowing SQL injection."
        ),
        "snippet": (
            'cursor.execute("SELECT * FROM patients WHERE name LIKE \'%"'
            " + search_term + \"%'\")"
        ),
        "recommendation": (
            "Use parameterized queries with placeholders. "
            "For LIKE queries, pass the pattern as a parameter."
        ),
    },
    {
        "rule_id": "py/xss",
        "rule_name": "Cross-Site Scripting (Reflected XSS)",
        "cwe_id": "CWE-79",
        "severity": "medium",
        "file": "medsecure/scanner/vulnerable_code/api_client.py",
        "start_line": 67,
        "end_line": 69,
        "message": (
            "User-controlled input is included in HTML output without "
            "escaping, enabling reflected cross-site scripting."
        ),
        "snippet": (
            'return f"<div class=\'alert\'>{error_message}</div>"'
        ),
        "recommendation": (
            "Use a templating engine with auto-escaping enabled, "
            "or explicitly escape HTML entities before rendering."
        ),
    },
    {
        "rule_id": "py/hardcoded-credentials",
        "rule_name": "Hardcoded Credentials",
        "cwe_id": "CWE-798",
        "severity": "critical",
        "file": "medsecure/scanner/vulnerable_code/config_loader.py",
        "start_line": 12,
        "end_line": 15,
        "message": (
            "Database credentials are hardcoded in the source code. "
            "This exposes sensitive credentials in version control."
        ),
        "snippet": (
            'DB_PASSWORD = "MedSecure_Prod_2024!"\n'
            'API_SECRET = "sk-prod-a1b2c3d4e5f6"'
        ),
        "recommendation": (
            "Move credentials to environment variables or a secrets "
            "manager. Never commit secrets to source control."
        ),
    },
    {
        "rule_id": "py/path-traversal",
        "rule_name": "Path Traversal",
        "cwe_id": "CWE-22",
        "severity": "medium",
        "file": "medsecure/scanner/vulnerable_code/data_handler.py",
        "start_line": 78,
        "end_line": 80,
        "message": (
            "User-controlled file path is used to read files without "
            "validation, enabling path traversal attacks."
        ),
        "snippet": (
            "def get_report(report_name: str) -> str:\n"
            '    with open(f"/var/reports/{report_name}") as f:\n'
            "        return f.read()"
        ),
        "recommendation": (
            "Validate and sanitize file paths. Use pathlib to resolve "
            "the path and ensure it stays within the intended directory."
        ),
    },
    {
        "rule_id": "py/unsafe-deserialization",
        "rule_name": "Deserialization of Untrusted Data",
        "cwe_id": "CWE-502",
        "severity": "high",
        "file": "medsecure/scanner/vulnerable_code/data_handler.py",
        "start_line": 92,
        "end_line": 94,
        "message": (
            "pickle.loads() is called on data from an untrusted source. "
            "Deserializing untrusted data can lead to arbitrary code execution."
        ),
        "snippet": (
            "def load_session(session_data: bytes) -> dict:\n"
            "    return pickle.loads(session_data)"
        ),
        "recommendation": (
            "Use a safe serialization format like JSON. "
            "If pickle is required, use hmac signing to verify data integrity."
        ),
    },
    {
        "rule_id": "py/weak-crypto",
        "rule_name": "Use of Broken Cryptographic Algorithm",
        "cwe_id": "CWE-327",
        "severity": "low",
        "file": "medsecure/scanner/vulnerable_code/auth_service.py",
        "start_line": 51,
        "end_line": 53,
        "message": (
            "MD5 is used for hashing passwords. MD5 is cryptographically "
            "broken and unsuitable for password hashing."
        ),
        "snippet": (
            "def hash_password(password: str) -> str:\n"
            "    return hashlib.md5(password.encode()).hexdigest()"
        ),
        "recommendation": (
            "Use a modern password hashing algorithm like bcrypt, scrypt, "
            "or argon2. Use the 'bcrypt' or 'passlib' library."
        ),
    },
    {
        "rule_id": "py/xxe",
        "rule_name": "XML External Entity (XXE) Injection",
        "cwe_id": "CWE-611",
        "severity": "medium",
        "file": "medsecure/scanner/vulnerable_code/data_handler.py",
        "start_line": 110,
        "end_line": 113,
        "message": (
            "XML parsing with external entity processing enabled. "
            "An attacker could read local files or perform SSRF via XXE."
        ),
        "snippet": (
            "def parse_medical_record(xml_data: str) -> dict:\n"
            "    parser = etree.XMLParser(resolve_entities=True)\n"
            "    root = etree.fromstring(xml_data.encode(), parser)"
        ),
        "recommendation": (
            "Disable external entity processing in the XML parser. "
            "Use defusedxml library for safe XML parsing."
        ),
    },
    {
        "rule_id": "py/ssrf",
        "rule_name": "Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "severity": "high",
        "file": "medsecure/scanner/vulnerable_code/api_client.py",
        "start_line": 34,
        "end_line": 36,
        "message": (
            "User-controlled URL is passed directly to an HTTP request "
            "without validation, enabling SSRF attacks."
        ),
        "snippet": (
            "def fetch_external_data(url: str) -> dict:\n"
            "    response = requests.get(url)\n"
            "    return response.json()"
        ),
        "recommendation": (
            "Validate URLs against an allowlist of permitted domains. "
            "Block requests to private IP ranges and localhost."
        ),
    },
    {
        "rule_id": "py/hardcoded-credentials",
        "rule_name": "Hardcoded Credentials",
        "cwe_id": "CWE-798",
        "severity": "critical",
        "file": "medsecure/scanner/vulnerable_code/api_client.py",
        "start_line": 8,
        "end_line": 10,
        "message": (
            "API key is hardcoded in source code. "
            "This key provides access to the HIPAA-protected patient data API."
        ),
        "snippet": (
            'PATIENT_API_KEY = "pk_live_MedSecure_HIPAA_9x8y7z"\n'
            'INTERNAL_SERVICE_TOKEN = "svc_medsecure_internal_prod"'
        ),
        "recommendation": (
            "Store API keys in environment variables or a secrets manager "
            "such as AWS Secrets Manager or HashiCorp Vault."
        ),
    },
    {
        "rule_id": "py/sql-injection",
        "rule_name": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "high",
        "file": "medsecure/scanner/vulnerable_code/auth_service.py",
        "start_line": 38,
        "end_line": 40,
        "message": (
            "User input is interpolated into a SQL query for role-based "
            "access control, enabling privilege escalation via SQL injection."
        ),
        "snippet": (
            "def check_permission(user_id: str, resource: str) -> bool:\n"
            '    query = f"SELECT role FROM acl WHERE user_id = \'{user_id}\' '
            "AND resource = '{resource}'\""
        ),
        "recommendation": (
            "Use parameterized queries. Never interpolate user input "
            "into SQL strings, especially in authorization checks."
        ),
    },
    {
        "rule_id": "py/log-injection",
        "rule_name": "Log Injection",
        "cwe_id": "CWE-117",
        "severity": "low",
        "file": "medsecure/scanner/vulnerable_code/auth_service.py",
        "start_line": 62,
        "end_line": 64,
        "message": (
            "User-controlled input is written to log files without "
            "sanitization, enabling log forging attacks."
        ),
        "snippet": (
            "def log_login_attempt(username: str, success: bool) -> None:\n"
            '    logger.info(f"Login attempt: user={username} success={success}")'
        ),
        "recommendation": (
            "Sanitize user input before logging. Remove or encode "
            "newline characters and other control characters."
        ),
    },
]


def _build_sarif_result(vuln: dict, index: int) -> dict:
    """Build a single SARIF result entry from a vulnerability definition."""
    return {
        "ruleId": vuln["rule_id"],
        "ruleIndex": index,
        "level": {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }[vuln["severity"]],
        "message": {"text": vuln["message"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": vuln["file"], "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": vuln["start_line"],
                        "endLine": vuln["end_line"],
                        "snippet": {"text": vuln["snippet"]},
                    },
                }
            }
        ],
        "fingerprints": {
            "primaryLocationLineHash": uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{vuln['file']}:{vuln['start_line']}:{vuln['rule_id']}",
            ).hex[:16]
        },
        "properties": {
            "cwe": vuln["cwe_id"],
            "severity": vuln["severity"],
            "recommendation": vuln["recommendation"],
        },
    }


def _build_sarif_rule(vuln: dict) -> dict:
    """Build a SARIF rule descriptor."""
    return {
        "id": vuln["rule_id"],
        "name": vuln["rule_name"],
        "shortDescription": {"text": vuln["rule_name"]},
        "fullDescription": {"text": vuln["message"]},
        "help": {
            "text": vuln["recommendation"],
            "markdown": f"**Recommendation:** {vuln['recommendation']}",
        },
        "properties": {
            "tags": ["security", vuln["cwe_id"]],
            "precision": "high",
            "severity": vuln["severity"],
        },
    }


def generate_sarif(output_path: Path | None = None) -> dict:
    """Generate a complete SARIF v2.1.0 report with mock CodeQL findings.

    Args:
        output_path: Optional path to write the SARIF JSON file.

    Returns:
        The SARIF report as a dictionary.
    """
    # Deduplicate rules by rule_id
    seen_rules: dict[str, dict] = {}
    rule_index_map: dict[str, int] = {}
    for vuln in VULNERABILITY_DEFINITIONS:
        if vuln["rule_id"] not in seen_rules:
            seen_rules[vuln["rule_id"]] = vuln
            rule_index_map[vuln["rule_id"]] = len(seen_rules) - 1

    rules = [_build_sarif_rule(seen_rules[rid]) for rid in seen_rules]
    results = [
        _build_sarif_result(vuln, rule_index_map[vuln["rule_id"]])
        for vuln in VULNERABILITY_DEFINITIONS
    ]

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "organization": "GitHub",
                        "semanticVersion": "2.16.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"medsecure-codeql-scan/{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).isoformat(),
                    }
                ],
            }
        ],
    }

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(sarif, indent=2))

    return sarif
