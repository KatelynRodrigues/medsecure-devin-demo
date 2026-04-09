"""Build detailed remediation prompts for Devin sessions.

Each prompt gives Devin the exact vulnerability context, code location,
and recommended fix pattern so it can produce a targeted, reviewable PR.
"""

from __future__ import annotations

from medsecure.models import SecurityFinding

# CWE-specific fix templates
_FIX_TEMPLATES: dict[str, str] = {
    "CWE-89": (
        "Fix this SQL injection vulnerability:\n"
        "- Replace string concatenation/f-string interpolation with parameterized queries\n"
        "- Use query placeholders (? for sqlite3, %s for psycopg2)\n"
        "- If using an ORM, use the ORM's query builder instead of raw SQL\n"
        "- Ensure ALL user inputs in the query are parameterized, not just some"
    ),
    "CWE-79": (
        "Fix this Cross-Site Scripting (XSS) vulnerability:\n"
        "- Use a templating engine with auto-escaping (e.g. Jinja2 with autoescape=True)\n"
        "- If building HTML strings manually, use markupsafe.escape() or html.escape()\n"
        "- Never include user input directly in HTML output"
    ),
    "CWE-798": (
        "Fix this hardcoded credentials vulnerability:\n"
        "- Move ALL secrets to environment variables using os.environ.get()\n"
        "- Add sensible error messages when required env vars are missing\n"
        "- Add the env var names to a .env.example file (without actual values)\n"
        "- Remove the hardcoded secret values entirely from the source code"
    ),
    "CWE-22": (
        "Fix this path traversal vulnerability:\n"
        "- Use pathlib.Path to resolve the full path\n"
        "- Validate the resolved path is within the expected base directory\n"
        "- Reject paths containing '..' or absolute path components\n"
        "- Consider using a whitelist of allowed filenames if applicable"
    ),
    "CWE-502": (
        "Fix this unsafe deserialization vulnerability:\n"
        "- Replace pickle.loads() with json.loads() or another safe format\n"
        "- If pickle is absolutely required, implement HMAC signature verification\n"
        "- Define a clear schema for the deserialized data\n"
        "- Never deserialize data from untrusted sources"
    ),
    "CWE-327": (
        "Fix this weak cryptographic algorithm vulnerability:\n"
        "- Replace MD5/SHA1 password hashing with bcrypt, scrypt, or argon2\n"
        "- Use the 'bcrypt' library: bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
        "- For non-password hashing, use SHA-256 or SHA-3\n"
        "- Ensure existing hashed passwords can be migrated (rehash on next login)"
    ),
    "CWE-611": (
        "Fix this XML External Entity (XXE) injection vulnerability:\n"
        "- Use defusedxml library instead of lxml/xml.etree directly\n"
        "- If using lxml, set resolve_entities=False and no_network=True\n"
        "- Disable DTD processing: "
        "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
        "- Consider using defusedxml.ElementTree.fromstring() as a drop-in replacement"
    ),
    "CWE-918": (
        "Fix this Server-Side Request Forgery (SSRF) vulnerability:\n"
        "- Validate URLs against an allowlist of permitted domains/hosts\n"
        "- Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)\n"
        "- Block requests to link-local addresses and metadata endpoints (169.254.x)\n"
        "- Use urllib.parse to parse and validate the URL before making the request"
    ),
    "CWE-117": (
        "Fix this log injection vulnerability:\n"
        "- Sanitize user input before including it in log messages\n"
        "- Remove or encode newline characters (\\n, \\r) and other control characters\n"
        "- Use structured logging (e.g. logger.info('event', extra={'username': sanitized})\n"
        "- Consider using a logging formatter that handles encoding automatically"
    ),
}


def build_prompt_for_findings(findings: list[SecurityFinding], repo: str) -> str:
    """Build a comprehensive remediation prompt for a batch of findings.

    Groups findings by file and produces detailed instructions for Devin.

    Args:
        findings: List of findings to remediate (typically from the same file).
        repo: Target repository name.

    Returns:
        A detailed prompt string for the Devin session.
    """
    header = (
        f"## Security Remediation Task\n\n"
        f"You are fixing security vulnerabilities identified by CodeQL in the "
        f"**{repo}** repository. This is a HIPAA-regulated healthcare application, "
        f"so security fixes are compliance-critical.\n\n"
        f"### Important Guidelines\n"
        f"- Fix ONLY the identified vulnerabilities — do not refactor unrelated code\n"
        f"- Preserve existing functionality and API contracts\n"
        f"- Add or update unit tests to verify the fix\n"
        f"- Follow the existing code style and conventions\n"
        f"- If a fix requires a new dependency, note it clearly in your PR description\n\n"
    )

    findings_section = "### Findings to Fix\n\n"
    for i, finding in enumerate(findings, 1):
        fix_template = _FIX_TEMPLATES.get(finding.cwe_id, finding.recommendation)
        findings_section += (
            f"#### Finding {i}: {finding.rule_name} ({finding.cwe_id})\n"
            f"- **Severity:** {finding.severity.value.upper()} ({finding.priority_label})\n"
            f"- **File:** `{finding.file_path}`\n"
            f"- **Lines:** {finding.start_line}–{finding.end_line}\n"
            f"- **Description:** {finding.message}\n"
            f"- **Vulnerable Code:**\n```python\n{finding.code_snippet}\n```\n"
            f"- **Fix Instructions:**\n{fix_template}\n\n"
        )

    footer = (
        "### PR Requirements\n"
        "- Title format: `fix(security): remediate {CWE-ID} in {filename}`\n"
        "- Include the CWE ID and finding description in the PR body\n"
        "- Tag the PR with `security-fix` label if possible\n"
        "- Ensure all existing tests still pass after your changes\n"
    )

    return header + findings_section + footer


def build_structured_output_schema() -> dict:
    """Return the JSON Schema for structured session output.

    This schema tells Devin what machine-readable data to return
    so we can automatically track remediation status.

    Returns:
        JSON Schema (Draft 7) dictionary.
    """
    return {
        "type": "object",
        "properties": {
            "findings_fixed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of finding IDs that were successfully fixed.",
            },
            "fix_confidence": {
                "type": "string",
                "enum": ["high", "medium", "low"],
                "description": "How confident Devin is in the fix quality.",
            },
            "files_modified": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of files that were modified.",
            },
            "requires_manual_review": {
                "type": "boolean",
                "description": "Whether the fix needs extra human review.",
            },
            "tests_added": {
                "type": "boolean",
                "description": "Whether new tests were added for the fix.",
            },
            "notes": {
                "type": "string",
                "description": "Any additional context about the fix.",
            },
        },
        "required": [
            "findings_fixed",
            "fix_confidence",
            "files_modified",
            "requires_manual_review",
        ],
    }
