# MedSecure Security Backlog Automation

Automated CodeQL finding remediation via the [Devin API](https://docs.devin.ai/api-reference/overview).

MedSecure is a HIPAA-regulated healthcare application where CodeQL flags dozens of security issues weekly. This automation ingests scanner output, creates Devin sessions to fix each finding, tracks remediation progress, and generates audit-ready compliance reports — closing the loop between security and engineering teams without anyone babysitting the process.

## Quick Start

```bash
# Install dependencies
pip install -e .

# Run the full pipeline in demo mode (no API keys needed)
medsecure demo

# Open the generated compliance dashboard
open output/compliance_report.html
```

## Architecture

```
CodeQL Scanner ──> SARIF Ingester ──> Priority Classifier ──> Devin Orchestrator
                                                                      │
Compliance Report <── Session Monitor <── Poll & Track <──────────────┘
       │                    │
       ▼                    ▼
  HTML Dashboard      Notification Hub (Slack + Email)
```

## Commands

```bash
# Individual pipeline stages
medsecure scan          # Generate mock CodeQL findings (SARIF format)
medsecure ingest        # Parse and prioritize findings
medsecure dispatch      # Create Devin sessions for findings
medsecure monitor       # Poll session status and collect results
medsecure report        # Generate compliance report
medsecure notify        # Send notification summaries

# Full pipeline
medsecure demo          # End-to-end with mock API (no keys needed)
medsecure run           # End-to-end with live Devin API

# Options
medsecure --verbose demo    # Debug logging
medsecure demo -o ./reports # Custom output directory
```

## Demo Mode

Running `medsecure demo` exercises the entire pipeline with mock data:

1. **Generates** 12 realistic CodeQL findings across 8 CWE categories
2. **Prioritizes** findings by severity (Critical > High > Medium > Low)
3. **Creates** mock Devin sessions grouped by file (avoids PR conflicts)
4. **Monitors** sessions through simulated lifecycle to completion
5. **Sends** mock Slack/email notifications at each state change
6. **Produces** a full HTML compliance dashboard + JSON export

Output artifacts in `output/`:
- `mock_codeql_results.sarif` — SARIF scan results
- `compliance_report.html` — Interactive HTML dashboard
- `compliance_report.json` — Machine-readable report for GRC tools
- `notifications.log` — All Slack notification payloads
- `emails/` — Generated email digests (HTML)

## Live Mode

```bash
export DEVIN_API_KEY="cog_your_key_here"
export DEVIN_ORG_ID="your_org_id"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."  # optional

medsecure run --repo your-org/your-repo
```

## Vulnerability Categories Covered

| CWE | Name | Severity |
|-----|------|----------|
| CWE-798 | Hardcoded Credentials | Critical |
| CWE-89 | SQL Injection | High |
| CWE-502 | Unsafe Deserialization | High |
| CWE-918 | Server-Side Request Forgery | High |
| CWE-79 | Cross-Site Scripting (XSS) | Medium |
| CWE-22 | Path Traversal | Medium |
| CWE-611 | XML External Entity (XXE) | Medium |
| CWE-327 | Weak Cryptographic Algorithm | Low |
| CWE-117 | Log Injection | Low |

## Project Structure

```
medsecure/
├── cli.py                  # Click CLI commands
├── config.py               # Configuration management
├── models.py               # Pydantic data models
├── scanner/                # Mock CodeQL SARIF generator
│   ├── mock_scanner.py
│   └── vulnerable_code/    # Intentionally vulnerable demo files
├── ingester/               # SARIF parsing + priority classification
│   ├── sarif_parser.py
│   └── prioritizer.py
├── orchestrator/           # Devin API session management
│   ├── devin_client.py     # Real Devin API v3 client
│   ├── mock_client.py      # Mock client for demo mode
│   ├── session_manager.py  # Session lifecycle management
│   └── prompt_builder.py   # Security-fix prompt templates
├── monitor/                # Session polling + state persistence
│   ├── poller.py
│   └── state_store.py      # SQLite state store
├── notifications/          # Slack + email notifications
│   ├── slack_notifier.py
│   └── email_notifier.py
└── reports/                # Compliance report generation
    ├── generator.py
    ├── html_report.py
    └── templates/
        └── dashboard.html  # Jinja2 HTML dashboard
```

## How It Closes the Loop

| Traditional Flow | MedSecure Automation |
|-----------------|---------------------|
| Scanner finds issue → ticket filed → sits in backlog | Scanner finds issue → Devin fixes it → PR ready for review |
| Security team nags engineering monthly | Automated notifications at each state change |
| Audit asks "what's the status?" → scramble | Real-time compliance dashboard |
| Average remediation: weeks/months | Average remediation: hours |

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
