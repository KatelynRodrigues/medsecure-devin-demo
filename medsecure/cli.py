"""CLI entry point for the MedSecure Security Backlog Automation.

Provides commands to run the full pipeline or individual stages,
plus a demo mode that exercises everything with mock data.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from medsecure.config import PipelineConfig
from medsecure.ingester.prioritizer import group_by_file, prioritize
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.models import Severity
from medsecure.monitor.poller import get_remediation_stats, sync_session_results
from medsecure.monitor.state_store import StateStore
from medsecure.notifications.email_notifier import EmailNotifier
from medsecure.notifications.slack_notifier import SlackNotifier
from medsecure.orchestrator.session_manager import SessionManager
from medsecure.reports.generator import build_report, build_scan_summary, export_json
from medsecure.reports.html_report import render_dashboard
from medsecure.scanner.mock_scanner import generate_sarif

console = Console()


def _setup_logging(verbose: bool = False) -> None:
    """Configure rich logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """MedSecure Security Backlog Automation.

    Automated CodeQL finding remediation via the Devin API.
    """
    _setup_logging(verbose)


@cli.command()
@click.option("--output", "-o", type=click.Path(), default="output/mock_codeql_results.sarif")
def scan(output: str) -> None:
    """Generate mock CodeQL scan results (SARIF format)."""
    output_path = Path(output)
    console.print(Panel("[bold]Generating mock CodeQL scan results...[/bold]", style="blue"))

    sarif = generate_sarif(output_path)
    result_count = len(sarif["runs"][0]["results"])

    console.print(f"  Generated [bold]{result_count}[/bold] findings")
    console.print(f"  SARIF output: [cyan]{output_path}[/cyan]")
    console.print("[green]Scan complete.[/green]")


@cli.command()
@click.option("--sarif-file", "-f", type=click.Path(exists=True), default=None)
def ingest(sarif_file: str | None) -> None:
    """Parse SARIF results and prioritize findings."""
    console.print(Panel("[bold]Ingesting and prioritizing findings...[/bold]", style="blue"))

    if sarif_file:
        with open(sarif_file) as f:
            sarif_data = json.load(f)
    else:
        console.print("  No SARIF file provided — generating mock scan data...")
        sarif_data = generate_sarif()

    from medsecure.ingester.sarif_parser import parse_sarif

    findings = parse_sarif(sarif_data)
    prioritized = prioritize(findings)

    table = Table(title="Prioritized Security Findings")
    table.add_column("Priority", style="bold")
    table.add_column("CWE", style="cyan")
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Severity")

    severity_styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for finding in prioritized:
        table.add_row(
            finding.priority_label,
            finding.cwe_id,
            finding.rule_name,
            finding.file_path.split("/")[-1],
            str(finding.start_line),
            f"[{severity_styles[finding.severity]}]{finding.severity.value.upper()}[/]",
        )

    console.print(table)
    console.print(f"\n  Total: [bold]{len(prioritized)}[/bold] unique findings")


@cli.command()
@click.option("--demo/--live", default=True, help="Use mock Devin API (demo) or real API (live)")
def dispatch(demo: bool) -> None:
    """Create Devin sessions to remediate findings."""
    config = PipelineConfig.from_env()
    config.demo_mode = demo

    if not demo and (not config.devin.api_key or not config.devin.org_id):
        console.print(
            "[red]Error:[/red] DEVIN_API_KEY and DEVIN_ORG_ID must be set for live mode."
        )
        sys.exit(1)

    console.print(
        Panel(
            f"[bold]Dispatching remediation sessions ({'DEMO' if demo else 'LIVE'} mode)[/bold]",
            style="blue",
        )
    )

    # Generate and prioritize findings
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)
    batches = group_by_file(prioritized)

    console.print(
        f"  Found [bold]{len(prioritized)}[/bold] findings"
        f" in [bold]{len(batches)}[/bold] file batches"
    )

    # Create sessions
    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)

        table = Table(title="Created Remediation Sessions")
        table.add_column("Session ID")
        table.add_column("Findings", justify="right")
        table.add_column("Status")
        table.add_column("URL")

        for session in sessions:
            table.add_row(
                session.session_id[:24] + "...",
                str(len(session.finding_ids)),
                session.status,
                session.session_url,
            )

        console.print(table)
        console.print(f"\n  Dispatched [bold]{len(sessions)}[/bold] sessions")


@cli.command()
@click.option("--demo/--live", default=True)
def monitor(demo: bool) -> None:
    """Poll active sessions and track progress."""
    config = PipelineConfig.from_env()
    config.demo_mode = demo

    console.print(Panel("[bold]Monitoring active sessions...[/bold]", style="blue"))

    # In a real scenario, this would load sessions from the state store
    # and poll them. For the CLI, we dispatch + monitor in one go.
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)
    batches = group_by_file(prioritized)

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        console.print(f"  Monitoring [bold]{len(sessions)}[/bold] sessions...")

        completed = manager.wait_for_completion(sessions, timeout_seconds=120)

        # Persist results
        config.output_dir.mkdir(parents=True, exist_ok=True)
        with StateStore(config.db_path) as store:
            sync_session_results(completed, prioritized, store)
            store.save_findings(prioritized)

        stats = get_remediation_stats(prioritized)
        console.print(f"\n  Completed: [green]{stats['completed']}[/green]")
        console.print(f"  Failed: [red]{stats['failed']}[/red]")
        console.print(f"  In progress: [blue]{stats['running']}[/blue]")


@cli.command()
@click.option("--output-dir", "-o", type=click.Path(), default="output")
def report(output_dir: str) -> None:
    """Generate compliance report from current state."""
    out = Path(output_dir)
    console.print(Panel("[bold]Generating compliance report...[/bold]", style="blue"))

    # Load from state store if available, otherwise generate fresh
    db_path = out / "medsecure_state.db"
    if db_path.exists():
        with StateStore(db_path) as store:
            findings = store.get_all_findings()
            sessions = store.get_all_sessions()
    else:
        console.print("  No state database found — generating from mock data...")
        sarif = generate_sarif()
        findings = parse_sarif(sarif)
        findings = prioritize(findings)
        sessions = []

    summary = build_scan_summary(findings)
    remediation_report = build_report(summary, findings, sessions)

    # Export JSON
    json_path = export_json(remediation_report, out / "compliance_report.json")
    console.print(f"  JSON report: [cyan]{json_path}[/cyan]")

    # Render HTML dashboard
    html_path = render_dashboard(remediation_report, out / "compliance_report.html")
    console.print(f"  HTML dashboard: [cyan]{html_path}[/cyan]")

    console.print(f"\n  Remediation rate: [bold]{remediation_report.remediation_rate:.0f}%[/bold]")
    console.print("[green]Report generated.[/green]")


@cli.command()
@click.option("--demo/--live", default=True)
def notify(demo: bool) -> None:
    """Send notification summaries."""
    config = PipelineConfig.from_env()
    config.demo_mode = demo

    console.print(Panel("[bold]Sending notifications...[/bold]", style="blue"))

    # Generate data for notifications
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)
    summary = build_scan_summary(prioritized)

    # Slack notifications
    slack = SlackNotifier(
        webhook_url=config.notifications.slack_webhook_url,
        channel=config.notifications.slack_channel,
        demo_mode=demo,
        log_path=config.output_dir / "notifications.log",
    )
    slack.notify_scan_complete(summary)
    console.print("  Sent scan summary notification")

    # Email notifications
    email = EmailNotifier(
        security_recipients=config.notifications.email_recipients_security,
        engineering_recipients=config.notifications.email_recipients_engineering,
        demo_mode=demo,
        output_dir=config.output_dir / "emails",
    )
    email.send_scan_digest(summary)
    console.print("  Sent scan digest email")

    notif_count = len(slack.get_notification_log())
    console.print(f"\n  Total notifications: [bold]{notif_count}[/bold]")
    console.print("[green]Notifications sent.[/green]")


@cli.command(name="demo")
@click.option("--output-dir", "-o", type=click.Path(), default="output")
def demo_pipeline(output_dir: str) -> None:
    """Run the full pipeline end-to-end in demo mode.

    This exercises every component with mock data and mock API calls,
    producing a compliance report you can open in a browser.
    """
    out = Path(output_dir)
    config = PipelineConfig(demo_mode=True, output_dir=out, db_path=out / "medsecure_state.db")

    console.print(
        Panel(
            "[bold white on blue] MedSecure Security Backlog Automation"
            " — DEMO MODE [/bold white on blue]",
            style="blue",
        )
    )

    # ── Step 1: Scan ──────────────────────────────────────────────
    console.print("\n[bold cyan]Step 1/6:[/bold cyan] Generating mock CodeQL scan results...")
    sarif_path = out / "mock_codeql_results.sarif"
    sarif = generate_sarif(sarif_path)
    result_count = len(sarif["runs"][0]["results"])
    console.print(f"  Generated [bold]{result_count}[/bold] findings -> [cyan]{sarif_path}[/cyan]")

    # ── Step 2: Ingest & Prioritize ───────────────────────────────
    console.print("\n[bold cyan]Step 2/6:[/bold cyan] Ingesting and prioritizing findings...")
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)

    severity_counts = {s: 0 for s in Severity}
    for f in prioritized:
        severity_counts[f.severity] += 1

    table = Table(title="Prioritized Findings Summary", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev, count in severity_counts.items():
        style = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}[sev.value]
        table.add_row(f"[{style}]{sev.value.upper()}[/]", str(count))
    console.print(table)

    # ── Step 3: Batch & Dispatch ──────────────────────────────────
    console.print("\n[bold cyan]Step 3/6:[/bold cyan] Creating Devin remediation sessions...")
    batches = group_by_file(prioritized)
    console.print(f"  Grouped into [bold]{len(batches)}[/bold] file-based batches")

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)

        session_table = Table(title="Dispatched Sessions")
        session_table.add_column("Session ID")
        session_table.add_column("Findings", justify="right")
        session_table.add_column("CWEs")
        for session in sessions:
            # Find the CWEs for this session's findings
            session_findings = [
                f for f in prioritized if f.finding_id in session.finding_ids
            ]
            cwes = ", ".join(sorted({f.cwe_id for f in session_findings}))
            session_table.add_row(
                session.session_id[:28] + "...",
                str(len(session.finding_ids)),
                cwes,
            )
        console.print(session_table)

        # ── Step 4: Monitor ───────────────────────────────────────
        console.print("\n[bold cyan]Step 4/6:[/bold cyan] Monitoring sessions until completion...")
        completed = manager.wait_for_completion(sessions, timeout_seconds=60)

    # ── Persist state ─────────────────────────────────────────────
    with StateStore(config.db_path) as store:
        sync_session_results(completed, prioritized, store)
        store.save_findings(prioritized)
        store.save_sessions(completed)

    # ── Step 5: Notify ────────────────────────────────────────────
    console.print("\n[bold cyan]Step 5/6:[/bold cyan] Sending notifications...")
    summary = build_scan_summary(prioritized)

    slack = SlackNotifier(
        demo_mode=True, log_path=out / "notifications.log"
    )
    slack.notify_scan_complete(summary)

    for session in completed:
        session_findings = [f for f in prioritized if f.finding_id in session.finding_ids]
        slack.notify_session_created(session, session_findings)
        if session.pr_url:
            slack.notify_pr_created(session)
        if session.status in ("error", "suspended"):
            slack.notify_failure(session)

    email = EmailNotifier(demo_mode=True, output_dir=out / "emails")
    email.send_scan_digest(summary)

    console.print(f"  Logged [bold]{len(slack.get_notification_log())}[/bold] Slack notifications")
    console.print(f"  Generated email digest -> [cyan]{out / 'emails'}[/cyan]")

    # ── Step 6: Report ────────────────────────────────────────────
    console.print("\n[bold cyan]Step 6/6:[/bold cyan] Generating compliance report...")
    remediation_report = build_report(summary, prioritized, completed)

    json_path = export_json(remediation_report, out / "compliance_report.json")
    html_path = render_dashboard(remediation_report, out / "compliance_report.html")

    # Send compliance email
    email.send_compliance_report(remediation_report)

    console.print(f"  JSON report: [cyan]{json_path}[/cyan]")
    console.print(f"  HTML dashboard: [cyan]{html_path}[/cyan]")

    # ── Final Summary ─────────────────────────────────────────────
    stats = get_remediation_stats(prioritized)
    console.print(
        Panel(
            f"[bold green]Pipeline Complete![/bold green]\n\n"
            f"  Total findings:   {stats['total']}\n"
            f"  Remediated:       [green]{stats['completed']}[/green]\n"
            f"  In progress:      [blue]{stats['running'] + stats['dispatched']}[/blue]\n"
            f"  Failed/Review:    [red]{stats['failed'] + stats['needs_review']}[/red]\n"
            f"  Pending:          {stats['pending']}\n"
            f"  Remediation rate: [bold]{remediation_report.remediation_rate:.0f}%[/bold]\n\n"
            f"  Open the HTML dashboard:\n"
            f"    [cyan]open {html_path}[/cyan]",
            title="Summary",
            style="green",
        )
    )


@cli.command(name="run")
@click.option("--repo", default="KatelynRodrigues/medsecure-devin-demo", help="Target repository")
@click.option("--output-dir", "-o", type=click.Path(), default="output")
def run_pipeline(repo: str, output_dir: str) -> None:
    """Run the full pipeline with live Devin API calls.

    Requires DEVIN_API_KEY and DEVIN_ORG_ID environment variables.
    """
    config = PipelineConfig.from_env()
    config.target_repo = repo
    config.output_dir = Path(output_dir)
    config.db_path = config.output_dir / "medsecure_state.db"
    config.demo_mode = False

    if not config.devin.api_key or not config.devin.org_id:
        console.print(
            "[red]Error:[/red] Set DEVIN_API_KEY and DEVIN_ORG_ID environment variables.\n"
            "  Get these from https://app.devin.ai/settings\n\n"
            "  Or run [cyan]medsecure demo[/cyan] for a full demo without API keys."
        )
        sys.exit(1)

    console.print(
        Panel(
            f"[bold white on green] MedSecure Security Backlog Automation"
            f" — LIVE MODE [/bold white on green]\n"
            f"  Target repo: {repo}",
            style="green",
        )
    )

    # The live pipeline follows the same steps as demo, but with real API calls
    # Step 1: Scan
    console.print("\n[bold cyan]Step 1/6:[/bold cyan] Generating CodeQL scan results...")
    sarif_path = config.output_dir / "codeql_results.sarif"
    sarif = generate_sarif(sarif_path)

    # Step 2: Ingest & Prioritize
    console.print("\n[bold cyan]Step 2/6:[/bold cyan] Ingesting and prioritizing...")
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)
    console.print(f"  {len(prioritized)} findings prioritized")

    # Step 3: Dispatch
    console.print("\n[bold cyan]Step 3/6:[/bold cyan] Creating Devin sessions...")
    batches = group_by_file(prioritized)

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        console.print(f"  Created {len(sessions)} sessions")

        for s in sessions:
            console.print(f"    {s.session_id} -> {s.session_url}")

        # Step 4: Monitor
        console.print("\n[bold cyan]Step 4/6:[/bold cyan] Monitoring sessions...")
        completed = manager.wait_for_completion(sessions, timeout_seconds=3600)

    # Step 5: Notify
    console.print("\n[bold cyan]Step 5/6:[/bold cyan] Sending notifications...")
    summary = build_scan_summary(prioritized)

    slack = SlackNotifier(
        webhook_url=config.notifications.slack_webhook_url,
        channel=config.notifications.slack_channel,
        demo_mode=not bool(config.notifications.slack_webhook_url),
        log_path=config.output_dir / "notifications.log",
    )
    slack.notify_scan_complete(summary)
    for session in completed:
        if session.pr_url:
            slack.notify_pr_created(session)

    email = EmailNotifier(
        demo_mode=True,
        output_dir=config.output_dir / "emails",
    )
    email.send_scan_digest(summary)

    # Step 6: Report
    console.print("\n[bold cyan]Step 6/6:[/bold cyan] Generating report...")
    with StateStore(config.db_path) as store:
        sync_session_results(completed, prioritized, store)
        store.save_findings(prioritized)

    remediation_report = build_report(summary, prioritized, completed)
    json_path = export_json(remediation_report, config.output_dir / "compliance_report.json")
    html_path = render_dashboard(remediation_report, config.output_dir / "compliance_report.html")

    console.print(f"\n  HTML dashboard: [cyan]{html_path}[/cyan]")
    console.print(f"  JSON report: [cyan]{json_path}[/cyan]")

    console.print(
        f"\n  [bold]Remediation rate: {remediation_report.remediation_rate:.0f}%[/bold]"
    )
