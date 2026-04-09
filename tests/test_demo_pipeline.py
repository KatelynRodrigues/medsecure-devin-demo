"""End-to-end test of the full demo pipeline."""

from pathlib import Path

from medsecure.config import PipelineConfig
from medsecure.ingester.prioritizer import group_by_file, prioritize
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.models import FindingStatus, Severity
from medsecure.monitor.poller import get_remediation_stats, sync_session_results
from medsecure.monitor.state_store import StateStore
from medsecure.notifications.email_notifier import EmailNotifier
from medsecure.notifications.slack_notifier import SlackNotifier
from medsecure.orchestrator.session_manager import SessionManager
from medsecure.reports.generator import build_report, build_scan_summary, export_json
from medsecure.reports.html_report import render_dashboard
from medsecure.scanner.mock_scanner import generate_sarif


def test_full_demo_pipeline(tmp_path: Path) -> None:
    """Run the entire pipeline end-to-end with mock data."""
    config = PipelineConfig(
        demo_mode=True,
        output_dir=tmp_path,
        db_path=tmp_path / "test.db",
    )

    # Step 1: Scan
    sarif = generate_sarif(tmp_path / "scan.sarif")
    assert (tmp_path / "scan.sarif").exists()

    # Step 2: Ingest & Prioritize
    findings = parse_sarif(sarif)
    assert len(findings) == 12  # Our mock scanner produces 12 findings

    prioritized = prioritize(findings)
    assert len(prioritized) == 12  # No duplicates in mock data

    # Verify severity distribution
    critical = [f for f in prioritized if f.severity == Severity.CRITICAL]
    high = [f for f in prioritized if f.severity == Severity.HIGH]
    assert len(critical) >= 2  # Hardcoded credentials
    assert len(high) >= 3  # SQL injection, deserialization, SSRF

    # Step 3: Batch & Dispatch
    batches = group_by_file(prioritized)
    assert len(batches) == 4  # 4 vulnerable files

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        assert len(sessions) == 4

        # Step 4: Monitor
        completed = manager.wait_for_completion(sessions, timeout_seconds=30)
        assert all(s.status in ("exit", "error", "suspended") for s in completed)

    # Step 5: Persist & Sync
    with StateStore(config.db_path) as store:
        sync_session_results(completed, prioritized, store)
        store.save_findings(prioritized)
        store.save_sessions(completed)

        # Verify persistence
        saved_findings = store.get_all_findings()
        assert len(saved_findings) == 12

        saved_sessions = store.get_all_sessions()
        assert len(saved_sessions) == 4

    # Step 6: Notify
    slack = SlackNotifier(demo_mode=True, log_path=tmp_path / "notifications.log")
    summary = build_scan_summary(prioritized)
    slack.notify_scan_complete(summary)
    for session in completed:
        if session.pr_url:
            slack.notify_pr_created(session)
    assert len(slack.get_notification_log()) >= 1

    email = EmailNotifier(demo_mode=True, output_dir=tmp_path / "emails")
    email.send_scan_digest(summary)
    assert (tmp_path / "emails" / "scan_digest.html").exists()

    # Step 7: Report
    report = build_report(summary, prioritized, completed)
    assert report.total_findings == 12
    assert report.remediation_rate >= 0

    json_path = export_json(report, tmp_path / "report.json")
    assert json_path.exists()

    html_path = render_dashboard(report, tmp_path / "dashboard.html")
    assert html_path.exists()

    # Verify HTML content
    html_content = html_path.read_text()
    assert "MedSecure" in html_content
    assert "Remediation Rate" in html_content


def test_state_store_roundtrip(tmp_path: Path) -> None:
    """Test saving and loading findings/sessions from the state store."""
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)

    with StateStore(tmp_path / "test.db") as store:
        store.save_findings(prioritized)
        loaded = store.get_all_findings()
        assert len(loaded) == len(prioritized)

        # Verify fields are preserved (compare by finding_id, not position)
        loaded_by_id = {f.finding_id: f for f in loaded}
        for original in prioritized:
            loaded_f = loaded_by_id[original.finding_id]
            assert original.cwe_id == loaded_f.cwe_id
            assert original.severity == loaded_f.severity


def test_remediation_stats() -> None:
    """Test remediation statistics calculation."""
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)

    # All pending initially
    stats = get_remediation_stats(prioritized)
    assert stats["total"] == len(prioritized)
    assert stats["pending"] == len(prioritized)
    assert stats["completed"] == 0

    # Mark some as completed
    for f in prioritized[:3]:
        f.status = FindingStatus.COMPLETED
    stats = get_remediation_stats(prioritized)
    assert stats["completed"] == 3
