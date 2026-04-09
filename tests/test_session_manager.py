"""Tests for session management."""

from medsecure.config import PipelineConfig
from medsecure.ingester.prioritizer import group_by_file, prioritize
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.orchestrator.session_manager import SessionManager
from medsecure.scanner.mock_scanner import generate_sarif


def _get_test_batches():
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    prioritized = prioritize(findings)
    return group_by_file(prioritized), prioritized


def test_dispatch_creates_sessions() -> None:
    config = PipelineConfig(demo_mode=True)
    batches, _ = _get_test_batches()

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        assert len(sessions) == len(batches)


def test_dispatch_session_has_finding_ids() -> None:
    config = PipelineConfig(demo_mode=True)
    batches, _ = _get_test_batches()

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        for session in sessions:
            assert len(session.finding_ids) > 0


def test_dispatch_session_has_url() -> None:
    config = PipelineConfig(demo_mode=True)
    batches, _ = _get_test_batches()

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        for session in sessions:
            assert session.session_url.startswith("https://")


def test_wait_for_completion_resolves() -> None:
    config = PipelineConfig(demo_mode=True)
    batches, _ = _get_test_batches()

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        completed = manager.wait_for_completion(sessions, timeout_seconds=30)
        # All sessions should have a terminal status
        for session in completed:
            assert session.status in ("exit", "error", "suspended")


def test_completed_sessions_have_prs() -> None:
    config = PipelineConfig(demo_mode=True)
    batches, _ = _get_test_batches()

    with SessionManager(config) as manager:
        sessions = manager.dispatch_findings(batches)
        completed = manager.wait_for_completion(sessions, timeout_seconds=30)
        # Completed sessions should have PR URLs
        successful = [s for s in completed if s.status == "exit"]
        for session in successful:
            assert session.pr_url is not None
