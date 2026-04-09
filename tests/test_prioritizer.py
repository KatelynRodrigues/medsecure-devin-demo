"""Tests for finding prioritization."""

from medsecure.ingester.prioritizer import (
    apply_severity_overrides,
    deduplicate,
    group_by_file,
    prioritize,
    sort_by_priority,
)
from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.models import Severity
from medsecure.scanner.mock_scanner import generate_sarif


def _get_test_findings():
    sarif = generate_sarif()
    return parse_sarif(sarif)


def test_deduplicate_removes_duplicates() -> None:
    findings = _get_test_findings()
    # Add a duplicate
    dup = findings[0].model_copy()
    findings_with_dup = [*findings, dup]
    deduped = deduplicate(findings_with_dup)
    assert len(deduped) == len(findings)


def test_deduplicate_preserves_unique() -> None:
    findings = _get_test_findings()
    deduped = deduplicate(findings)
    assert len(deduped) == len(findings)


def test_severity_overrides_hardcoded_creds_critical() -> None:
    findings = _get_test_findings()
    adjusted = apply_severity_overrides(findings)
    cred_findings = [f for f in adjusted if f.cwe_id == "CWE-798"]
    assert all(f.severity == Severity.CRITICAL for f in cred_findings)


def test_sort_by_priority_critical_first() -> None:
    findings = _get_test_findings()
    adjusted = apply_severity_overrides(findings)
    sorted_findings = sort_by_priority(adjusted)
    if len(sorted_findings) >= 2:
        # First finding should be critical or high
        assert sorted_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_group_by_file() -> None:
    findings = _get_test_findings()
    groups = group_by_file(findings)
    # We have 4 vulnerable files
    assert len(groups) == 4
    # All findings should be accounted for
    total = sum(len(group) for group in groups.values())
    assert total == len(findings)


def test_prioritize_full_pipeline() -> None:
    findings = _get_test_findings()
    result = prioritize(findings)
    assert len(result) > 0
    # Should be sorted by severity
    severity_order = [f.severity for f in result]
    expected_order = sorted(
        severity_order,
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s.value],
    )
    assert severity_order == expected_order
