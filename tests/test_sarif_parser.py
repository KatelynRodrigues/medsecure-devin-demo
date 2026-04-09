"""Tests for SARIF parsing."""

from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.scanner.mock_scanner import generate_sarif


def test_parse_sarif_returns_findings() -> None:
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    assert len(findings) > 0


def test_parse_sarif_all_findings_have_required_fields() -> None:
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    for f in findings:
        assert f.finding_id
        assert f.rule_id
        assert f.cwe_id
        assert f.file_path
        assert f.start_line > 0
        assert f.severity


def test_parse_sarif_extracts_cwe_ids() -> None:
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    cwe_ids = {f.cwe_id for f in findings}
    # We should have at least SQL injection and hardcoded credentials
    assert "CWE-89" in cwe_ids
    assert "CWE-798" in cwe_ids


def test_parse_sarif_extracts_code_snippets() -> None:
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    # At least some findings should have code snippets
    snippets = [f for f in findings if f.code_snippet]
    assert len(snippets) > 0


def test_parse_sarif_finding_ids_are_unique() -> None:
    sarif = generate_sarif()
    findings = parse_sarif(sarif)
    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids))
