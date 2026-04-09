"""Tests for prompt building."""

from medsecure.ingester.sarif_parser import parse_sarif
from medsecure.orchestrator.prompt_builder import (
    build_prompt_for_findings,
    build_structured_output_schema,
)
from medsecure.scanner.mock_scanner import generate_sarif


def _get_test_findings():
    sarif = generate_sarif()
    return parse_sarif(sarif)


def test_build_prompt_includes_cwe() -> None:
    findings = _get_test_findings()
    sql_findings = [f for f in findings if f.cwe_id == "CWE-89"]
    prompt = build_prompt_for_findings(sql_findings, "test/repo")
    assert "CWE-89" in prompt
    assert "SQL Injection" in prompt


def test_build_prompt_includes_file_paths() -> None:
    findings = _get_test_findings()
    prompt = build_prompt_for_findings(findings[:2], "test/repo")
    assert findings[0].file_path in prompt


def test_build_prompt_includes_fix_instructions() -> None:
    findings = _get_test_findings()
    prompt = build_prompt_for_findings(findings[:1], "test/repo")
    assert "Fix" in prompt or "fix" in prompt


def test_build_prompt_includes_repo_name() -> None:
    findings = _get_test_findings()
    prompt = build_prompt_for_findings(findings[:1], "my-org/my-repo")
    assert "my-org/my-repo" in prompt


def test_structured_output_schema_valid() -> None:
    schema = build_structured_output_schema()
    assert schema["type"] == "object"
    assert "findings_fixed" in schema["properties"]
    assert "fix_confidence" in schema["properties"]
    assert "files_modified" in schema["properties"]
    assert "requires_manual_review" in schema["properties"]
    assert "findings_fixed" in schema["required"]
