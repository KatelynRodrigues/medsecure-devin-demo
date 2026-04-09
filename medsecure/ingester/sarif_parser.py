"""Parse SARIF v2.1.0 output into structured SecurityFinding objects."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from medsecure.models import SecurityFinding, Severity

# Map SARIF level + CWE properties to our severity enum
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

# SARIF level fallback mapping (when properties.severity is missing)
_LEVEL_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.LOW,
}


def parse_sarif_file(sarif_path: Path) -> list[SecurityFinding]:
    """Parse a SARIF file and return a list of SecurityFinding objects.

    Args:
        sarif_path: Path to the SARIF JSON file.

    Returns:
        List of parsed SecurityFinding objects.
    """
    with open(sarif_path) as f:
        sarif_data = json.load(f)
    return parse_sarif(sarif_data)


def parse_sarif(sarif_data: dict) -> list[SecurityFinding]:
    """Parse SARIF data dictionary into SecurityFinding objects.

    Args:
        sarif_data: Parsed SARIF JSON as a dictionary.

    Returns:
        List of SecurityFinding objects.
    """
    findings: list[SecurityFinding] = []

    for run in sarif_data.get("runs", []):
        # Build a rule lookup for enrichment
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        rules_list = driver.get("rules", [])
        rules_by_id: dict[str, dict] = {}
        for rule in rules_list:
            rules_by_id[rule["id"]] = rule

        for result in run.get("results", []):
            finding = _parse_result(result, rules_by_id)
            if finding is not None:
                findings.append(finding)

    return findings


def _parse_result(result: dict, rules_by_id: dict[str, dict]) -> SecurityFinding | None:
    """Parse a single SARIF result into a SecurityFinding."""
    rule_id = result.get("ruleId", "unknown")
    rule = rules_by_id.get(rule_id, {})
    rule_name = rule.get("name", rule_id)

    # Extract location
    locations = result.get("locations", [])
    if not locations:
        return None

    phys = locations[0].get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    region = phys.get("region", {})

    file_path = artifact.get("uri", "unknown")
    start_line = region.get("startLine", 0)
    end_line = region.get("endLine", start_line)
    snippet = region.get("snippet", {}).get("text", "")

    # Extract properties
    props = result.get("properties", {})
    cwe_id = props.get("cwe", "")
    recommendation = props.get("recommendation", "")

    # If no CWE in properties, try rule tags
    if not cwe_id:
        rule_props = rule.get("properties", {})
        tags = rule_props.get("tags", [])
        for tag in tags:
            if tag.startswith("CWE-"):
                cwe_id = tag
                break

    # If no recommendation in properties, try rule help
    if not recommendation:
        help_obj = rule.get("help", {})
        recommendation = help_obj.get("text", "")

    # Determine severity
    severity_str = props.get("severity", "")
    if severity_str in _SEVERITY_MAP:
        severity = _SEVERITY_MAP[severity_str]
    else:
        level = result.get("level", "warning")
        severity = _LEVEL_SEVERITY.get(level, Severity.MEDIUM)

    # Generate deterministic finding ID
    fingerprint = result.get("fingerprints", {}).get("primaryLocationLineHash", "")
    if fingerprint:
        finding_id = f"finding-{fingerprint}"
    else:
        ns_input = f"{file_path}:{start_line}:{rule_id}"
        finding_id = f"finding-{uuid.uuid5(uuid.NAMESPACE_URL, ns_input).hex[:16]}"

    return SecurityFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name=rule_name,
        cwe_id=cwe_id,
        severity=severity,
        message=result.get("message", {}).get("text", ""),
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        code_snippet=snippet,
        recommendation=recommendation,
    )
