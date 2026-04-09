"""Prioritize and deduplicate security findings."""

from __future__ import annotations

from medsecure.models import SecurityFinding, Severity

# CWE-based severity overrides for healthcare/HIPAA context
_CWE_SEVERITY_OVERRIDES: dict[str, Severity] = {
    "CWE-798": Severity.CRITICAL,  # Hardcoded creds are always critical in healthcare
    "CWE-89": Severity.HIGH,       # SQL injection
    "CWE-502": Severity.HIGH,      # Unsafe deserialization
    "CWE-918": Severity.HIGH,      # SSRF
    "CWE-79": Severity.MEDIUM,     # XSS
    "CWE-22": Severity.MEDIUM,     # Path traversal
    "CWE-611": Severity.MEDIUM,    # XXE
    "CWE-327": Severity.LOW,       # Weak crypto (unless it's password-related)
    "CWE-117": Severity.LOW,       # Log injection
}

# Severity sort order (lower = higher priority)
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def deduplicate(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Remove duplicate findings based on (rule_id, file_path, start_line).

    Args:
        findings: List of parsed findings (may contain duplicates).

    Returns:
        Deduplicated list.
    """
    seen: set[tuple[str, str, int]] = set()
    unique: list[SecurityFinding] = []

    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.start_line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def apply_severity_overrides(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Apply healthcare-context severity overrides based on CWE.

    For example, hardcoded credentials (CWE-798) are always critical
    in a HIPAA-regulated environment.

    Args:
        findings: List of findings to adjust.

    Returns:
        Findings with updated severity levels.
    """
    adjusted: list[SecurityFinding] = []
    for finding in findings:
        override = _CWE_SEVERITY_OVERRIDES.get(finding.cwe_id)
        if override is not None:
            finding = finding.model_copy(update={"severity": override})
        adjusted.append(finding)
    return adjusted


def sort_by_priority(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Sort findings by severity (critical first).

    Args:
        findings: List of findings to sort.

    Returns:
        Sorted list with critical findings first.
    """
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def group_by_file(findings: list[SecurityFinding]) -> dict[str, list[SecurityFinding]]:
    """Group findings by file path for batched remediation.

    Related findings in the same file should be fixed in a single
    Devin session to avoid conflicting PRs.

    Args:
        findings: List of findings to group.

    Returns:
        Dictionary mapping file paths to their findings.
    """
    groups: dict[str, list[SecurityFinding]] = {}
    for finding in findings:
        groups.setdefault(finding.file_path, []).append(finding)
    return groups


def prioritize(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Full prioritization pipeline: deduplicate, override severity, sort.

    Args:
        findings: Raw list of parsed findings.

    Returns:
        Deduplicated, severity-adjusted, priority-sorted findings.
    """
    unique = deduplicate(findings)
    adjusted = apply_severity_overrides(unique)
    return sort_by_priority(adjusted)
