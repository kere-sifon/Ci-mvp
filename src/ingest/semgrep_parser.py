# semgrep_parser.py
# Parse Semgrep JSON output into Finding models.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models.finding import Finding, ScannerSource, Severity

# Semgrep's `extra.severity` isn't always one consistent scale. Legacy pattern
# rules use the execution scale (ERROR/WARNING/INFO), mapped here to the
# equivalent risk level. But newer curated rule families (e.g. the
# supply-chain / config-audit rules) write a risk-severity value directly —
# CRITICAL/HIGH/MEDIUM/LOW — straight into extra.severity. Both scales are
# handled in one lookup since their keys don't overlap except INFO, which
# maps to LOW under either interpretation.
_SEVERITY_MAP = {
    # Execution-severity scale (classic pattern rules)
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    # Risk-severity scale (curated rule families, e.g. dependabot/supply-chain)
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _map_severity(value: str | None) -> Severity:
    if not value:
        return Severity.UNKNOWN
    return _SEVERITY_MAP.get(value.upper(), Severity.UNKNOWN)


def _result_to_finding(result: dict[str, Any], index: int) -> Finding:
    check_id = result.get("check_id") or result.get("rule_id") or f"semgrep-{index}"
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    path = result.get("path") or ""
    start = result.get("start") or {}
    line = start.get("line")

    severity_raw = extra.get("severity") or metadata.get("severity")
    if isinstance(severity_raw, str):
        sev = _map_severity(severity_raw)
    else:
        sev = Severity.MEDIUM

    return Finding(
        id=f"semgrep:{check_id}:{path}:{line or index}",
        scanner=ScannerSource.SEMGREP,
        rule_id=check_id,
        title=metadata.get("message") or extra.get("message") or check_id,
        severity=sev,
        file_path=path or None,
        line=line,
        description=extra.get("message") or metadata.get("message") or "",
        raw=result,
    )


def parse_semgrep_json(data: dict[str, Any]) -> list[Finding]:
    """Parse a Semgrep JSON report into normalized findings."""
    results = data.get("results") or []
    return [_result_to_finding(r, i) for i, r in enumerate(results)]


def load_semgrep_file(path: str | Path) -> list[Finding]:
    """Load and parse a Semgrep JSON file from disk."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_semgrep_json(json.loads(content))
