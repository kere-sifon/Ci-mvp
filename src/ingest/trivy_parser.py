# trivy_parser.py
# Parse Trivy JSON (filesystem / image scan) into Finding models.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models.finding import Finding, ScannerSource, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}


def _map_severity(value: str | None) -> Severity:
    if not value:
        return Severity.UNKNOWN
    return _SEVERITY_MAP.get(value.upper(), Severity.UNKNOWN)


def _vuln_to_finding(vuln: dict[str, Any], target: str, index: int) -> Finding:
    vuln_id = vuln.get("VulnerabilityID") or vuln.get("ID") or f"trivy-{index}"
    pkg = vuln.get("PkgName") or vuln.get("PkgIdentifier", {}).get("Name")
    return Finding(
        id=f"trivy:{target}:{vuln_id}:{index}",
        scanner=ScannerSource.TRIVY,
        rule_id=vuln_id,
        title=vuln.get("Title") or vuln_id,
        severity=_map_severity(vuln.get("Severity")),
        file_path=target,
        description=vuln.get("Description") or "",
        cve_id=vuln.get("VulnerabilityID") if str(vuln.get("VulnerabilityID", "")).startswith("CVE-") else None,
        package=pkg,
        installed_version=vuln.get("InstalledVersion"),
        fixed_version=vuln.get("FixedVersion"),
        raw=vuln,
    )


def _secret_to_finding(secret: dict[str, Any], target: str, index: int) -> Finding:
    rule_id = secret.get("RuleID") or secret.get("Category") or "secret"
    return Finding(
        id=f"trivy-secret:{target}:{rule_id}:{index}",
        scanner=ScannerSource.TRIVY,
        rule_id=rule_id,
        title=secret.get("Title") or f"Secret: {rule_id}",
        severity=_map_severity(secret.get("Severity") or "HIGH"),
        file_path=secret.get("Target") or target,
        line=secret.get("StartLine"),
        description=secret.get("Match") or secret.get("Title") or "",
        raw=secret,
    )


def parse_trivy_json(data: dict[str, Any]) -> list[Finding]:
    """Parse a Trivy JSON report into normalized findings."""
    findings: list[Finding] = []
    index = 0

    for result in data.get("Results") or []:
        target = result.get("Target") or "unknown"
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_vuln_to_finding(vuln, target, index))
            index += 1
        for secret in result.get("Secrets") or []:
            findings.append(_secret_to_finding(secret, target, index))
            index += 1

    return findings


def load_trivy_file(path: str | Path) -> list[Finding]:
    """Load and parse a Trivy JSON file from disk."""
    content = Path(path).read_text(encoding="utf-8")
    return parse_trivy_json(json.loads(content))
