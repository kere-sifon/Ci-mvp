# finding.py
# Shared Pydantic schemas for normalized scanner output and triage verdicts.

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ScannerSource(str, Enum):
    TRIVY = "trivy"
    SEMGREP = "semgrep"


class Finding(BaseModel):
    """Normalized security finding from any supported scanner."""

    id: str
    scanner: ScannerSource
    rule_id: str
    title: str
    severity: Severity
    file_path: str | None = None
    line: int | None = None
    description: str = ""
    cve_id: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    raw: dict = Field(default_factory=dict)


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class TriageResult(BaseModel):
    """Classifier output for a finding or cluster."""

    finding_id: str
    verdict: Verdict
    rationale: str
    suggested_fix: str | None = None
    confidence: Literal["high", "medium", "low"] = "medium"


class FindingCluster(BaseModel):
    """Grouped findings sharing the same rule and target file."""

    cluster_key: str
    findings: list[Finding]

    @property
    def representative(self) -> Finding:
        return self.findings[0]
