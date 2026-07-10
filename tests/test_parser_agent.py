# test_parser_agent.py
# Fixture-based tests for the Parser Agent.

from __future__ import annotations

from pathlib import Path

import pytest

from src.agents.parser_agent import parser_agent_node
from src.agents.state import AgentState
from src.ingest.semgrep_parser import load_semgrep_file
from src.ingest.trivy_parser import load_trivy_file
from src.models.finding import ScannerSource, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_trivy_fixture():
    findings = load_trivy_file(FIXTURES / "trivy_sample.json")
    assert len(findings) == 2
    assert findings[0].scanner == ScannerSource.TRIVY
    assert findings[0].cve_id == "CVE-2024-1234"
    assert findings[0].severity == Severity.HIGH
    assert findings[1].rule_id == "aws-access-key-id"


def test_load_semgrep_fixture():
    findings = load_semgrep_file(FIXTURES / "semgrep_sample.json")
    assert len(findings) == 2
    assert findings[0].scanner == ScannerSource.SEMGREP
    assert "eval" in findings[0].title.lower() or "eval" in findings[0].description.lower()
    assert findings[0].file_path == "src/utils.py"
    assert findings[0].line == 15


def test_semgrep_severity_handles_risk_scale_not_just_execution_scale():
    """
    Regression test: some curated Semgrep rule families (e.g. the
    package_managers.dependabot.* rules) write extra.severity directly on
    the risk scale (CRITICAL/HIGH/MEDIUM/LOW) rather than the classic
    execution scale (ERROR/WARNING/INFO). Previously this fell through to
    Severity.UNKNOWN since the lookup table only recognized the execution
    scale. Shape matches a real-world dependabot-missing-cooldown finding.
    """
    from src.ingest.semgrep_parser import parse_semgrep_json
    from src.models.finding import Severity

    data = {
        "results": [
            {
                "check_id": "package_managers.dependabot.dependabot-missing-cooldown.dependabot-missing-cooldown",
                "path": ".github/dependabot.yml",
                "start": {"line": 5, "col": 5},
                "extra": {
                    "message": "This Dependabot configuration does not set a cooldown period.",
                    "metadata": {"confidence": "HIGH", "likelihood": "LOW", "impact": "HIGH"},
                    "severity": "MEDIUM",
                },
            }
        ]
    }
    findings = parse_semgrep_json(data)
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].severity != Severity.UNKNOWN


def test_parser_agent_node_combined():
    state: AgentState = {
        "trivy_file": str(FIXTURES / "trivy_sample.json"),
        "semgrep_file": str(FIXTURES / "semgrep_sample.json"),
        "pr_number": None,
        "messages": [],
        "findings": [],
        "triage_results": [],
        "errors": [],
        "markdown_comment": "",
        "parser_attempted": False,
        "classifier_attempted": False,
        "reporter_attempted": False,
        "reclassify_requested": False,
        "next": "",
    }
    result = parser_agent_node(state)
    assert result["parser_attempted"] is True
    assert len(result["findings"]) == 4
    assert "errors" not in result or not result["errors"]
