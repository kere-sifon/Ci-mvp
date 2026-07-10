# test_reporter_agent.py
# Tests for the Reporter Agent's markdown rendering, including the
# cluster-grouping fix (a rule that fires N times should render as one
# entry with N locations, not N repeated rationale blocks).

from __future__ import annotations

from pathlib import Path

from src.agents.classifier_agent import classify_clusters, cluster_findings
from src.agents.parser_agent import parse_findings_from_state, parser_agent_node
from src.agents.reporter_agent import render_markdown_comment
from src.agents.state import AgentState
from src.models.finding import Finding, TriageResult, Verdict

FIXTURES = Path(__file__).parent / "fixtures"


class MockLLM:
    def __init__(self, response_path: Path):
        self._content = response_path.read_text(encoding="utf-8")

    def invoke(self, messages):
        from unittest.mock import MagicMock

        response = MagicMock()
        response.content = self._content
        return response


def test_single_finding_renders_inline_location():
    finding = Finding(
        id="f1",
        scanner="trivy",
        rule_id="CVE-2024-9999",
        title="Example vuln",
        severity="HIGH",
        file_path="requirements.txt",
    )
    result = TriageResult(
        finding_id="f1",
        verdict=Verdict.TRUE_POSITIVE,
        rationale="Known CVE, upgrade required.",
    )
    markdown = render_markdown_comment([finding], [result])

    assert "(`requirements.txt`)" in markdown
    assert "instances" not in markdown  # singular findings shouldn't get instance-count styling
    assert markdown.count("Known CVE, upgrade required.") == 1


def test_duplicate_cluster_renders_once_with_all_locations():
    """
    Regression test: 3 findings sharing the same scanner+rule_id+file_path
    (a single cluster) must render as ONE entry listing all 3 locations,
    not 3 near-identical entries repeating the same rationale.
    """
    state: AgentState = {
        "trivy_file": str(FIXTURES / "trivy_duplicate_sample.json"),
        "semgrep_file": None,
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
    parser_result = parser_agent_node(state)
    state["findings"] = parser_result["findings"]
    findings = parse_findings_from_state(state)

    clusters = cluster_findings(findings)
    assert len(clusters) == 1  # sanity check: all 3 do share one cluster

    mock_llm = MockLLM(FIXTURES / "classifier_response_duplicate.json")
    triage_results = classify_clusters(clusters, llm=mock_llm)
    assert len(triage_results) == 3  # fan-out fix: all 3 get verdicts

    markdown = render_markdown_comment(findings, triage_results)

    # One grouped entry, not three
    assert markdown.count("Known CVE with a fixed version available") == 1
    assert "**3 instances**" in markdown
    assert "**Locations:**" in markdown
    # All three underlying findings' locations should still be listed
    assert markdown.count("requirements.txt") >= 3
