# test_classifier_agent.py
# Fixture-based tests for the Classifier Agent (Bedrock mocked).

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agents.classifier_agent import (
    classify_clusters,
    classifier_agent_node,
    cluster_findings,
)
from src.agents.parser_agent import parser_agent_node
from src.agents.state import AgentState
from src.models.finding import Verdict

FIXTURES = Path(__file__).parent / "fixtures"


class MockLLM:
    """Mock LangChain chat model returning fixture classifier JSON."""

    def __init__(self, response_path: Path):
        self._content = response_path.read_text(encoding="utf-8")

    def invoke(self, messages):
        response = MagicMock()
        response.content = self._content
        return response


@pytest.fixture
def parsed_state() -> AgentState:
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
    parser_result = parser_agent_node(state)
    state["findings"] = parser_result["findings"]
    state["parser_attempted"] = True
    return state


def test_cluster_findings(parsed_state):
    from src.agents.parser_agent import parse_findings_from_state

    findings = parse_findings_from_state(parsed_state)
    clusters = cluster_findings(findings)
    assert len(clusters) == 4
    assert all(len(c.findings) >= 1 for c in clusters)


def test_classify_clusters_mock_llm(parsed_state):
    from src.agents.parser_agent import parse_findings_from_state

    findings = parse_findings_from_state(parsed_state)
    clusters = cluster_findings(findings)
    mock_llm = MockLLM(FIXTURES / "classifier_response.json")
    results = classify_clusters(clusters, llm=mock_llm)
    assert len(results) == 4
    verdicts = {r.verdict for r in results}
    assert Verdict.TRUE_POSITIVE in verdicts
    assert Verdict.FALSE_POSITIVE in verdicts


def test_classifier_agent_node_mock_llm(parsed_state, monkeypatch):
    mock_llm = MockLLM(FIXTURES / "classifier_response.json")
    monkeypatch.setattr("src.agents.classifier_agent.get_llm", lambda **kwargs: mock_llm)

    result = classifier_agent_node(parsed_state)
    assert result["classifier_attempted"] is True
    assert len(result["triage_results"]) == 4
    assert result["triage_results"][0]["verdict"] == "true_positive"


def test_cluster_verdict_fans_out_to_every_member():
    """
    Regression test: when 3 findings share the same scanner+rule_id+file_path,
    they collapse into ONE cluster. The LLM is only shown (and only judges) the
    cluster's representative finding — but every finding in that cluster must
    still end up with its own TriageResult, or duplicate findings silently
    disappear from the final report.
    """
    from src.agents.classifier_agent import cluster_findings, classify_clusters
    from src.agents.parser_agent import parse_findings_from_state, parser_agent_node

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
    assert len(parser_result["findings"]) == 3  # 3 raw findings, 1 cluster

    state["findings"] = parser_result["findings"]
    findings = parse_findings_from_state(state)
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert len(clusters[0].findings) == 3

    mock_llm = MockLLM(FIXTURES / "classifier_response_duplicate.json")
    triage_results = classify_clusters(clusters, llm=mock_llm)

    assert len(triage_results) == 3, "all 3 findings must get a verdict, not just the representative"
    assert {r.finding_id for r in triage_results} == {f.id for f in findings}
    assert all(r.verdict == Verdict.TRUE_POSITIVE for r in triage_results)
