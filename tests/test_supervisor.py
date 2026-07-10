# test_supervisor.py
# End-to-end supervisor test with Bedrock mocked.

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.agents.supervisor import (
    build_supervisor_graph,
    run_triage,
    supervisor_node,
)

FIXTURES = Path(__file__).parent / "fixtures"


class MockLLM:
    def __init__(self):
        self._content = (FIXTURES / "classifier_response.json").read_text(encoding="utf-8")

    def invoke(self, messages):
        response = MagicMock()
        response.content = self._content
        return response


def test_graph_wiring():
    graph = build_supervisor_graph()
    compiled = graph.compile()
    expected_nodes = {"supervisor", "parse", "classify", "report"}
    actual_nodes = set(compiled.get_graph().nodes.keys())
    missing = expected_nodes - actual_nodes
    assert not missing, f"Missing nodes: {missing}"


def test_supervisor_routing():
    cases = [
        {
            "name": "no findings → parse",
            "state": {
                "findings": [],
                "triage_results": [],
                "markdown_comment": "",
                "errors": [],
                "parser_attempted": False,
                "classifier_attempted": False,
                "reporter_attempted": False,
                "reclassify_requested": False,
            },
            "expected": "parse",
        },
        {
            "name": "findings ready → classify",
            "state": {
                "findings": [{"id": "f1"}],
                "triage_results": [],
                "markdown_comment": "",
                "errors": [],
                "parser_attempted": True,
                "classifier_attempted": False,
                "reporter_attempted": False,
                "reclassify_requested": False,
            },
            "expected": "classify",
        },
        {
            "name": "triage results ready → report",
            "state": {
                "findings": [{"id": "f1"}],
                "triage_results": [{"finding_id": "f1", "verdict": "needs_review"}],
                "markdown_comment": "",
                "errors": [],
                "parser_attempted": True,
                "classifier_attempted": True,
                "reporter_attempted": False,
                "reclassify_requested": False,
            },
            "expected": "report",
        },
        {
            "name": "comment ready → END",
            "state": {
                "findings": [{"id": "f1"}],
                "triage_results": [{"finding_id": "f1"}],
                "markdown_comment": "## Security Scan Triage",
                "errors": [],
                "parser_attempted": True,
                "classifier_attempted": True,
                "reporter_attempted": True,
                "reclassify_requested": False,
            },
            "expected": "END",
        },
        {
            "name": "reclassify requested → classify",
            "state": {
                "findings": [{"id": "f1"}],
                "triage_results": [],
                "markdown_comment": "",
                "errors": ["Missing triage verdicts"],
                "parser_attempted": True,
                "classifier_attempted": True,
                "reporter_attempted": False,
                "reclassify_requested": True,
            },
            "expected": "classify",
        },
        {
            "name": "parser failed → END",
            "state": {
                "findings": [],
                "triage_results": [],
                "markdown_comment": "",
                "errors": ["ParserAgent error: file not found"],
                "parser_attempted": True,
                "classifier_attempted": False,
                "reporter_attempted": False,
                "reclassify_requested": False,
            },
            "expected": "END",
        },
        {
            "name": "clean scan (0 findings, no errors) → report, not dead-end END",
            "state": {
                "findings": [],
                "triage_results": [],
                "markdown_comment": "",
                "errors": [],
                "parser_attempted": True,
                "classifier_attempted": False,
                "reporter_attempted": False,
                "reclassify_requested": False,
            },
            "expected": "report",
        },
    ]

    for case in cases:
        full_state = {
            "trivy_file": None,
            "semgrep_file": None,
            "pr_number": None,
            "messages": [],
            "next": "",
            **case["state"],
        }
        result = supervisor_node(full_state)
        assert result["next"] == case["expected"], case["name"]


def test_run_triage_e2e(monkeypatch):
    mock_llm = MockLLM()
    monkeypatch.setattr("src.agents.classifier_agent.get_llm", lambda **kwargs: mock_llm)

    result = run_triage(
        trivy_file=str(FIXTURES / "trivy_sample.json"),
        semgrep_file=str(FIXTURES / "semgrep_sample.json"),
    )

    assert len(result["findings"]) == 4
    assert len(result["triage_results"]) == 4
    assert result["markdown_comment"]
    assert "<!-- ci-triage-agent -->" in result["markdown_comment"]
    assert "Confirmed vulnerabilities" in result["markdown_comment"]
    assert "Likely false positives" in result["markdown_comment"]


def test_run_triage_e2e_clean_scan(tmp_path, monkeypatch):
    """
    Regression test: a genuinely clean scan (0 findings, no errors) must
    produce a valid 'no findings' markdown comment, not silently fail with
    no comment and no errors (the old dead-end behavior).
    """

    def _fail_if_called(**kwargs):
        raise AssertionError("Classifier should never be called when there are 0 findings")

    monkeypatch.setattr("src.agents.classifier_agent.get_llm", _fail_if_called)

    empty_trivy = tmp_path / "empty_trivy.json"
    empty_trivy.write_text('{"SchemaVersion": 2, "Results": []}')
    empty_semgrep = tmp_path / "empty_semgrep.json"
    empty_semgrep.write_text('{"results": []}')

    result = run_triage(
        trivy_file=str(empty_trivy),
        semgrep_file=str(empty_semgrep),
    )

    assert result["findings"] == []
    assert result["triage_results"] == []
    assert result["errors"] == []
    assert result["markdown_comment"], "clean scan must still produce a comment"
    assert "Total findings:** 0" in result["markdown_comment"]
