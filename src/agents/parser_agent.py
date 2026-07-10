# parser_agent.py
# Parser Agent — normalizes raw Trivy/Semgrep JSON into shared Finding schema.

from __future__ import annotations

import logging

from src.agents.state import AgentState
from src.ingest.semgrep_parser import load_semgrep_file
from src.ingest.trivy_parser import load_trivy_file
from src.models.finding import Finding

logger = logging.getLogger("parser_agent")


def parser_agent_node(state: AgentState) -> dict:
    """
    Parser Agent — reads scanner JSON files, emits normalized findings.
    Bounded to ingest parsers only; no LLM calls.
    """
    trivy_file = state.get("trivy_file")
    semgrep_file = state.get("semgrep_file")

    logger.info(
        "ParserAgent START | trivy_file=%s | semgrep_file=%s",
        trivy_file,
        semgrep_file,
    )

    new_findings: list[dict] = []
    new_errors: list[str] = []

    if not trivy_file and not semgrep_file:
        new_errors.append("ParserAgent error: no scanner input files provided")
    else:
        if trivy_file:
            try:
                for finding in load_trivy_file(trivy_file):
                    new_findings.append(finding.model_dump(mode="json"))
            except Exception as e:
                err = f"ParserAgent error (trivy): {e}"
                logger.error(err)
                new_errors.append(err)

        if semgrep_file:
            try:
                for finding in load_semgrep_file(semgrep_file):
                    new_findings.append(finding.model_dump(mode="json"))
            except Exception as e:
                err = f"ParserAgent error (semgrep): {e}"
                logger.error(err)
                new_errors.append(err)

    logger.info(
        "ParserAgent DONE | findings=%d | errors=%d",
        len(new_findings),
        len(new_errors),
    )

    state_update: dict = {"next": "supervisor", "parser_attempted": True}
    if new_findings:
        state_update["findings"] = new_findings
    if new_errors:
        state_update["errors"] = new_errors

    return state_update


def parse_findings_from_state(state: AgentState) -> list[Finding]:
    """Rehydrate Finding models from state dicts."""
    return [Finding.model_validate(f) for f in state.get("findings", [])]
