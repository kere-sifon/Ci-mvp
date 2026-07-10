# supervisor.py
# Multi-agent supervisor for CI security scan triage.
#
# ARCHITECTURE:
#   Supervisor owns all routing decisions.
#   Three specialist agents:
#     - ParserAgent     → normalize Trivy/Semgrep JSON
#     - ClassifierAgent → Bedrock verdict (true_positive / false_positive / needs_review)
#     - ReporterAgent   → markdown PR comment
#
# FLOW:
#   START → supervisor → parser → supervisor
#                      → classifier → supervisor
#                      → reporter → supervisor
#                      → END
#
#   Specialists ALWAYS return to supervisor. Supervisor owns routing.
#   Reporter may flag missing/malformed data → loop back to classifier once.

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from src.agents.classifier_agent import classifier_agent_node
from src.agents.parser_agent import parser_agent_node
from src.agents.reporter_agent import reporter_agent_node
from src.agents.state import AgentState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("supervisor")


def supervisor_node(state: AgentState) -> dict:
    """
    The orchestration brain. Reads state, decides which specialist runs next.
    """
    findings = state.get("findings", [])
    triage_results = state.get("triage_results", [])
    markdown_comment = state.get("markdown_comment", "")
    errors = state.get("errors", [])
    parser_attempted = state.get("parser_attempted", False)
    classifier_attempted = state.get("classifier_attempted", False)
    reporter_attempted = state.get("reporter_attempted", False)
    reclassify_requested = state.get("reclassify_requested", False)

    logger.info(
        "SUPERVISOR ROUTING | findings=%d | triage_results=%d | "
        "has_comment=%s | errors=%d | parser=%s | classifier=%s | reporter=%s | reclassify=%s",
        len(findings),
        len(triage_results),
        bool(markdown_comment),
        len(errors),
        parser_attempted,
        classifier_attempted,
        reporter_attempted,
        reclassify_requested,
    )

    # Rule 1: No parsed findings yet → run parser (unless parser failed with errors)
    if not findings and not parser_attempted:
        decision = "parse"
        logger.info("SUPERVISOR DECISION → %s (reason: parser not yet run)", decision)

    elif not findings and parser_attempted and errors:
        decision = "END"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: parser failed, errors=%s)",
            decision,
            errors,
        )

    # Rule 1b: Parser succeeded with genuinely zero findings (clean scan) →
    # skip classification entirely (nothing to classify) and go straight to
    # report, so a clean PR gets a "no findings" comment instead of silence.
    elif not findings and parser_attempted and not errors and not reporter_attempted:
        decision = "report"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: clean scan, 0 findings, nothing to classify)",
            decision,
        )

    # Rule 2: Reporter flagged missing data → loop back to classifier once
    elif reclassify_requested and classifier_attempted:
        decision = "classify"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: reporter requested reclassification)",
            decision,
        )

    # Rule 3: Have findings, no triage results → run classifier
    elif findings and not triage_results and not classifier_attempted:
        decision = "classify"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: %d findings awaiting classification)",
            decision,
            len(findings),
        )

    elif findings and not triage_results and classifier_attempted and errors:
        decision = "END"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: classifier failed, errors=%s)",
            decision,
            errors,
        )

    # Rule 4: Have triage results, no comment yet → run reporter
    elif triage_results and not markdown_comment:
        decision = "report"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: %d triage results ready for report)",
            decision,
            len(triage_results),
        )

    # Rule 5: Reporter completed with comment → done
    elif markdown_comment:
        decision = "END"
        logger.info("SUPERVISOR DECISION → %s (reason: markdown comment ready)", decision)

    # Rule 6: Dead end
    else:
        decision = "END"
        logger.info(
            "SUPERVISOR DECISION → %s (reason: no viable path, errors=%s)",
            decision,
            errors,
        )

    return {"next": decision}


def route_from_supervisor(state: AgentState) -> str:
    """Conditional edge function — maps supervisor decisions to graph nodes."""
    decision = state.get("next", "END")
    logger.info("GRAPH ROUTING → node=%s", decision)
    return decision


def build_supervisor_graph():
    """Construct the supervisor-worker StateGraph."""
    graph = StateGraph(AgentState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("parse", parser_agent_node)
    graph.add_node("classify", classifier_agent_node)
    graph.add_node("report", reporter_agent_node)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "parse": "parse",
            "classify": "classify",
            "report": "report",
            "END": END,
        },
    )

    graph.add_edge("parse", "supervisor")
    graph.add_edge("classify", "supervisor")
    graph.add_edge("report", "supervisor")

    return graph


def build_supervisor_agent():
    """Compile the supervisor graph."""
    graph = build_supervisor_graph()
    return graph.compile()


def run_triage(
    *,
    trivy_file: str | None = None,
    semgrep_file: str | None = None,
    pr_number: int | None = None,
) -> dict:
    """Run one full triage pipeline and return final state."""
    logger.info("=" * 60)
    logger.info(
        "SUPERVISOR RUN START | trivy=%s | semgrep=%s | pr=%s",
        trivy_file,
        semgrep_file,
        pr_number,
    )
    logger.info("=" * 60)

    initial_state: AgentState = {
        "trivy_file": trivy_file,
        "semgrep_file": semgrep_file,
        "pr_number": pr_number,
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

    app = build_supervisor_agent()
    config = {"recursion_limit": 25}
    result = app.invoke(initial_state, config=config)

    logger.info(
        "SUPERVISOR RUN DONE | findings=%d | triage_results=%d | errors=%d",
        len(result.get("findings", [])),
        len(result.get("triage_results", [])),
        len(result.get("errors", [])),
    )

    return result
