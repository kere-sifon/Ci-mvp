# state.py
# Typed state contract for the CI triage supervisor graph.

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    # Input paths (set once at entry)
    trivy_file: str | None
    semgrep_file: str | None
    pr_number: int | None

    # Handoff channels (specialists append)
    messages: Annotated[list[BaseMessage], operator.add]
    findings: Annotated[list[dict], operator.add]  # Finding.model_dump() entries
    triage_results: list[dict]  # TriageResult.model_dump() — replaced each classify run
    errors: Annotated[list[str], operator.add]

    # Reporter output (replaced each report run)
    markdown_comment: str

    # Attempt flags — prevent infinite loops (mirrors validator_attempted / storage_attempted)
    parser_attempted: bool
    classifier_attempted: bool
    reporter_attempted: bool
    reclassify_requested: bool

    # Routing signal — supervisor writes, graph reads
    next: str
