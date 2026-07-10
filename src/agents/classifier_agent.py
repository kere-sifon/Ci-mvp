# classifier_agent.py
# Classifier Agent — calls Bedrock for triage verdicts on clustered findings.

from __future__ import annotations

import json
import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.parser_agent import parse_findings_from_state
from src.agents.state import AgentState
from src.config import LLM_PROVIDER, get_llm
from src.models.finding import Finding, FindingCluster, TriageResult, Verdict

logger = logging.getLogger("classifier_agent")

CLASSIFIER_SYSTEM = """You are a security triage classifier for CI/CD scan results.

For each finding cluster, determine whether it represents a real vulnerability
or noise (false positive / needs human review).

IMPORTANT — what you are and are not given:
You receive only scanner metadata for each finding: the rule ID, title,
severity, file path, line number, and description text. You do NOT receive
the actual matched code snippet or surrounding source context — many scanners
(including the Semgrep OSS tier) do not expose it in their JSON output.

Do not speculate about what the code at a given line probably contains or
invent specific variable names, function calls, or context that you have not
actually been shown. If the rule's own description already names the general
risk (e.g. "untrusted github context in a run: step"), reason at that level —
describe the general risk and what a human should check — rather than
asserting confident-sounding specifics about the exact code (e.g. claiming a
particular field name appears on that line) that you cannot see. When the
finding's real risk genuinely depends on code you can't see, that is itself
a reason to lean toward needs_review with lower confidence, not an invitation
to guess plausible specifics to fill the gap.

Respond ONLY with a JSON array. Each element must have:
- finding_id: the representative finding id from the cluster
- verdict: one of true_positive | false_positive | needs_review
- rationale: concise explanation (1-3 sentences), grounded only in the
  metadata you were actually given
- suggested_fix: optional remediation hint (null if none)
- confidence: high | medium | low

Be conservative: flag uncertain cases as needs_review rather than false_positive.
"""


def cluster_findings(findings: list[Finding]) -> list[FindingCluster]:
    """Group findings by scanner + rule + file path."""
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        key = f"{finding.scanner.value}:{finding.rule_id}:{finding.file_path or 'unknown'}"
        buckets.setdefault(key, []).append(finding)
    return [FindingCluster(cluster_key=k, findings=v) for k, v in buckets.items()]


def _parse_classifier_response(content: str, clusters: list[FindingCluster]) -> list[TriageResult]:
    """
    Parse LLM JSON output into TriageResult models.

    The LLM is prompted with one representative finding per cluster and returns
    one verdict per representative. Each verdict is then fanned out to every
    finding in that cluster, so a cluster of N duplicate/related findings ends
    up with N TriageResults (all sharing the same verdict/rationale) rather
    than a verdict for only the representative — otherwise every non-representative
    finding in a multi-item cluster would silently disappear from the report.
    """
    # Map representative finding id -> full list of finding ids in its cluster
    cluster_members_by_rep_id = {
        c.representative.id: [f.id for f in c.findings] for c in clusters
    }
    results: list[TriageResult] = []

    # Try fenced JSON first
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL)
    raw_json = fenced.group(1) if fenced else content.strip()

    try:
        items = json.loads(raw_json)
    except json.JSONDecodeError:
        # Fallback: find array in text
        match = re.search(r"\[.*\]", content, re.DOTALL)
        if not match:
            raise ValueError("Classifier response contained no JSON array") from None
        items = json.loads(match.group(0))

    if not isinstance(items, list):
        raise ValueError("Classifier response must be a JSON array")

    for item in items:
        rep_id = item.get("finding_id", "")
        member_ids = cluster_members_by_rep_id.get(rep_id)
        if member_ids is None:
            logger.warning("Classifier returned unknown finding_id=%s — skipping", rep_id)
            continue
        verdict_str = str(item.get("verdict", "needs_review")).lower()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.NEEDS_REVIEW
        rationale = item.get("rationale") or "No rationale provided."
        suggested_fix = item.get("suggested_fix")
        confidence = item.get("confidence") or "medium"

        # Fan the representative's verdict out to every finding in the cluster.
        for member_id in member_ids:
            results.append(
                TriageResult(
                    finding_id=member_id,
                    verdict=verdict,
                    rationale=rationale,
                    suggested_fix=suggested_fix,
                    confidence=confidence,
                )
            )

    return results


def _build_cluster_prompt(clusters: list[FindingCluster]) -> str:
    payload = []
    for cluster in clusters:
        rep = cluster.representative
        payload.append(
            {
                "finding_id": rep.id,
                "cluster_size": len(cluster.findings),
                "scanner": rep.scanner.value,
                "rule_id": rep.rule_id,
                "title": rep.title,
                "severity": rep.severity.value,
                "file_path": rep.file_path,
                "line": rep.line,
                "description": rep.description[:500],
                "package": rep.package,
                "installed_version": rep.installed_version,
                "fixed_version": rep.fixed_version,
            }
        )
    return json.dumps(payload, indent=2)


def classify_clusters(clusters: list[FindingCluster], llm=None) -> list[TriageResult]:
    """Classify finding clusters via Bedrock (or injected mock LLM)."""
    if not clusters:
        return []

    model = llm or get_llm(json_mode=True)
    prompt = _build_cluster_prompt(clusters)
    messages = [
        SystemMessage(content=CLASSIFIER_SYSTEM),
        HumanMessage(content=f"Classify these finding clusters:\n\n{prompt}"),
    ]
    response = model.invoke(messages)
    content = response.content if isinstance(response.content, str) else str(response.content)
    return _parse_classifier_response(content, clusters)


def classifier_agent_node(state: AgentState) -> dict:
    """
    Classifier Agent — reads findings, calls Bedrock, emits TriageResults.
    """
    findings = parse_findings_from_state(state)
    reclassify = state.get("reclassify_requested", False)

    logger.info(
        "ClassifierAgent START | findings=%d | reclassify=%s | provider=%s",
        len(findings),
        reclassify,
        LLM_PROVIDER,
    )

    new_results: list[dict] = []
    new_errors: list[str] = []

    if not findings:
        new_errors.append("ClassifierAgent error: no findings to classify")
    else:
        try:
            clusters = cluster_findings(findings)
            for result in classify_clusters(clusters):
                new_results.append(result.model_dump(mode="json"))
        except Exception as e:
            err = f"ClassifierAgent error: {e}"
            logger.error(err)
            new_errors.append(err)

    logger.info(
        "ClassifierAgent DONE | triage_results=%d | errors=%d",
        len(new_results),
        len(new_errors),
    )

    state_update: dict = {
        "next": "supervisor",
        "classifier_attempted": True,
        "reclassify_requested": False,
    }
    if new_results:
        state_update["triage_results"] = new_results
    if new_errors:
        state_update["errors"] = new_errors

    return state_update
