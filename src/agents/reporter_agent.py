# reporter_agent.py
# Reporter Agent — turns TriageResults into a markdown PR comment.

from __future__ import annotations

import logging

from src.agents.parser_agent import parse_findings_from_state
from src.agents.state import AgentState
from src.github.comment import COMMENT_HEADER
from src.models.finding import Finding, TriageResult, Verdict

logger = logging.getLogger("reporter_agent")


def _load_triage_results(state: AgentState) -> list[TriageResult]:
    return [TriageResult.model_validate(r) for r in state.get("triage_results", [])]


def _finding_map(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def _validate_triage_coverage(
    findings: list[Finding], triage_results: list[TriageResult]
) -> list[str]:
    """Return issues that should trigger reclassification."""
    issues: list[str] = []

    if not findings:
        # Genuinely clean scan — zero findings means zero triage results is
        # correct, not a failure. Nothing to validate or reclassify.
        return issues

    if not triage_results:
        issues.append("No triage results produced")
        return issues

    finding_ids = {f.id for f in findings}
    clustered_ids = set(finding_ids)  # one verdict per finding id for now
    result_ids = {r.finding_id for r in triage_results}

    missing = clustered_ids - result_ids
    if missing:
        issues.append(f"Missing triage verdicts for {len(missing)} finding(s)")

    for result in triage_results:
        if not result.rationale or len(result.rationale.strip()) < 10:
            issues.append(f"Malformed rationale for finding_id={result.finding_id}")

    return issues


def _location_str(finding: Finding) -> str:
    loc = finding.file_path or "unknown"
    if finding.line:
        loc = f"{loc}:{finding.line}"
    return loc


def _cluster_group_key(finding: Finding) -> tuple[str, str, str]:
    """
    Group findings the same way the Classifier clustered them
    (scanner + rule_id + file_path) so the report shows one entry per
    cluster instead of repeating an identical verdict/rationale once
    per raw finding fanned out to that cluster.
    """
    return (finding.scanner.value, finding.rule_id, finding.file_path or "unknown")


def render_markdown_comment(
    findings: list[Finding], triage_results: list[TriageResult]
) -> str:
    """Render the final PR comment markdown."""
    fmap = _finding_map(findings)
    by_verdict: dict[Verdict, list[tuple[Finding, TriageResult]]] = {
        Verdict.TRUE_POSITIVE: [],
        Verdict.NEEDS_REVIEW: [],
        Verdict.FALSE_POSITIVE: [],
    }

    for result in triage_results:
        finding = fmap.get(result.finding_id)
        if finding:
            by_verdict[result.verdict].append((finding, result))

    lines = [
        COMMENT_HEADER,
        "## Security Scan Triage",
        "",
        f"**Total findings:** {len(findings)} | "
        f"**True positives:** {len(by_verdict[Verdict.TRUE_POSITIVE])} | "
        f"**Needs review:** {len(by_verdict[Verdict.NEEDS_REVIEW])} | "
        f"**Likely false positives:** {len(by_verdict[Verdict.FALSE_POSITIVE])}",
        "",
    ]

    sections = [
        ("Confirmed vulnerabilities", Verdict.TRUE_POSITIVE, "These findings appear to be real issues."),
        ("Needs human review", Verdict.NEEDS_REVIEW, "Uncertain — please verify manually."),
        ("Likely false positives", Verdict.FALSE_POSITIVE, "These appear to be scanner noise."),
    ]

    for title, verdict, subtitle in sections:
        items = by_verdict[verdict]
        lines.append(f"### {title}")
        lines.append(f"_{subtitle}_")
        lines.append("")
        if not items:
            lines.append("_None_")
            lines.append("")
            continue

        # Group same-cluster findings (identical rule_id/file/scanner) so a
        # rule that fired 6 times shows once, with all 6 locations listed,
        # instead of the same rationale repeated 6 times.
        groups: dict[tuple[str, str, str], list[tuple[Finding, TriageResult]]] = {}
        for finding, result in items:
            groups.setdefault(_cluster_group_key(finding), []).append((finding, result))

        for group_items in groups.values():
            rep_finding, rep_result = group_items[0]
            locations = [_location_str(f) for f, _ in group_items]
            count = len(group_items)

            if count == 1:
                lines.append(
                    f"- **[{rep_finding.severity.value}]** `{rep_finding.rule_id}` — "
                    f"{rep_finding.title} (`{locations[0]}`)"
                )
            else:
                lines.append(
                    f"- **[{rep_finding.severity.value}]** `{rep_finding.rule_id}` — "
                    f"{rep_finding.title} — **{count} instances**"
                )
                lines.append(
                    "  - **Locations:** " + ", ".join(f"`{loc}`" for loc in locations)
                )

            lines.append(f"  - **Verdict:** {rep_result.verdict.value}")
            lines.append(f"  - **Rationale:** {rep_result.rationale}")
            if rep_result.suggested_fix:
                lines.append(f"  - **Suggested fix:** {rep_result.suggested_fix}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by [ci-triage-agent](https://github.com/actions)_")
    return "\n".join(lines)


def reporter_agent_node(state: AgentState) -> dict:
    """
    Reporter Agent — validates triage output and renders markdown comment.
    Sets reclassify_requested if data is incomplete/malformed.
    """
    findings = parse_findings_from_state(state)
    triage_results = _load_triage_results(state)

    logger.info(
        "ReporterAgent START | findings=%d | triage_results=%d",
        len(findings),
        len(triage_results),
    )

    validation_issues = _validate_triage_coverage(findings, triage_results)
    new_errors: list[str] = []

    if validation_issues and not state.get("classifier_attempted", False):
        # Classifier hasn't run yet — shouldn't happen, but fail safe
        new_errors.extend(validation_issues)
    elif validation_issues and len(triage_results) < len(findings) and not state.get(
        "reclassify_requested"
    ):
        # First pass with issues → request reclassification (supervisor loops back)
        logger.info("ReporterAgent: validation issues → reclassify requested: %s", validation_issues)
        return {
            "next": "supervisor",
            "reclassify_requested": True,
            "errors": validation_issues,
        }

    if validation_issues:
        # Already retried — accept best-effort output
        for issue in validation_issues:
            new_errors.append(f"ReporterAgent warning: {issue}")

    markdown = render_markdown_comment(findings, triage_results)

    logger.info("ReporterAgent DONE | comment_length=%d", len(markdown))

    state_update: dict = {
        "next": "supervisor",
        "markdown_comment": markdown,
        "reporter_attempted": True,
        "reclassify_requested": False,
    }
    if new_errors:
        state_update["errors"] = new_errors

    return state_update
