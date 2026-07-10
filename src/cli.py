#!/usr/bin/env python3
# cli.py
# CLI entrypoint for ci-triage-agent.

from __future__ import annotations

import argparse
import logging
import sys

from src.agents.supervisor import run_triage
from src.config import llm_config_summary
from src.github.client import post_or_update_pr_comment

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("cli")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Triage SAST/SCA scanner output into a human-readable PR comment",
    )
    parser.add_argument("--trivy-file", help="Path to Trivy JSON report")
    parser.add_argument("--semgrep-file", help="Path to Semgrep JSON report")
    parser.add_argument(
        "--pr-number",
        type=int,
        default=None,
        help="GitHub PR number to post/update comment (optional for local runs)",
    )
    args = parser.parse_args(argv)

    if not args.trivy_file and not args.semgrep_file:
        parser.error("At least one of --trivy-file or --semgrep-file is required")

    logger.info("LLM config: %s", llm_config_summary())

    result = run_triage(
        trivy_file=args.trivy_file,
        semgrep_file=args.semgrep_file,
        pr_number=args.pr_number,
    )

    markdown = result.get("markdown_comment", "")
    if not markdown:
        logger.error("Triage produced no markdown comment. errors=%s", result.get("errors"))
        return 1

    print(markdown)

    if args.pr_number:
        url = post_or_update_pr_comment(args.pr_number, markdown)
        logger.info("Posted comment: %s", url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
