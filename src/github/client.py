# client.py
# GitHub API client for posting/updating PR triage comments.

from __future__ import annotations

import logging

from github import Github

from src.config import GITHUB_REPOSITORY, GITHUB_TOKEN
from src.github.comment import COMMENT_HEADER, find_existing_comment

logger = logging.getLogger("github_client")


def _parse_repo() -> tuple[str, str]:
    if not GITHUB_REPOSITORY or "/" not in GITHUB_REPOSITORY:
        msg = "GITHUB_REPOSITORY must be set to owner/repo"
        raise ValueError(msg)
    owner, repo = GITHUB_REPOSITORY.split("/", 1)
    return owner, repo


def post_or_update_pr_comment(pr_number: int, markdown: str) -> str:
    """
    Post a new PR comment or update an existing ci-triage-agent comment.

    Returns the comment URL.
    """
    if not GITHUB_TOKEN:
        msg = "GITHUB_TOKEN is required to post PR comments"
        raise ValueError(msg)

    gh = Github(GITHUB_TOKEN)
    owner, repo_name = _parse_repo()
    repo = gh.get_repo(f"{owner}/{repo_name}")
    pr = repo.get_pull(pr_number)

    existing_id = None
    for comment in pr.get_issue_comments():
        if COMMENT_HEADER in (comment.body or ""):
            existing_id = comment.id
            break

    body = markdown if COMMENT_HEADER in markdown else f"{COMMENT_HEADER}\n{markdown}"

    if existing_id:
        comment = pr.get_issue_comment(existing_id)
        comment.edit(body)
        logger.info("Updated PR #%d comment id=%s", pr_number, existing_id)
        return comment.html_url

    comment = pr.create_issue_comment(body)
    logger.info("Created PR #%d comment id=%s", pr_number, comment.id)
    return comment.html_url
