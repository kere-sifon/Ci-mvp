# comment.py
# PR comment helpers for ci-triage-agent.

from __future__ import annotations

COMMENT_HEADER = "<!-- ci-triage-agent -->"


def find_existing_comment(comments: list[dict]) -> int | None:
    """Return the database ID of an existing triage comment, if any."""
    for comment in comments:
        body = comment.get("body") or ""
        if COMMENT_HEADER in body:
            return comment.get("id")
    return None
