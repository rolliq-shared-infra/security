#!/usr/bin/env python3
"""
Suppression expiry audit for adversarial-review-suppressions.yml.

Shipped inside the `suppression-audit` composite action. Called by each
Rolliq repo's weekly-scan workflow (via the reusable weekly-security-scan
workflow) to audit the repo-local file, and by platform-iac's
`audit-canonical-suppressions.yml` workflow to audit the canonical platform
file. Replaces the byte-identical copies previously duplicated in
solution-template and solution-recruitment-reference-check.

Reads the suppressions file and classifies each entry:
  EXPIRED  — expires date has passed; suppression is already inactive in PR reviews
  EXPIRING — expires within WARN_DAYS; should be renewed or removed before it lapses
  PERMANENT — no expires field; no action needed

Creates or updates a GitHub Issue titled ISSUE_TITLE summarising expired/expiring
entries. Closes the issue automatically when there is nothing to act on.

Exit code 0 always — this is an informational audit. Expired suppressions already
surface naturally in PR reviews (adversarial-review.py drops them at load time).

Required env vars:
  GITHUB_TOKEN        GitHub token with issues:write
  REPO                owner/repo slug

Optional env vars:
  SUPPRESSIONS_PATH   Path to the suppressions YAML file to audit. Defaults
                      to .github/adversarial-review-suppressions.yml (the
                      repo-local file). Platform-iac's audit-canonical
                      workflow sets this explicitly to the canonical file
                      to make the target obvious in workflow logs.
"""

import os
import sys
import re
import yaml
import httpx
from datetime import date, timedelta
from pathlib import Path

# Path is env-configurable so platform-iac can target the canonical file
# explicitly. Default matches every other caller (audits the repo-local file
# at the standard location).
SUPPRESSIONS_PATH = Path(
    os.environ.get("SUPPRESSIONS_PATH", ".github/adversarial-review-suppressions.yml")
)
WARN_DAYS = 60
GITHUB_API = "https://api.github.com"
ISSUE_TITLE = "Security: suppression expiry audit"
ISSUE_LABEL = "security"

# Explicit timeout on every GitHub API call — without it a hung connection
# stalls the audit job until the workflow-level timeout-minutes kills it.
_GITHUB_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)


# ── Load and classify suppressions ────────────────────────────────────────────

def load_and_classify() -> tuple[list[dict], list[dict], list[dict]]:
    """Return (expired, expiring_soon, permanent) lists."""
    # Missing file is a no-op rather than a crash — a downstream repo with no
    # repo-local suppressions (the post-Phase-2 steady state for clients-config
    # and recruitment-reference-check) should not fail its weekly audit job.
    if not SUPPRESSIONS_PATH.is_file():
        print(
            f"No suppressions file at {SUPPRESSIONS_PATH} — nothing to audit.",
            file=sys.stderr,
        )
        return [], [], []
    with open(SUPPRESSIONS_PATH) as f:
        content = f.read()
    # Skip header comments to find the YAML root
    lines = content.split("\n")
    yaml_start = next(
        (i for i, l in enumerate(lines) if not l.startswith("#") and l.strip()),
        0,
    )
    data = yaml.safe_load("\n".join(lines[yaml_start:])) or {}
    suppressions = data.get("suppressions", [])

    today = date.today()
    expired, expiring, permanent = [], [], []

    for s in suppressions:
        raw = s.get("expires", "")
        if not raw:
            permanent.append(s)
            continue
        try:
            exp = date.fromisoformat(str(raw))
        except ValueError:
            print(
                f"Warning: suppression '{s.get('id', '?')}' has unparseable expires "
                f"value {raw!r} — treated as permanent",
                file=sys.stderr,
            )
            permanent.append(s)
            continue

        days_left = (exp - today).days
        entry = {**s, "_expires": exp, "_days_left": days_left}
        if days_left < 0:
            expired.append(entry)
        elif days_left <= WARN_DAYS:
            expiring.append(entry)
        else:
            permanent.append(s)

    return expired, expiring, permanent


# ── GitHub Issue helpers ────────────────────────────────────────────────────

def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# Hard page cap for issue lookup — 20 pages × 100 = 2000 issues.
_MAX_ISSUE_PAGES = 20


def _find_issue_by_title(token: str, repo: str, state: str) -> int | None:
    """Return the number of the issue titled ISSUE_TITLE in the given state.

    Paginates fully via the Link header — a label can accumulate far more than
    one page of issues, so a single per_page=100 request can miss the target.
    """
    with httpx.Client(timeout=_GITHUB_TIMEOUT) as client:
        url: str | None = f"{GITHUB_API}/repos/{repo}/issues"
        params: dict | None = {"state": state, "labels": ISSUE_LABEL, "per_page": 100}
        for _ in range(_MAX_ISSUE_PAGES):
            resp = client.get(url, headers=_headers(token), params=params)
            resp.raise_for_status()
            for issue in resp.json():
                if issue.get("title") == ISSUE_TITLE:
                    return issue["number"]
            next_link = resp.links.get("next", {}).get("url")
            if not next_link:
                return None
            url, params = next_link, None  # next_link already carries the query
    return None


def find_existing_issue(token: str, repo: str) -> int | None:
    """Return the issue number of an existing open audit issue, or None."""
    return _find_issue_by_title(token, repo, "open")


def find_closed_issue(token: str, repo: str) -> int | None:
    """Return the issue number of a previously closed audit issue, or None."""
    return _find_issue_by_title(token, repo, "closed")


def create_issue(token: str, repo: str, body: str) -> int:
    with httpx.Client(timeout=_GITHUB_TIMEOUT) as client:
        resp = client.post(
            f"{GITHUB_API}/repos/{repo}/issues",
            headers=_headers(token),
            json={"title": ISSUE_TITLE, "body": body, "labels": [ISSUE_LABEL]},
        )
        resp.raise_for_status()
        return resp.json()["number"]


def update_issue(token: str, repo: str, number: int, body: str) -> None:
    with httpx.Client(timeout=_GITHUB_TIMEOUT) as client:
        resp = client.patch(
            f"{GITHUB_API}/repos/{repo}/issues/{number}",
            headers=_headers(token),
            json={"body": body, "state": "open"},
        )
        resp.raise_for_status()


def close_issue(token: str, repo: str, number: int, body: str) -> None:
    with httpx.Client(timeout=_GITHUB_TIMEOUT) as client:
        resp = client.patch(
            f"{GITHUB_API}/repos/{repo}/issues/{number}",
            headers=_headers(token),
            json={"body": body, "state": "closed"},
        )
        resp.raise_for_status()


# ── Report formatting ──────────────────────────────────────────────────────

def _entry_row(s: dict) -> str:
    eid = s.get("id", "unknown")
    expires = s.get("_expires", "?")
    days_left = s.get("_days_left", 0)
    reason_full = s.get("reason", "").strip()
    # First sentence only
    m = re.search(r"^(.+?[.!?])(?:\s|$)", reason_full)
    reason = m.group(1) if m else reason_full[:120]
    if days_left < 0:
        age = f"{-days_left}d ago"
    else:
        age = f"in {days_left}d"
    return f"| `{eid}` | {expires} ({age}) | {reason} |"


def build_body(expired: list[dict], expiring: list[dict], run_url: str) -> str:
    today = date.today().isoformat()
    sections = [f"<!-- suppression-audit-bot -->\n## Suppression expiry audit — {today}\n"]

    if expired:
        sections.append(
            f"### ❌ Expired ({len(expired)})\n\n"
            "These suppressions have lapsed. The finding now surfaces in PR reviews.\n"
            "**Action**: remove the suppression entry if the issue is resolved, or update "
            "`expires` to extend the workaround with a new justification comment.\n\n"
            "| ID | Expired | Reason (first sentence) |\n"
            "|---|---|---|\n"
            + "\n".join(_entry_row(s) for s in expired)
        )

    if expiring:
        sections.append(
            f"### ⚠️ Expiring within {WARN_DAYS} days ({len(expiring)})\n\n"
            "| ID | Expires | Reason (first sentence) |\n"
            "|---|---|---|\n"
            + "\n".join(_entry_row(s) for s in expiring)
        )

    sections.append(f"\n---\n*[Run]({run_url}) · Updated {today}*")
    return "\n\n".join(sections)


def build_clean_body(run_url: str) -> str:
    today = date.today().isoformat()
    return (
        f"<!-- suppression-audit-bot -->\n"
        f"## Suppression expiry audit — {today}\n\n"
        f"✅ No expired or expiring suppressions.\n\n"
        f"---\n*[Run]({run_url}) · Updated {today}*"
    )


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    run_url = os.environ.get("RUN_URL", "")

    if not token or not repo:
        print("ERROR: GITHUB_TOKEN and REPO must be set", file=sys.stderr)
        sys.exit(1)

    expired, expiring, permanent = load_and_classify()
    total = len(expired) + len(expiring) + len(permanent)
    print(
        f"Suppressions: {total} total — "
        f"{len(expired)} expired, {len(expiring)} expiring within {WARN_DAYS}d, "
        f"{len(permanent)} permanent"
    )

    existing = find_existing_issue(token, repo)
    needs_action = expired or expiring

    if needs_action:
        body = build_body(expired, expiring, run_url)
        if existing:
            update_issue(token, repo, existing, body)
            print(f"Updated issue #{existing}")
        else:
            # Reopen a previously closed issue if found, otherwise create new
            closed = find_closed_issue(token, repo)
            if closed:
                update_issue(token, repo, closed, body)
                print(f"Reopened issue #{closed}")
            else:
                number = create_issue(token, repo, body)
                print(f"Created issue #{number}")
    else:
        body = build_clean_body(run_url)
        if existing:
            close_issue(token, repo, existing, body)
            print(f"Closed issue #{existing} — nothing to action")
        else:
            print("No action needed — no issue to create or update")


if __name__ == "__main__":
    main()
