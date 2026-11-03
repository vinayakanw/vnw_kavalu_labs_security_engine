#!/usr/bin/env python3
"""Check that every commit in a range carries a ``Signed-off-by:`` trailer.

This enforces the Developer Certificate of Origin (https://developercertificate.org/),
the same lightweight "sign your work" process the Linux kernel uses. It is a
statement that you wrote the change (or have the right to submit it) under the
project's licence. See CONTRIBUTING.md.

Usage:
    python scripts/check_dco.py <base-ref> <head-ref>

Merge commits and commits authored by bots (``*[bot]``) are exempt.
Exit status: 0 = all good, 1 = at least one commit is missing a sign-off,
2 = usage or git error.

Standard library only, on purpose: it runs in CI before dependencies install.
"""

from __future__ import annotations

import re
import subprocess
import sys

SIGNOFF = re.compile(r"^Signed-off-by: .+ <[^<>\s]+@[^<>\s]+>\s*$", re.MULTILINE)
RECORD_SEP = "\x1e"
FIELD_SEP = "\x00"

HELP = """
Every commit must be signed off. The easy way:

    git commit -s -m "your message"          # new commits
    git commit --amend -s --no-edit          # fix the latest commit
    git rebase --signoff <base-ref>          # fix every commit on your branch
    git push --force-with-lease              # then update the pull request

Why? See "Developer Certificate of Origin" in CONTRIBUTING.md.
"""


def commits_in_range(base: str, head: str) -> list[tuple[str, str, str, str]]:
    """Return (sha, author name, author email, full message) for each non-merge commit."""
    # "%x00" / "%x1e" are git's own escapes for NUL and the record separator;
    # a literal NUL cannot be passed as a command-line argument.
    fmt = "%H%x00%an%x00%ae%x00%B%x1e"
    result = subprocess.run(
        ["git", "log", "--no-merges", f"--format={fmt}", f"{base}..{head}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git log failed")
    commits = []
    for record in result.stdout.split(RECORD_SEP):
        record = record.strip("\n")
        if not record:
            continue
        sha, name, email, message = record.split(FIELD_SEP, 3)
        commits.append((sha, name, email, message))
    return commits


def missing_signoff(commits: list[tuple[str, str, str, str]]) -> list[tuple[str, str]]:
    """Return (short sha, subject) for commits that need a sign-off but lack one."""
    bad = []
    for sha, name, _email, message in commits:
        if name.endswith("[bot]"):
            continue
        if not SIGNOFF.search(message):
            subject = message.strip().splitlines()[0] if message.strip() else "(empty message)"
            bad.append((sha[:7], subject))
    return bad


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.split("Usage:")[1].split("Merge commits")[0].strip(), file=sys.stderr)
        return 2
    try:
        commits = commits_in_range(argv[1], argv[2])
    except RuntimeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    bad = missing_signoff(commits)
    if not bad:
        print(f"DCO OK: {len(commits)} commit(s) checked, all signed off.")
        return 0

    print(f"DCO check failed: {len(bad)} of {len(commits)} commit(s) are missing 'Signed-off-by:'\n")
    for short_sha, subject in bad:
        print(f"  {short_sha}  {subject}")
    print(HELP)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
